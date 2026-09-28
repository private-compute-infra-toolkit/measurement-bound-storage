/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.mbs;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.util.SecretBytes;
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.AttestationToken;
import com.google.mbs.domain.BundleCorruptedException;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupIncompleteException;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupPartiallyWrittenException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.KmsGeneratedKey;
import com.google.mbs.domain.MeasurementBoundCertificate;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.StorageAlreadyLockedException;
import com.google.mbs.domain.TrustPackage;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class KmsMeasurementBoundCertificateProviderTest {

  @Mock private KmsClientInterface kmsClient;
  @Mock private KeyBackupStorage storage;
  @Mock private AttestationCollector attestationCollector;
  @Mock private Metrics mockMetrics;

  private KmsMeasurementBoundCertificateProvider certificateProvider;
  private static final String KMS_KEY_ARN = "test-kms-key-arn";
  private static final byte[] TEST_USER_DATA = "test_userdata".getBytes(StandardCharsets.UTF_8);

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory certificateFactory =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            spec,
            new X500Name("CN=Test CA"),
            Duration.ofDays(30),
            Optional.empty(),
            KeyUsage.keyCertSign);

    certificateProvider =
        new KmsMeasurementBoundCertificateProvider(
            kmsClient,
            storage,
            KMS_KEY_ARN,
            TEST_USER_DATA,
            attestationCollector,
            certificateFactory,
            mockMetrics);

    certificateProvider.retryBackoff = Duration.ZERO;
  }

  private MeasurementBoundCertificate activeCertificate() {
    TrustPackage trustPackage = certificateProvider.getActiveTrustPackage();
    assertEquals(1, trustPackage.bundles().size());
    assertTrue(trustPackage.crossSignedCertificates().isEmpty());
    return trustPackage.bundles().get(0);
  }

  private void stubEmptyStorage() throws Exception {
    when(storage.getKeyBackup()).thenThrow(new KeyBackupNotFoundException("Key backup absent"));
  }

  /** Storage that is pristine until something is written, then serves exactly that. */
  private void stubStorageServingWhatIsPut() throws Exception {
    AtomicReference<KeyBackup> stored = new AtomicReference<>();
    doAnswer(
            invocation -> {
              stored.set(invocation.getArgument(0));
              return null;
            })
        .when(storage)
        .putKeyBackup(any());
    when(storage.getKeyBackup())
        .thenAnswer(
            invocation -> {
              KeyBackup backup = stored.get();
              if (backup == null) {
                throw new KeyBackupNotFoundException("Key backup absent");
              }
              return backup;
            });
  }

  /** A backup whose private key matches encodedCert, with KMS stubbed to yield its data key. */
  private KeyBackup consistentBackup(PrivateKey privateKey, byte[] encodedCert, String label)
      throws Exception {
    byte[] plaintextDataKey = generateAesKey();
    byte[] kmsEncryptedDataKey = ("kms-encrypted-" + label).getBytes(StandardCharsets.UTF_8);
    when(kmsClient.decrypt(kmsEncryptedDataKey, KMS_KEY_ARN)).thenReturn(plaintextDataKey);
    return new KeyBackup(
        encodedCert,
        kmsEncryptedDataKey,
        encrypt(privateKey.getEncoded(), plaintextDataKey),
        ("attestation-" + label).getBytes(StandardCharsets.UTF_8));
  }

  /** Stubs data key generation so the generated backup is also decryptable when read back. */
  private byte[] stubDataKeyGeneration() throws Exception {
    byte[] plaintext = generateAesKey();
    byte[] ciphertext = "generated-data-key".getBytes(StandardCharsets.UTF_8);
    when(kmsClient.generateDataKey(KMS_KEY_ARN))
        .thenReturn(
            KmsGeneratedKey.builder().setPlaintext(plaintext).setCiphertext(ciphertext).build());
    when(kmsClient.decrypt(ciphertext, KMS_KEY_ARN)).thenReturn(plaintext);
    return ciphertext;
  }

  private byte[] stubAttestation(String text) throws Exception {
    byte[] doc = text.getBytes(StandardCharsets.UTF_8);
    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenReturn(AttestationToken.fromBytes(doc));
    return doc;
  }

  private MbsCertificateFactory.X509CertificateAndPrivateKey generateCertAndKey(String subject)
      throws Exception {
    return MbsCertificateFactory.createSelfSignedCertificatesFactory(
            new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA"),
            new X500Name(subject),
            Duration.ofDays(30),
            Optional.empty(),
            KeyUsage.keyCertSign)
        .generate();
  }

  @FunctionalInterface
  private interface CertificateEncoder {
    byte[] encode(X509Certificate certificate) throws Exception;
  }

  private void runReloadCertificate_loadsFromStorageTest(CertificateEncoder encoder)
      throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    X509Certificate certificate = certAndKey.certificate();
    PrivateKey privateKey = certAndKey.privateKey();

    KeyBackup backup =
        consistentBackup(privateKey, encoder.encode(certificate), "loaded-from-storage");
    when(storage.getKeyBackup()).thenReturn(backup);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = activeCertificate();

    assertNotNull(result);
    assertSame(result, activeCertificate());
    assertEquals(
        certificate.getSubjectX500Principal(), result.getCertificate().getSubjectX500Principal());
    assertArrayEquals(
        certificate.getPublicKey().getEncoded(),
        result.getCertificate().getPublicKey().getEncoded());
    assertArrayEquals(privateKey.getEncoded(), result.getPrivateKey().getEncoded());
    assertEquals(
        Base64.getEncoder().encodeToString(backup.attestationDocBytes()),
        result.getAttestationToken().getBase64());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void reloadCertificate_loadsFromStorageDer() throws Exception {
    runReloadCertificate_loadsFromStorageTest(X509Certificate::getEncoded);
  }

  @Test
  public void reloadCertificate_loadsFromStoragePem() throws Exception {
    runReloadCertificate_loadsFromStorageTest(KmsMeasurementBoundCertificateProvider::toPemBytes);
  }

  @Test
  public void reloadCertificate_generatesAndStores() throws Exception {
    stubStorageServingWhatIsPut();
    byte[] dataKeyCiphertext = stubDataKeyGeneration();
    byte[] attestationDoc = stubAttestation("Mocked attestation doc");

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = activeCertificate();

    assertNotNull(result);
    assertSame(result, activeCertificate());
    assertNotNull(result.getCertificate());
    assertNotNull(result.getPrivateKey());
    assertEquals("CN=Test CA", result.getCertificate().getSubjectX500Principal().getName());
    assertEquals(
        Base64.getEncoder().encodeToString(attestationDoc),
        result.getAttestationToken().getBase64());

    ArgumentCaptor<PublicKey> pubkeyBoundToAttestationDocCaptor =
        ArgumentCaptor.forClass(PublicKey.class);
    verify(attestationCollector)
        .collectBoundToPubkey(pubkeyBoundToAttestationDocCaptor.capture(), eq(TEST_USER_DATA));
    assertEquals(
        result.getCertificate().getPublicKey(), pubkeyBoundToAttestationDocCaptor.getValue());

    // Generating is only ever permitted under the lock, and the lock is given back afterwards.
    verify(storage).acquireLock();
    ArgumentCaptor<KeyBackup> backupCaptor = ArgumentCaptor.forClass(KeyBackup.class);
    verify(storage).putKeyBackup(backupCaptor.capture());
    verify(storage).releaseLock();
    KeyBackup written = backupCaptor.getValue();
    assertArrayEquals(
        KmsMeasurementBoundCertificateProvider.toPemBytes(result.getCertificate()),
        written.certBytes());
    assertArrayEquals(dataKeyCiphertext, written.kmsEncryptedDataKey());
    assertArrayEquals(attestationDoc, written.attestationDocBytes());
    assertNotNull(written.aeadEncryptedPrivateKey());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void reloadCertificate_storageThrowsException_propagatesWrappedError() throws Exception {
    when(storage.getKeyBackup())
        .thenThrow(new KeyBackupAccessFailedException("Failed to fetch object"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.reloadCertificate();
        });

    // A read failure is not a transient backup state, so it must not be retried.
    verify(storage, times(1)).getKeyBackup();
  }

  @Test
  public void reloadCertificate_kmsDecryptFails_reportsKmsOperationFailed() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    byte[] kmsEncryptedDataKey = "kms-encrypted-data-key".getBytes(StandardCharsets.UTF_8);

    // A complete backup, so the reload reaches the KMS decrypt during loading.
    when(storage.getKeyBackup())
        .thenReturn(
            new KeyBackup(
                certAndKey.certificate().getEncoded(),
                kmsEncryptedDataKey,
                "unreadable-without-the-data-key".getBytes(StandardCharsets.UTF_8),
                "attestation-doc".getBytes(StandardCharsets.UTF_8)));
    when(kmsClient.decrypt(kmsEncryptedDataKey, KMS_KEY_ARN))
        .thenThrow(new KmsException("KMS error"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.reloadCertificate();
        });

    verify(mockMetrics).recordEvent(Metrics.MbsEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void reloadCertificate_generationFails_doesNotReleaseLock() throws Exception {
    stubEmptyStorage();
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenThrow(new KmsException("KMS error"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.reloadCertificate();
        });

    // Failing while holding the lock leaves it behind on purpose, for an operator to resolve.
    verify(storage).acquireLock();
    verify(storage, never()).releaseLock();
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void reloadCertificate_partiallyWrittenUnderLock_abortsAndDoesNotReleaseLock()
      throws Exception {
    // Pristine before the lock, half-written after it: the state is unknown, so we must not write
    // over it. The retry then sees the same half-written backup and gives up holding the lock.
    when(storage.getKeyBackup())
        .thenThrow(new KeyBackupNotFoundException("Key backup absent"))
        .thenThrow(new KeyBackupPartiallyWrittenException("Key backup partially written"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, certificateProvider::reloadCertificate);

    assertEquals(KeyBackupPartiallyWrittenException.class, thrown.getCause().getClass());
    verify(storage, times(1)).acquireLock();
    verify(storage, never()).releaseLock();
    verify(storage, never()).putKeyBackup(any());
    verify(kmsClient, never()).generateDataKey(any());
  }

  @Test
  public void reloadCertificate_backupAppearsUnderLock_releasesLockWithoutGenerating()
      throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup backup =
        consistentBackup(
            certAndKey.privateKey(),
            KmsMeasurementBoundCertificateProvider.toPemBytes(certAndKey.certificate()),
            "won-the-race");

    // Storage looks pristine before the lock, but another instance published while we took it.
    when(storage.getKeyBackup())
        .thenThrow(new KeyBackupNotFoundException("Key backup absent"))
        .thenReturn(backup);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = activeCertificate();

    assertNotNull(result);
    assertSame(result, activeCertificate());
    verify(storage).acquireLock();
    verify(storage).releaseLock();
    verify(storage, never()).putKeyBackup(any());
    verify(kmsClient, never()).generateDataKey(any());
  }

  @Test
  public void reloadCertificate_alreadyLocked_waitsAndLoadsWinnerCert() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup backup =
        consistentBackup(
            certAndKey.privateKey(),
            KmsMeasurementBoundCertificateProvider.toPemBytes(certAndKey.certificate()),
            "winner");

    // Pristine on the first attempt, then the lock holder publishes before the retry reads.
    when(storage.getKeyBackup())
        .thenThrow(new KeyBackupNotFoundException("Key backup absent"))
        .thenReturn(backup);
    doThrow(new StorageAlreadyLockedException("Generation lock present"))
        .when(storage)
        .acquireLock();

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = activeCertificate();

    assertNotNull(result);
    assertSame(result, activeCertificate());
    assertEquals("CN=Test CA", result.getCertificate().getSubjectX500Principal().getName());
    // This instance lost the race, so it must never generate.
    verify(kmsClient, never()).generateDataKey(any());
    verify(storage, never()).putKeyBackup(any());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void reloadCertificate_lockHeldOnBothAttempts_reportsWaitingForMbsLock() throws Exception {
    stubEmptyStorage();
    doThrow(new StorageAlreadyLockedException("Generation lock present"))
        .when(storage)
        .acquireLock();

    RuntimeException thrown =
        assertThrows(RuntimeException.class, certificateProvider::reloadCertificate);

    assertEquals(StorageAlreadyLockedException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.WAITING_FOR_MBS_LOCK);
    // One lock attempt per reload attempt: the original and the single retry, and no more.
    verify(storage, times(2)).acquireLock();
    verify(storage, never()).putKeyBackup(any());
    verify(mockMetrics, never()).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void reloadCertificate_updatesCertificateWhenStorageChanges() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey1 =
        generateCertAndKey("CN=Test CA 1");
    KeyBackup first =
        consistentBackup(certAndKey1.privateKey(), certAndKey1.certificate().getEncoded(), "first");
    when(storage.getKeyBackup()).thenReturn(first);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate initial = activeCertificate();
    assertNotNull(initial);
    assertEquals("CN=Test CA 1", initial.getCertificate().getSubjectX500Principal().getName());

    // Storage is updated with a rotated certificate
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey2 =
        generateCertAndKey("CN=Test CA 2");
    KeyBackup second =
        consistentBackup(
            certAndKey2.privateKey(), certAndKey2.certificate().getEncoded(), "second");
    when(storage.getKeyBackup()).thenReturn(second);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate reloaded = activeCertificate();
    assertNotNull(reloaded);
    assertEquals("CN=Test CA 2", reloaded.getCertificate().getSubjectX500Principal().getName());
    assertEquals(
        "CN=Test CA 2", activeCertificate().getCertificate().getSubjectX500Principal().getName());
  }

  @Test
  public void reloadCertificate_failureThrowsAndRetainsActiveCertificate() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup active =
        consistentBackup(certAndKey.privateKey(), certAndKey.certificate().getEncoded(), "active");
    when(storage.getKeyBackup()).thenReturn(active);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate initial = activeCertificate();
    assertNotNull(initial);

    // Simulate transient storage error during reload
    when(storage.getKeyBackup())
        .thenThrow(
            new KeyBackupAccessFailedException("Failed to fetch object", new RuntimeException()));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reloadCertificate());

    // Storage failures are checked exceptions now, so callers receive them wrapped.
    assertEquals(KeyBackupAccessFailedException.class, thrown.getCause().getClass());
    // The previously loaded certificate is still the one served
    assertSame(initial, activeCertificate());
  }

  @Test
  public void getActiveTrustPackage_uninitialized_throwsIllegalStateException() {
    IllegalStateException ex =
        assertThrows(
            IllegalStateException.class, () -> certificateProvider.getActiveTrustPackage());
    assertEquals("Measurement-bound certificate has not been initialized yet", ex.getMessage());
  }

  @Test
  public void reloadCertificate_backupLostArtifacts_reportsCorruptedAndDoesNotGenerate()
      throws Exception {
    // Which artifacts are missing is the storage's business now; the provider only has to refuse
    // to generate over a backup that was once complete.
    when(storage.getKeyBackup())
        .thenThrow(new KeyBackupIncompleteException("Key backup incomplete, missing [cert]"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, certificateProvider::reloadCertificate);

    assertEquals(KeyBackupIncompleteException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.STORED_BACKUP_CORRUPTED);
    // An incomplete backup is damage, not a publication in flight, so it must not be retried.
    verify(storage, times(1)).getKeyBackup();
    verify(storage, never()).acquireLock();
    verify(storage, never()).putKeyBackup(any());
    verify(kmsClient, never()).generateDataKey(any());
  }

  @Test
  public void reloadCertificate_backupPartiallyWritten_retriesAndLoadsOnceComplete()
      throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup backup =
        consistentBackup(certAndKey.privateKey(), certAndKey.certificate().getEncoded(), "settled");

    // A reader can catch a publication in flight; that is transient, not damage.
    when(storage.getKeyBackup())
        .thenThrow(new KeyBackupPartiallyWrittenException("Key backup partially written"))
        .thenReturn(backup);

    certificateProvider.reloadCertificate();

    assertNotNull(activeCertificate());
    verify(mockMetrics, never()).recordEvent(Metrics.MbsEvent.STORED_BACKUP_CORRUPTED);
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
    verify(storage, never()).acquireLock();
  }

  @Test
  public void reloadCertificate_backupStaysPartiallyWritten_reportsCorruptedAfterRetry()
      throws Exception {
    when(storage.getKeyBackup())
        .thenThrow(new KeyBackupPartiallyWrittenException("Key backup partially written"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, certificateProvider::reloadCertificate);

    assertEquals(KeyBackupPartiallyWrittenException.class, thrown.getCause().getClass());
    // One read per attempt: the original and the single retry, then terminal.
    verify(storage, times(2)).getKeyBackup();
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.STORED_BACKUP_CORRUPTED);
    verify(storage, never()).acquireLock();
    verify(kmsClient, never()).generateDataKey(any());
  }

  @Test
  public void reloadCertificate_concurrentCalls_neverOverlap() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup backup =
        consistentBackup(
            certAndKey.privateKey(), certAndKey.certificate().getEncoded(), "concurrent");

    AtomicInteger inFlight = new AtomicInteger();
    AtomicInteger peakInFlight = new AtomicInteger();
    when(storage.getKeyBackup())
        .thenAnswer(
            invocation -> {
              peakInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
              // Hold the critical section open long enough that unsynchronised callers overlap.
              Thread.sleep(20);
              inFlight.decrementAndGet();
              return backup;
            });

    int threadCount = 4;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    CyclicBarrier startTogether = new CyclicBarrier(threadCount);
    List<Future<?>> futures = new ArrayList<>();
    try {
      for (int i = 0; i < threadCount; i++) {
        futures.add(
            executor.submit(
                () -> {
                  startTogether.await();
                  certificateProvider.reloadCertificate();
                  return null;
                }));
      }
      for (Future<?> future : futures) {
        future.get(30, TimeUnit.SECONDS);
      }
    } finally {
      executor.shutdownNow();
    }

    assertEquals(1, peakInFlight.get());
    assertNotNull(activeCertificate());
  }

  @Test
  public void reloadCertificate_mismatchedPrivateKey_rejectsAndReportsCorrupted() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKeyA =
        generateCertAndKey("CN=Test CA");
    KeyPair keyPairB = generateKeyPair();

    KeyBackup backup =
        consistentBackup(
            keyPairB.getPrivate(), certAndKeyA.certificate().getEncoded(), "mismatched");
    when(storage.getKeyBackup()).thenReturn(backup);

    RuntimeException thrown =
        assertThrows(RuntimeException.class, certificateProvider::reloadCertificate);

    assertEquals(BundleCorruptedException.class, thrown.getCause().getClass());
    // Contents are interpreted during loading, which never takes the lock.
    verify(storage, never()).acquireLock();
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.STORED_BACKUP_CORRUPTED);
    verify(mockMetrics, never()).recordEvent(Metrics.MbsEvent.SUCCESS);
    verify(storage, never()).putKeyBackup(any());
    verify(kmsClient, never()).generateDataKey(any());
    assertThrows(IllegalStateException.class, certificateProvider::getActiveTrustPackage);
  }

  private KeyPair generateKeyPair() throws GeneralSecurityException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  private byte[] generateAesKey() throws GeneralSecurityException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    SecretKey secretKey = keyGen.generateKey();
    return secretKey.getEncoded();
  }

  private byte[] encrypt(byte[] plaintext, byte[] key) throws GeneralSecurityException {
    return getAead(key).encrypt(plaintext, new byte[0]);
  }

  @AccessesPartialKey
  private Aead getAead(byte[] key) throws GeneralSecurityException {
    AesGcmKey aesGcmKey =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES256_GCM)
            .setKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
            .setIdRequirement(1)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmKey).withFixedId(1).makePrimary())
            .build();
    return keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
  }
}
