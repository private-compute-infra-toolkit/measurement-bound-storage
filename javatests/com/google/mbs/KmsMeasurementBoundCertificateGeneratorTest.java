/*
 * Copyright 2026 Google LLC
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

import static com.google.mbs.testing.CertificateTestHelper.parseCertificate;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
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
import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertHandle;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.KmsGeneratedKey;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.StorageAlreadyLockedException;
import com.google.mbs.domain.StorageSnapshot;
import com.google.mbs.domain.ValidityPeriod;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class KmsMeasurementBoundCertificateGeneratorTest {

  @Mock private KmsClientInterface kmsClient;
  @Mock private KeyBackupStorage storage;
  @Mock private AttestationCollector attestationCollector;
  @Mock private Metrics mockMetrics;

  private KmsMeasurementBoundCertificateGenerator generator;
  private static final String KMS_KEY_ARN = "test-kms-key-arn";
  private static final byte[] TEST_USER_DATA = "test_userdata".getBytes(StandardCharsets.UTF_8);
  private static final ValidityPeriod VALIDITY_PERIOD_0 =
      new ValidityPeriod(
          Instant.parse("1930-01-01T00:00:00Z"), Instant.parse("1930-02-01T00:00:00Z"));
  private static final ValidityPeriod VALIDITY_PERIOD_1 =
      new ValidityPeriod(
          Instant.parse("1931-01-01T00:00:00Z"), Instant.parse("1931-02-01T00:00:00Z"));
  private static final ValidityPeriod VALIDITY_PERIOD_2 =
      new ValidityPeriod(
          Instant.parse("1932-01-01T00:00:00Z"), Instant.parse("1932-02-01T00:00:00Z"));
  private static final CertificatesConfig CONFIG =
      CertificatesConfig.builder()
          .setSelfSignedCertificates(Map.of(0, new SelfSignedCertificate(0, VALIDITY_PERIOD_0)))
          .setActiveSelfSignedCertificateIds(Set.of(0))
          .setAcceptableSelfSignedCertificateIds(Set.of(0))
          .build();
  private static final CertificatesConfig TWO_EPOCH_CONFIG =
      CertificatesConfig.builder()
          .setSelfSignedCertificates(
              Map.of(
                  0, new SelfSignedCertificate(0, VALIDITY_PERIOD_0),
                  1, new SelfSignedCertificate(1, VALIDITY_PERIOD_1)))
          .setActiveSelfSignedCertificateIds(Set.of(0, 1))
          .setAcceptableSelfSignedCertificateIds(Set.of(0, 1))
          .build();

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory certificateFactory =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            spec, new X500Name("CN=Test CA"), Optional.empty(), KeyUsage.keyCertSign);

    generator =
        new KmsMeasurementBoundCertificateGenerator(
            kmsClient,
            storage,
            KMS_KEY_ARN,
            TEST_USER_DATA,
            attestationCollector,
            certificateFactory,
            mockMetrics);

    generator.retryBackoff = Duration.ZERO;
  }

  private record FakeComplete(int epoch, KeyBackup read) implements BackupHandle.Complete {}

  private static BackupHandle completeHandle() {
    KeyBackup dummy =
        new KeyBackup(
            "cert".getBytes(StandardCharsets.UTF_8),
            "key".getBytes(StandardCharsets.UTF_8),
            "priv".getBytes(StandardCharsets.UTF_8),
            "att".getBytes(StandardCharsets.UTF_8));
    return new FakeComplete(0, dummy);
  }

  private record FakeSnapshot(
      Map<Integer, BackupHandle> bundleHandles,
      Map<CrossSignedCertificateId, CrossSignedCertHandle> crossSignedCertHandles)
      implements StorageSnapshot {

    FakeSnapshot(Map<Integer, BackupHandle> bundleHandles) {
      this(bundleHandles, Map.of());
    }

    @Override
    public BackupHandle getBundleHandle(int epoch) {
      return bundleHandles.getOrDefault(epoch, emptyHandle(epoch));
    }

    @Override
    public CrossSignedCertHandle getCrossSignedCertHandle(CrossSignedCertificateId id) {
      return crossSignedCertHandles.getOrDefault(id, mock(CrossSignedCertHandle.Empty.class));
    }
  }

  private static StorageSnapshot snapshotOf(BackupHandle epoch0Handle) {
    return new FakeSnapshot(Map.of(0, epoch0Handle));
  }

  private static BackupHandle.Empty emptyHandle(int epoch) {
    BackupHandle.Empty empty = mock(BackupHandle.Empty.class);
    when(empty.epoch()).thenReturn(epoch);
    return empty;
  }

  private BackupHandle.Empty stubEmptyStorage() throws Exception {
    BackupHandle.Empty empty = emptyHandle(0);
    when(storage.getSnapshot()).thenReturn(snapshotOf(empty));
    return empty;
  }

  @Test
  public void generateCertificates_emptyStorage_generatesAndWrites() throws Exception {
    BackupHandle.Empty empty = stubEmptyStorage();
    byte[] plaintextDataKey = generateAesKey();
    byte[] dataKeyCiphertext = "generated-data-key".getBytes(StandardCharsets.UTF_8);
    when(kmsClient.generateDataKey(KMS_KEY_ARN))
        .thenReturn(
            KmsGeneratedKey.builder()
                .setPlaintext(plaintextDataKey)
                .setCiphertext(dataKeyCiphertext)
                .build());
    byte[] attestationDoc = "Mocked attestation doc".getBytes(StandardCharsets.UTF_8);
    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenReturn(AttestationToken.fromBytes(attestationDoc));

    generator.generateCertificates(CONFIG);

    InOrder inOrder = inOrder(storage, empty);
    inOrder.verify(storage).getSnapshot();
    inOrder.verify(storage).acquireLock();
    inOrder.verify(storage).getSnapshot();
    ArgumentCaptor<KeyBackup> backupCaptor = ArgumentCaptor.forClass(KeyBackup.class);
    inOrder.verify(empty).write(backupCaptor.capture());
    inOrder.verify(storage).releaseLock();

    KeyBackup written = backupCaptor.getValue();
    assertNotNull(written);
    assertArrayEquals(dataKeyCiphertext, written.kmsEncryptedDataKey());
    assertArrayEquals(attestationDoc, written.attestationDocBytes());

    X509Certificate certificate = parseCertificate(written.certBytes());
    assertEquals("CN=Test CA", certificate.getSubjectX500Principal().getName());
    assertEquals(VALIDITY_PERIOD_0.notBefore(), certificate.getNotBefore().toInstant());
    assertEquals(VALIDITY_PERIOD_0.notAfter(), certificate.getNotAfter().toInstant());
    assertArrayEquals(
        KmsMeasurementBoundCertificateGenerator.toPemBytes(certificate), written.certBytes());

    ArgumentCaptor<PublicKey> pubkeyCaptor = ArgumentCaptor.forClass(PublicKey.class);
    verify(attestationCollector).collectBoundToPubkey(pubkeyCaptor.capture(), eq(TEST_USER_DATA));
    assertEquals(certificate.getPublicKey(), pubkeyCaptor.getValue());

    byte[] decryptedPrivateKeyBytes = decrypt(written.aeadEncryptedPrivateKey(), plaintextDataKey);
    KeyFactory keyFactory = KeyFactory.getInstance(certificate.getPublicKey().getAlgorithm());
    PrivateKey privateKey =
        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKeyBytes));
    assertTrue(isKeyMatchingCertificate(certificate, privateKey));
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_completeBackupExists_skipsWithoutLocking() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle()));

    generator.generateCertificates(CONFIG);

    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(kmsClient, never()).generateDataKey(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_incompleteBackupExists_skipsWithoutLocking() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(new BackupHandle.Incomplete(0, List.of("public/0/root_certificate.pem"))));

    generator.generateCertificates(CONFIG);

    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(kmsClient, never()).generateDataKey(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_partiallyWrittenBackupExists_skipsWithoutLocking()
      throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                new BackupHandle.PartiallyWritten(0, List.of("public/0/root_certificate.pem"))));

    generator.generateCertificates(CONFIG);

    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(kmsClient, never()).generateDataKey(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_backupAppearsUnderLock_releasesLockWithoutGenerating()
      throws Exception {
    BackupHandle.Empty empty = mock(BackupHandle.Empty.class);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(empty))
        .thenReturn(snapshotOf(completeHandle()));

    generator.generateCertificates(CONFIG);

    verify(storage, times(2)).getSnapshot();
    verify(storage).acquireLock();
    verify(storage).releaseLock();
    verify(empty, never()).write(any());
    verify(kmsClient, never()).generateDataKey(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_partiallyWrittenUnderLock_releasesLockWithoutGenerating()
      throws Exception {
    BackupHandle.Empty empty = mock(BackupHandle.Empty.class);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(empty))
        .thenReturn(
            snapshotOf(
                new BackupHandle.PartiallyWritten(0, List.of("public/0/root_certificate.pem"))));

    generator.generateCertificates(CONFIG);

    verify(storage, times(2)).getSnapshot();
    verify(storage).acquireLock();
    verify(storage).releaseLock();
    verify(empty, never()).write(any());
    verify(kmsClient, never()).generateDataKey(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_generationFails_doesNotReleaseLock() throws Exception {
    BackupHandle.Empty empty0 = emptyHandle(0);
    BackupHandle.Empty empty1 = emptyHandle(1);
    when(storage.getSnapshot()).thenReturn(new FakeSnapshot(Map.of(0, empty0, 1, empty1)));
    when(kmsClient.generateDataKey(KMS_KEY_ARN))
        .thenReturn(
            KmsGeneratedKey.builder()
                .setPlaintext(generateAesKey())
                .setCiphertext("generated-data-key-0".getBytes(StandardCharsets.UTF_8))
                .build())
        .thenThrow(new KmsException("KMS error on epoch 1"));
    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenReturn(AttestationToken.fromBytes("att".getBytes(StandardCharsets.UTF_8)));

    RuntimeException thrown =
        assertThrows(
            RuntimeException.class, () -> generator.generateCertificates(TWO_EPOCH_CONFIG));

    assertEquals(KmsException.class, thrown.getCause().getClass());
    verify(empty0).write(any());
    verify(empty1, never()).write(any());
    verify(storage).acquireLock();
    verify(storage, never()).releaseLock();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void generateCertificates_alreadyLocked_waitsAndSkipsWhenWinnerPublishes()
      throws Exception {
    BackupHandle.Empty empty = mock(BackupHandle.Empty.class);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(empty))
        .thenReturn(snapshotOf(completeHandle()));
    doThrow(new StorageAlreadyLockedException("Generation lock present"))
        .when(storage)
        .acquireLock();

    generator.generateCertificates(CONFIG);

    verify(storage, times(2)).getSnapshot();
    verify(storage, times(1)).acquireLock();
    verify(kmsClient, never()).generateDataKey(any());
    verify(empty, never()).write(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_lockHeldOnBothAttempts_reportsWaitingForMbsLock()
      throws Exception {
    stubEmptyStorage();
    doThrow(new StorageAlreadyLockedException("Generation lock present"))
        .when(storage)
        .acquireLock();

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> generator.generateCertificates(CONFIG));

    assertEquals(StorageAlreadyLockedException.class, thrown.getCause().getClass());
    verify(storage, times(2)).acquireLock();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.WAITING_FOR_MBS_LOCK);
  }

  @Test
  public void generateCertificates_storageThrowsException_propagatesWrappedError()
      throws Exception {
    doThrow(new KeyBackupAccessFailedException("Failed to list")).when(storage).getSnapshot();

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> generator.generateCertificates(CONFIG));

    assertEquals(KeyBackupAccessFailedException.class, thrown.getCause().getClass());
    verify(storage, times(1)).getSnapshot();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.S3_OPERATION_FAILED);
  }

  @Test
  public void generateCertificates_writeFails_reportsS3OperationFailed() throws Exception {
    BackupHandle.Empty empty = stubEmptyStorage();
    byte[] plaintextDataKey = generateAesKey();
    byte[] dataKeyCiphertext = "generated-data-key".getBytes(StandardCharsets.UTF_8);
    when(kmsClient.generateDataKey(KMS_KEY_ARN))
        .thenReturn(
            KmsGeneratedKey.builder()
                .setPlaintext(plaintextDataKey)
                .setCiphertext(dataKeyCiphertext)
                .build());
    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenReturn(AttestationToken.fromBytes("att".getBytes(StandardCharsets.UTF_8)));
    doThrow(new KeyBackupAccessFailedException("S3 write failed")).when(empty).write(any());

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> generator.generateCertificates(CONFIG));

    assertEquals(KeyBackupAccessFailedException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.S3_OPERATION_FAILED);
  }

  @Test
  public void generateCertificates_attestationFails_reportsCertificateGenerationFailed()
      throws Exception {
    stubEmptyStorage();
    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenThrow(new IllegalStateException("Attestation failed"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> generator.generateCertificates(CONFIG));

    assertEquals(IllegalStateException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.GENERAL_FAILURE);
  }

  @Test
  public void generateCertificates_multipleEpochsInConfig_generatesMissingUnderSingleLock()
      throws Exception {
    // Leave epoch 1 inactive to verify that all configured self-signed certificates (including
    // pre-rotation inactive epochs) are generated.
    CertificatesConfig multiEpochConfig =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(
                Map.of(
                    0, new SelfSignedCertificate(0, VALIDITY_PERIOD_0),
                    1, new SelfSignedCertificate(1, VALIDITY_PERIOD_1),
                    2, new SelfSignedCertificate(2, VALIDITY_PERIOD_2)))
            .setActiveSelfSignedCertificateIds(Set.of(0, 2))
            .setAcceptableSelfSignedCertificateIds(Set.of(0, 1, 2))
            .build();

    BackupHandle.Empty empty1 = emptyHandle(1);
    BackupHandle.Empty empty2 = emptyHandle(2);
    StorageSnapshot snapshot =
        new FakeSnapshot(
            Map.of(
                0, completeHandle(),
                1, empty1,
                2, empty2));
    when(storage.getSnapshot()).thenReturn(snapshot);

    byte[] plaintextDataKey1 = generateAesKey();
    byte[] dataKeyCiphertext1 = "generated-data-key-1".getBytes(StandardCharsets.UTF_8);
    byte[] plaintextDataKey2 = generateAesKey();
    byte[] dataKeyCiphertext2 = "generated-data-key-2".getBytes(StandardCharsets.UTF_8);
    when(kmsClient.generateDataKey(KMS_KEY_ARN))
        .thenReturn(
            KmsGeneratedKey.builder()
                .setPlaintext(plaintextDataKey1)
                .setCiphertext(dataKeyCiphertext1)
                .build())
        .thenReturn(
            KmsGeneratedKey.builder()
                .setPlaintext(plaintextDataKey2)
                .setCiphertext(dataKeyCiphertext2)
                .build());
    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenReturn(AttestationToken.fromBytes("att".getBytes(StandardCharsets.UTF_8)));

    generator.generateCertificates(multiEpochConfig);

    ArgumentCaptor<KeyBackup> backup1Captor = ArgumentCaptor.forClass(KeyBackup.class);
    ArgumentCaptor<KeyBackup> backup2Captor = ArgumentCaptor.forClass(KeyBackup.class);
    InOrder inOrder = inOrder(storage);
    inOrder.verify(storage).getSnapshot();
    inOrder.verify(storage).acquireLock();
    inOrder.verify(storage).getSnapshot();
    inOrder.verify(storage).releaseLock();

    verify(empty1).write(backup1Captor.capture());
    verify(empty2).write(backup2Captor.capture());
    verify(kmsClient, times(2)).generateDataKey(KMS_KEY_ARN);
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);

    X509Certificate cert1 = parseCertificate(backup1Captor.getValue().certBytes());
    assertEquals(VALIDITY_PERIOD_1.notBefore(), cert1.getNotBefore().toInstant());
    assertEquals(VALIDITY_PERIOD_1.notAfter(), cert1.getNotAfter().toInstant());

    X509Certificate cert2 = parseCertificate(backup2Captor.getValue().certBytes());
    assertEquals(VALIDITY_PERIOD_2.notBefore(), cert2.getNotBefore().toInstant());
    assertEquals(VALIDITY_PERIOD_2.notAfter(), cert2.getNotAfter().toInstant());
  }

  @Test
  public void
      generateCertificates_oneOfMultipleEpochsAppearsUnderLock_generatesOnlyRemainingMissingEpoch()
          throws Exception {
    BackupHandle.Empty empty0 = emptyHandle(0);
    BackupHandle.Empty empty1 = emptyHandle(1);
    when(storage.getSnapshot())
        .thenReturn(new FakeSnapshot(Map.of(0, empty0, 1, empty1)))
        .thenReturn(new FakeSnapshot(Map.of(0, completeHandle(), 1, empty1)));

    when(kmsClient.generateDataKey(KMS_KEY_ARN))
        .thenReturn(
            KmsGeneratedKey.builder()
                .setPlaintext(generateAesKey())
                .setCiphertext("generated-data-key-1".getBytes(StandardCharsets.UTF_8))
                .build());
    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenReturn(AttestationToken.fromBytes("att".getBytes(StandardCharsets.UTF_8)));

    generator.generateCertificates(TWO_EPOCH_CONFIG);

    verify(storage, times(2)).getSnapshot();
    verify(storage).acquireLock();
    verify(empty0, never()).write(any());
    ArgumentCaptor<KeyBackup> backup1Captor = ArgumentCaptor.forClass(KeyBackup.class);
    verify(empty1).write(backup1Captor.capture());
    verify(storage).releaseLock();
    verify(kmsClient, times(1)).generateDataKey(KMS_KEY_ARN);
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);

    X509Certificate cert1 = parseCertificate(backup1Captor.getValue().certBytes());
    assertEquals(VALIDITY_PERIOD_1.notBefore(), cert1.getNotBefore().toInstant());
    assertEquals(VALIDITY_PERIOD_1.notAfter(), cert1.getNotAfter().toInstant());
  }

  private boolean isKeyMatchingCertificate(X509Certificate certificate, PrivateKey privateKey)
      throws GeneralSecurityException {
    byte[] probe = "mbs-key-certificate-consistency-check".getBytes(StandardCharsets.UTF_8);
    Signature signer = Signature.getInstance(certificate.getSigAlgName());
    signer.initSign(privateKey);
    signer.update(probe);
    byte[] signature = signer.sign();

    Signature verifier = Signature.getInstance(certificate.getSigAlgName());
    verifier.initVerify(certificate.getPublicKey());
    verifier.update(probe);
    return verifier.verify(signature);
  }

  private byte[] generateAesKey() throws GeneralSecurityException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    SecretKey secretKey = keyGen.generateKey();
    return secretKey.getEncoded();
  }

  private byte[] decrypt(byte[] ciphertext, byte[] key) throws GeneralSecurityException {
    return getAead(key).decrypt(ciphertext, new byte[0]);
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
