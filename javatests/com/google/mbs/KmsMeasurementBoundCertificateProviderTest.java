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
import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.BundleCorruptedException;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertHandle;
import com.google.mbs.domain.CrossSignedCertificate;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupIncompleteException;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupPartiallyWrittenException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.MeasurementBoundBundle;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.StorageSnapshot;
import com.google.mbs.domain.TrustPackage;
import com.google.mbs.domain.ValidityPeriod;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class KmsMeasurementBoundCertificateProviderTest {

  @Mock private KmsClientInterface kmsClient;
  @Mock private KeyBackupStorage storage;
  @Mock private Metrics mockMetrics;

  private KmsMeasurementBoundCertificateProvider certificateProvider;
  private static final String KMS_KEY_ARN = "test-kms-key-arn";
  private static final ValidityPeriod DEFAULT_VALIDITY =
      new ValidityPeriod(
          Instant.parse("1930-01-01T00:00:00Z"), Instant.parse("1930-02-01T00:00:00Z"));
  private static final CertificatesConfig CONFIG =
      CertificatesConfig.builder()
          .setSelfSignedCertificates(selfSignedCerts(0))
          .setActiveSelfSignedCertificateIds(Set.of(0))
          .build();

  private static Map<Integer, SelfSignedCertificate> selfSignedCerts(int... epochs) {
    return Arrays.stream(epochs)
        .boxed()
        .collect(Collectors.toMap(e -> e, e -> new SelfSignedCertificate(e, DEFAULT_VALIDITY)));
  }

  private static Map<CrossSignedCertificateId, CrossSignedCertificate> crossSignedCerts(
      CrossSignedCertificateId... ids) {
    return Arrays.stream(ids)
        .collect(
            Collectors.toMap(
                id -> id,
                id ->
                    new CrossSignedCertificate(
                        id.privateKeyEpochId(), id.publicKeyEpochId(), DEFAULT_VALIDITY)));
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);

    certificateProvider =
        new KmsMeasurementBoundCertificateProvider(kmsClient, storage, KMS_KEY_ARN, mockMetrics);

    certificateProvider.retryBackoff = Duration.ZERO;
  }

  private MeasurementBoundBundle activeCertificate() {
    TrustPackage trustPackage = certificateProvider.getActiveTrustPackage();
    assertEquals(1, trustPackage.bundles().size());
    assertTrue(trustPackage.crossSignedCertificates().isEmpty());
    return trustPackage.bundles().get(0);
  }

  private record FakeComplete(int epoch, KeyBackup read) implements BackupHandle.Complete {}

  private record FakeEmpty(int epoch) implements BackupHandle.Empty {
    @Override
    public void write(KeyBackup backup) {}
  }

  private record FakeCompleteCrossSigned(
      CrossSignedCertificateId id, CrossSignedCertificateBackup read)
      implements CrossSignedCertHandle.Complete {}

  private record FakeEmptyCrossSigned(CrossSignedCertificateId id)
      implements CrossSignedCertHandle.Empty {
    @Override
    public void write(CrossSignedCertificateBackup backup) {}
  }

  private static BackupHandle completeHandle(KeyBackup backup) {
    return new FakeComplete(0, backup);
  }

  private static BackupHandle completeHandle(int epoch, KeyBackup backup) {
    return new FakeComplete(epoch, backup);
  }

  private static CrossSignedCertHandle completeCrossSignedHandle(
      CrossSignedCertificateId id, byte[] certBytes) {
    return new FakeCompleteCrossSigned(id, new CrossSignedCertificateBackup(certBytes));
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
      return bundleHandles.getOrDefault(epoch, new FakeEmpty(epoch));
    }

    @Override
    public CrossSignedCertHandle getCrossSignedCertHandle(CrossSignedCertificateId id) {
      return crossSignedCertHandles.getOrDefault(id, new FakeEmptyCrossSigned(id));
    }
  }

  private static StorageSnapshot snapshotOf(BackupHandle epoch0Handle) {
    return new FakeSnapshot(Map.of(0, epoch0Handle));
  }

  private void stubCrossSignedStorage(
      Map<CrossSignedCertificateId, CrossSignedCertHandle> crossSignedCertHandles)
      throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey0 =
        generateCertAndKey("CN=Test CA Epoch 0");
    KeyBackup backup0 =
        consistentBackup(
            certAndKey0.privateKey(), certAndKey0.certificate().getEncoded(), "epoch-0");
    when(storage.getSnapshot())
        .thenReturn(
            new FakeSnapshot(Map.of(0, completeHandle(0, backup0)), crossSignedCertHandles));
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

  private MbsCertificateFactory.X509CertificateAndPrivateKey generateCertAndKey(String subject)
      throws Exception {
    SelfSignedCertificate params = new SelfSignedCertificate(0, DEFAULT_VALIDITY);
    return MbsCertificateFactory.createSelfSignedCertificatesFactory(
            new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA"),
            new X500Name(subject),
            Optional.empty(),
            KeyUsage.keyCertSign)
        .generate(params);
  }

  @FunctionalInterface
  private interface CertificateEncoder {
    byte[] encode(X509Certificate certificate) throws Exception;
  }

  private void runReload_loadsFromStorageTest(CertificateEncoder encoder) throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    X509Certificate certificate = certAndKey.certificate();
    PrivateKey privateKey = certAndKey.privateKey();

    KeyBackup backup =
        consistentBackup(privateKey, encoder.encode(certificate), "loaded-from-storage");
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(backup)));

    certificateProvider.reload(CONFIG);
    MeasurementBoundBundle result = activeCertificate();

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
    verify(storage, times(1)).getSnapshot();
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.SUCCESS);
  }

  @Test
  public void reload_loadsFromStorageDer() throws Exception {
    runReload_loadsFromStorageTest(X509Certificate::getEncoded);
  }

  @Test
  public void reload_loadsFromStoragePem() throws Exception {
    runReload_loadsFromStorageTest(KmsMeasurementBoundCertificateGenerator::toPemBytes);
  }

  @Test
  public void reload_emptyStorage_throwsNotFoundAndDoesNotAcquireLock() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(new FakeEmpty(0)));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(CONFIG));

    assertEquals(KeyBackupNotFoundException.class, thrown.getCause().getClass());
    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.KEY_BACKUP_NOT_FOUND);
  }

  @Test
  public void reload_storageThrowsException_propagatesWrappedError() throws Exception {
    doThrow(new KeyBackupAccessFailedException("Failed to list")).when(storage).getSnapshot();

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.reload(CONFIG);
        });

    verify(storage, times(1)).getSnapshot();
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.S3_OPERATION_FAILED);
  }

  @Test
  public void reload_unexpectedRuntimeException_reportsCertificateLoadFailed() throws Exception {
    when(storage.getSnapshot()).thenThrow(new IllegalStateException("Unexpected error"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(CONFIG));

    assertEquals(IllegalStateException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.GENERAL_FAILURE);
  }

  @Test
  public void reload_kmsDecryptFails_reportsKmsOperationFailed() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    byte[] kmsEncryptedDataKey = "kms-encrypted-data-key".getBytes(StandardCharsets.UTF_8);

    KeyBackup backup =
        new KeyBackup(
            certAndKey.certificate().getEncoded(),
            kmsEncryptedDataKey,
            "unreadable-without-the-data-key".getBytes(StandardCharsets.UTF_8),
            "attestation-doc".getBytes(StandardCharsets.UTF_8));
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(backup)));
    when(kmsClient.decrypt(kmsEncryptedDataKey, KMS_KEY_ARN))
        .thenThrow(new KmsException("KMS error"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.reload(CONFIG);
        });

    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void reload_unchangedBackup_skipsKmsDecryptAndKeepsSameCertificateBundle()
      throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup backup =
        consistentBackup(
            certAndKey.privateKey(), certAndKey.certificate().getEncoded(), "steady-state");
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(backup)));

    certificateProvider.reload(CONFIG);
    MeasurementBoundBundle firstCert = activeCertificate();

    certificateProvider.reload(CONFIG);
    MeasurementBoundBundle secondCert = activeCertificate();

    verify(kmsClient, times(1)).decrypt(any(), eq(KMS_KEY_ARN));
    assertSame(firstCert, secondCert);
  }

  @Test
  public void reload_updatesTrustPackageWhenStorageChanges() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey1 =
        generateCertAndKey("CN=Test CA 1");
    KeyBackup first =
        consistentBackup(certAndKey1.privateKey(), certAndKey1.certificate().getEncoded(), "first");
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(first)));

    certificateProvider.reload(CONFIG);
    MeasurementBoundBundle initial = activeCertificate();
    assertNotNull(initial);
    assertEquals("CN=Test CA 1", initial.getCertificate().getSubjectX500Principal().getName());
    verify(kmsClient, times(1)).decrypt(eq(first.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));

    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey2 =
        generateCertAndKey("CN=Test CA 2");
    KeyBackup second =
        consistentBackup(
            certAndKey2.privateKey(), certAndKey2.certificate().getEncoded(), "second");
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(second)));

    certificateProvider.reload(CONFIG);
    MeasurementBoundBundle reloaded = activeCertificate();
    assertNotNull(reloaded);
    assertEquals("CN=Test CA 2", reloaded.getCertificate().getSubjectX500Principal().getName());
    assertEquals(
        "CN=Test CA 2", activeCertificate().getCertificate().getSubjectX500Principal().getName());
    verify(kmsClient, times(1)).decrypt(eq(second.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));
    verify(kmsClient, times(2)).decrypt(any(), eq(KMS_KEY_ARN));
  }

  @Test
  public void reload_multipleActiveEpochs_loadsActiveAndIgnoresInactive() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey0 =
        generateCertAndKey("CN=Test CA Epoch 0");
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey1 =
        generateCertAndKey("CN=Test CA Epoch 1");
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey2 =
        generateCertAndKey("CN=Test CA Epoch 2");
    KeyBackup backup0 =
        consistentBackup(
            certAndKey0.privateKey(), certAndKey0.certificate().getEncoded(), "epoch-0");
    KeyBackup backup1 =
        consistentBackup(
            certAndKey1.privateKey(), certAndKey1.certificate().getEncoded(), "epoch-1");
    KeyBackup backup2 =
        consistentBackup(
            certAndKey2.privateKey(), certAndKey2.certificate().getEncoded(), "epoch-2");

    when(storage.getSnapshot())
        .thenReturn(
            new FakeSnapshot(
                Map.of(
                    0, completeHandle(0, backup0),
                    1, completeHandle(1, backup1),
                    2, completeHandle(2, backup2))));

    certificateProvider.reload(
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1, 2))
            .setActiveSelfSignedCertificateIds(Set.of(2, 0))
            .build());

    TrustPackage pkg = certificateProvider.getActiveTrustPackage();
    assertEquals(2, pkg.bundles().size());
    assertTrue(pkg.crossSignedCertificates().isEmpty());
    Set<String> loadedSubjects =
        pkg.bundles().stream()
            .map(b -> b.getCertificate().getSubjectX500Principal().getName())
            .collect(Collectors.toSet());
    assertEquals(Set.of("CN=Test CA Epoch 0", "CN=Test CA Epoch 2"), loadedSubjects);
    verify(kmsClient, times(1)).decrypt(eq(backup0.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));
    verify(kmsClient, never()).decrypt(eq(backup1.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));
    verify(kmsClient, times(1)).decrypt(eq(backup2.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));
  }

  @Test
  public void reload_activeEpochsChanged_reusesCachedBundlesAndUpdatesActiveSet() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey0 =
        generateCertAndKey("CN=Test CA Epoch 0");
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey2 =
        generateCertAndKey("CN=Test CA Epoch 2");
    KeyBackup backup0 =
        consistentBackup(
            certAndKey0.privateKey(), certAndKey0.certificate().getEncoded(), "epoch-0");
    KeyBackup backup2 =
        consistentBackup(
            certAndKey2.privateKey(), certAndKey2.certificate().getEncoded(), "epoch-2");

    when(storage.getSnapshot())
        .thenReturn(
            new FakeSnapshot(
                Map.of(
                    0, completeHandle(0, backup0),
                    2, completeHandle(2, backup2))));

    CertificatesConfig.Builder configBuilder =
        CertificatesConfig.builder().setSelfSignedCertificates(selfSignedCerts(0, 2));

    certificateProvider.reload(configBuilder.setActiveSelfSignedCertificateIds(Set.of(0)).build());
    TrustPackage pkg0 = certificateProvider.getActiveTrustPackage();
    MeasurementBoundBundle bundle0 = pkg0.bundles().get(0);
    verify(kmsClient, times(1)).decrypt(eq(backup0.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));
    verify(kmsClient, never()).decrypt(eq(backup2.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));

    // Activating epoch 2 alongside epoch 0 reuses the cached epoch 0 bundle without re-decrypting.
    certificateProvider.reload(
        configBuilder.setActiveSelfSignedCertificateIds(Set.of(0, 2)).build());
    TrustPackage pkg0And2 = certificateProvider.getActiveTrustPackage();
    assertEquals(2, pkg0And2.bundles().size());
    assertTrue(pkg0And2.bundles().contains(bundle0));
    MeasurementBoundBundle bundle2 =
        pkg0And2.bundles().stream().filter(b -> b != bundle0).findFirst().orElseThrow();
    verify(kmsClient, times(1)).decrypt(eq(backup0.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));
    verify(kmsClient, times(1)).decrypt(eq(backup2.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));

    // Deactivating epoch 0 keeps only epoch 2 active and reuses its cached bundle.
    certificateProvider.reload(configBuilder.setActiveSelfSignedCertificateIds(Set.of(2)).build());
    TrustPackage pkg2 = certificateProvider.getActiveTrustPackage();
    assertEquals(1, pkg2.bundles().size());
    assertSame(bundle2, pkg2.bundles().get(0));
    verify(kmsClient, times(1)).decrypt(eq(backup2.kmsEncryptedDataKey()), eq(KMS_KEY_ARN));
  }

  @Test
  public void reload_oneOfMultipleActiveEpochsMissing_retainsPreviousTrustPackage()
      throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey0 =
        generateCertAndKey("CN=Test CA Epoch 0");
    KeyBackup backup0 =
        consistentBackup(
            certAndKey0.privateKey(), certAndKey0.certificate().getEncoded(), "epoch-0");
    when(storage.getSnapshot())
        .thenReturn(new FakeSnapshot(Map.of(0, completeHandle(0, backup0), 1, new FakeEmpty(1))));

    certificateProvider.reload(CONFIG);
    TrustPackage initialPackage = certificateProvider.getActiveTrustPackage();
    assertEquals(1, initialPackage.bundles().size());

    CertificatesConfig config0And1 =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1))
            .setActiveSelfSignedCertificateIds(Set.of(0, 1))
            .build();
    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(config0And1));

    assertEquals(KeyBackupNotFoundException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.KEY_BACKUP_NOT_FOUND);
    assertEquals(initialPackage, certificateProvider.getActiveTrustPackage());
    assertSame(
        initialPackage.bundles().get(0),
        certificateProvider.getActiveTrustPackage().bundles().get(0));
  }

  @Test
  public void reload_activeCrossSignedCertificates_loadsActiveAndUpdatesAcrossReloads()
      throws Exception {
    CrossSignedCertificateId id01 = new CrossSignedCertificateId(0, 1);
    CrossSignedCertificateId id10 = new CrossSignedCertificateId(1, 0);
    CrossSignedCertificateId id12 = new CrossSignedCertificateId(1, 2);
    X509Certificate cross01Cert = generateCertAndKey("CN=Cross 0_1").certificate();
    X509Certificate cross10Cert = generateCertAndKey("CN=Cross 1_0").certificate();
    X509Certificate cross12Cert = generateCertAndKey("CN=Cross 1_2").certificate();

    stubCrossSignedStorage(
        Map.of(
            id01,
            completeCrossSignedHandle(
                id01, KmsMeasurementBoundCertificateGenerator.toPemBytes(cross01Cert)),
            id10,
            completeCrossSignedHandle(
                id10, KmsMeasurementBoundCertificateGenerator.toPemBytes(cross10Cert)),
            id12,
            completeCrossSignedHandle(
                id12, KmsMeasurementBoundCertificateGenerator.toPemBytes(cross12Cert))));

    CertificatesConfig.Builder configBuilder =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1, 2))
            .setCrossSignedCertificates(crossSignedCerts(id01, id10, id12))
            .setActiveSelfSignedCertificateIds(Set.of(0));

    certificateProvider.reload(
        configBuilder.setActiveCrossSignedCertificateIds(Set.of(id01, id10)).build());

    TrustPackage pkg1 = certificateProvider.getActiveTrustPackage();
    assertEquals(List.of(cross01Cert, cross10Cert), pkg1.crossSignedCertificates());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.SUCCESS);

    certificateProvider.reload(
        configBuilder.setActiveCrossSignedCertificateIds(Set.of(id12)).build());
    TrustPackage pkg2 = certificateProvider.getActiveTrustPackage();
    assertEquals(List.of(cross12Cert), pkg2.crossSignedCertificates());

    certificateProvider.reload(configBuilder.setActiveCrossSignedCertificateIds(Set.of()).build());
    TrustPackage pkg3 = certificateProvider.getActiveTrustPackage();
    assertTrue(pkg3.crossSignedCertificates().isEmpty());
  }

  @Test
  public void reload_missingActiveCrossSignedCertificate_retainsPreviousTrustPackage()
      throws Exception {
    CrossSignedCertificateId id01 = new CrossSignedCertificateId(0, 1);
    CrossSignedCertificateId id10 = new CrossSignedCertificateId(1, 0);
    X509Certificate cross01Cert = generateCertAndKey("CN=Cross 0_1").certificate();

    stubCrossSignedStorage(
        Map.of(
            id01,
            completeCrossSignedHandle(
                id01, KmsMeasurementBoundCertificateGenerator.toPemBytes(cross01Cert))));

    CertificatesConfig.Builder configBuilder =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1))
            .setCrossSignedCertificates(crossSignedCerts(id01, id10))
            .setActiveSelfSignedCertificateIds(Set.of(0));

    certificateProvider.reload(
        configBuilder.setActiveCrossSignedCertificateIds(Set.of(id01)).build());
    TrustPackage initialPackage = certificateProvider.getActiveTrustPackage();
    assertEquals(List.of(cross01Cert), initialPackage.crossSignedCertificates());

    CertificatesConfig configWithMissingCross =
        configBuilder.setActiveCrossSignedCertificateIds(Set.of(id01, id10)).build();
    RuntimeException thrown =
        assertThrows(
            RuntimeException.class, () -> certificateProvider.reload(configWithMissingCross));

    assertEquals(KeyBackupNotFoundException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.KEY_BACKUP_NOT_FOUND);
    assertEquals(initialPackage, certificateProvider.getActiveTrustPackage());
  }

  @Test
  public void reload_corruptedCrossSignedCertificate_retainsPreviousTrustPackage()
      throws Exception {
    CrossSignedCertificateId id01 = new CrossSignedCertificateId(0, 1);
    X509Certificate cross01Cert = generateCertAndKey("CN=Cross 0_1").certificate();

    stubCrossSignedStorage(
        Map.of(
            id01,
            completeCrossSignedHandle(
                id01, KmsMeasurementBoundCertificateGenerator.toPemBytes(cross01Cert))));

    CertificatesConfig config =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1))
            .setCrossSignedCertificates(crossSignedCerts(id01))
            .setActiveSelfSignedCertificateIds(Set.of(0))
            .setActiveCrossSignedCertificateIds(Set.of(id01))
            .build();
    certificateProvider.reload(config);
    TrustPackage initialPackage = certificateProvider.getActiveTrustPackage();
    assertEquals(List.of(cross01Cert), initialPackage.crossSignedCertificates());

    stubCrossSignedStorage(
        Map.of(
            id01,
            completeCrossSignedHandle(id01, "corrupted-cert".getBytes(StandardCharsets.UTF_8))));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(config));

    assertEquals(BundleCorruptedException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    assertEquals(initialPackage, certificateProvider.getActiveTrustPackage());
  }

  @Test
  public void reload_kmsFailureThrowsAndRetainsActiveTrustPackage() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup active =
        consistentBackup(certAndKey.privateKey(), certAndKey.certificate().getEncoded(), "active");
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(active)));

    certificateProvider.reload(CONFIG);
    MeasurementBoundBundle initial = activeCertificate();
    assertNotNull(initial);

    // Storage is updated with a rotated certificate
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey2 =
        generateCertAndKey("CN=Test CA 2");
    KeyBackup second =
        consistentBackup(
            certAndKey2.privateKey(), certAndKey2.certificate().getEncoded(), "second");
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(second)));

    // Simulate KMS failure: decrypt throws regardless of arguments
    when(kmsClient.decrypt(any(), any())).thenThrow(new KmsException("testing decrypt failure"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(CONFIG));

    // KMS failures are checked exceptions, so callers receive them wrapped.
    assertEquals(KmsException.class, thrown.getCause().getClass());
    // The previously loaded certificate is still the one served
    assertSame(initial, activeCertificate());
  }

  @Test
  public void reload_storageFailureThrowsAndRetainsActiveTrustPackage() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup active =
        consistentBackup(certAndKey.privateKey(), certAndKey.certificate().getEncoded(), "active");
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(active)));

    certificateProvider.reload(CONFIG);
    MeasurementBoundBundle initial = activeCertificate();
    assertNotNull(initial);

    doThrow(new KeyBackupAccessFailedException("Failed to fetch object", new RuntimeException()))
        .when(storage)
        .getSnapshot();

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(CONFIG));

    assertEquals(KeyBackupAccessFailedException.class, thrown.getCause().getClass());
    assertSame(initial, activeCertificate());
  }

  @Test
  public void getActiveTrustPackage_uninitialized_throwsIllegalStateException() {
    IllegalStateException ex =
        assertThrows(
            IllegalStateException.class, () -> certificateProvider.getActiveTrustPackage());
    assertEquals("Trust package has not been initialized yet", ex.getMessage());
  }

  @Test
  public void reload_backupLostArtifacts_reportsCorruptedAndDoesNotGenerate() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(new BackupHandle.Incomplete(0, List.of("public/0/root_certificate.pem"))));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(CONFIG));

    assertEquals(KeyBackupIncompleteException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    verify(storage, never()).acquireLock();
    verify(kmsClient, never()).generateDataKey(any());
  }

  @Test
  public void reload_backupPartiallyWritten_retriesAndLoadsOnceComplete() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup backup =
        consistentBackup(certAndKey.privateKey(), certAndKey.certificate().getEncoded(), "settled");

    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                new BackupHandle.PartiallyWritten(0, List.of("public/0/root_certificate.pem"))))
        .thenReturn(snapshotOf(completeHandle(backup)));

    certificateProvider.reload(CONFIG);

    assertNotNull(activeCertificate());
    verify(mockMetrics, never()).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.SUCCESS);
    verify(storage, never()).acquireLock();
  }

  @Test
  public void reload_backupStaysPartiallyWritten_reportsCorruptedAfterRetry() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                new BackupHandle.PartiallyWritten(0, List.of("public/0/root_certificate.pem"))));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(CONFIG));

    assertEquals(KeyBackupPartiallyWrittenException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    verify(storage, never()).acquireLock();
    verify(kmsClient, never()).generateDataKey(any());
  }

  @Test
  public void reload_concurrentCalls_neverOverlap() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        generateCertAndKey("CN=Test CA");
    KeyBackup backup =
        consistentBackup(
            certAndKey.privateKey(), certAndKey.certificate().getEncoded(), "concurrent");

    AtomicInteger inFlight = new AtomicInteger();
    AtomicInteger peakInFlight = new AtomicInteger();
    when(storage.getSnapshot())
        .thenAnswer(
            invocation -> {
              peakInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
              Thread.sleep(20);
              inFlight.decrementAndGet();
              return snapshotOf(completeHandle(backup));
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
                  certificateProvider.reload(CONFIG);
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
  public void reload_mismatchedPrivateKey_rejectsAndReportsCorrupted() throws Exception {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKeyA =
        generateCertAndKey("CN=Test CA");
    KeyPair keyPairB = generateKeyPair();

    KeyBackup backup =
        consistentBackup(
            keyPairB.getPrivate(), certAndKeyA.certificate().getEncoded(), "mismatched");
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(backup)));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> certificateProvider.reload(CONFIG));

    assertEquals(BundleCorruptedException.class, thrown.getCause().getClass());
    verify(storage, never()).acquireLock();
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    verify(mockMetrics, never()).recordLoadEvent(Metrics.LoadEvent.SUCCESS);
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
