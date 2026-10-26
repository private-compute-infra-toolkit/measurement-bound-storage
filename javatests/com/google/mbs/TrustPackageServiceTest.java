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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.AttestationToken;
import com.google.mbs.domain.BackupAccessFailedException;
import com.google.mbs.domain.BackupCorruptedException;
import com.google.mbs.domain.BackupIncompleteException;
import com.google.mbs.domain.BackupNotFoundException;
import com.google.mbs.domain.BackupPartiallyWrittenException;
import com.google.mbs.domain.BackupStorage;
import com.google.mbs.domain.CertificateCodec;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertificate;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateBackupHandle;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedBundle;
import com.google.mbs.domain.SelfSignedBundleBackup;
import com.google.mbs.domain.SelfSignedBundleBackupHandle;
import com.google.mbs.domain.SelfSignedBundleBackupSealer;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.StorageSnapshot;
import com.google.mbs.domain.TrustPackage;
import com.google.mbs.domain.ValidityPeriod;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class TrustPackageServiceTest {

  private static final ValidityPeriod DEFAULT_VALIDITY =
      new ValidityPeriod(
          Instant.parse("1930-01-01T00:00:00Z"), Instant.parse("1930-02-01T00:00:00Z"));
  private static final CertificatesConfig CONFIG =
      CertificatesConfig.builder()
          .setSelfSignedCertificates(selfSignedCerts(0))
          .setActiveSelfSignedCertificateIds(Set.of(0))
          .build();

  private static final SelfSignedBundleBackup BACKUP_0 = dummyBackup("epoch-0");
  private static final SelfSignedBundleBackup BACKUP_1 = dummyBackup("epoch-1");
  private static final SelfSignedBundleBackup BACKUP_2 = dummyBackup("epoch-2");
  private static final byte[] CROSS_01_BYTES = "cross-01".getBytes(StandardCharsets.UTF_8);
  private static final byte[] CROSS_10_BYTES = "cross-10".getBytes(StandardCharsets.UTF_8);
  private static final byte[] CROSS_12_BYTES = "cross-12".getBytes(StandardCharsets.UTF_8);

  private static final SelfSignedBundle bundle0 = dummyBundle("epoch-0");
  private static final SelfSignedBundle bundle1 = dummyBundle("epoch-1");
  private static final SelfSignedBundle bundle2 = dummyBundle("epoch-2");
  private static final X509Certificate cross01Cert = mock(X509Certificate.class);
  private static final X509Certificate cross10Cert = mock(X509Certificate.class);
  private static final X509Certificate cross12Cert = mock(X509Certificate.class);

  @Mock private SelfSignedBundleBackupSealer backupSealer;
  @Mock private CertificateCodec certificateCodec;
  @Mock private BackupStorage storage;
  @Mock private Metrics mockMetrics;

  private TrustPackageService trustPackageService;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);

    when(backupSealer.unseal(BACKUP_0)).thenReturn(bundle0);
    when(backupSealer.unseal(BACKUP_1)).thenReturn(bundle1);
    when(backupSealer.unseal(BACKUP_2)).thenReturn(bundle2);
    when(certificateCodec.toCertificate(CROSS_01_BYTES)).thenReturn(cross01Cert);
    when(certificateCodec.toCertificate(CROSS_10_BYTES)).thenReturn(cross10Cert);
    when(certificateCodec.toCertificate(CROSS_12_BYTES)).thenReturn(cross12Cert);

    trustPackageService =
        new TrustPackageService(backupSealer, certificateCodec, storage, mockMetrics);
    trustPackageService.retryBackoff = Duration.ZERO;
  }

  private static SelfSignedBundleBackup dummyBackup(String label) {
    return new SelfSignedBundleBackup(
        ("cert-" + label).getBytes(StandardCharsets.UTF_8),
        ("kms-key-" + label).getBytes(StandardCharsets.UTF_8),
        ("priv-key-" + label).getBytes(StandardCharsets.UTF_8),
        ("attestation-" + label).getBytes(StandardCharsets.UTF_8));
  }

  private static SelfSignedBundle dummyBundle(String label) {
    return new SelfSignedBundle(
        mock(X509Certificate.class),
        mock(PrivateKey.class),
        AttestationToken.fromBytes(("att-" + label).getBytes(StandardCharsets.UTF_8)));
  }

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

  private SelfSignedBundle activeCertificate() {
    TrustPackage trustPackage = trustPackageService.getActiveTrustPackage();
    assertEquals(1, trustPackage.selfSignedBundles().size());
    assertTrue(trustPackage.crossSignedCertificates().isEmpty());
    return trustPackage.selfSignedBundles().get(0);
  }

  private record FakeComplete(int epoch, SelfSignedBundleBackup read)
      implements SelfSignedBundleBackupHandle.Complete {}

  private record FakeEmpty(int epoch) implements SelfSignedBundleBackupHandle.Empty {
    @Override
    public void write(SelfSignedBundleBackup backup) {}
  }

  private record FakeCompleteCrossSigned(
      CrossSignedCertificateId id, CrossSignedCertificateBackup read)
      implements CrossSignedCertificateBackupHandle.Complete {}

  private record FakeEmptyCrossSigned(CrossSignedCertificateId id)
      implements CrossSignedCertificateBackupHandle.Empty {
    @Override
    public void write(CrossSignedCertificateBackup backup) {}
  }

  private static SelfSignedBundleBackupHandle completeHandle(SelfSignedBundleBackup backup) {
    return new FakeComplete(0, backup);
  }

  private static SelfSignedBundleBackupHandle completeHandle(
      int epoch, SelfSignedBundleBackup backup) {
    return new FakeComplete(epoch, backup);
  }

  private static CrossSignedCertificateBackupHandle completeCrossSignedHandle(
      CrossSignedCertificateId id, byte[] certBytes) {
    return new FakeCompleteCrossSigned(id, new CrossSignedCertificateBackup(certBytes));
  }

  private record FakeSnapshot(
      Map<Integer, SelfSignedBundleBackupHandle> selfSignedBundleBackupHandles,
      Map<CrossSignedCertificateId, CrossSignedCertificateBackupHandle>
          crossSignedCertificateBackupHandles)
      implements StorageSnapshot {

    FakeSnapshot(Map<Integer, SelfSignedBundleBackupHandle> selfSignedBundleBackupHandles) {
      this(selfSignedBundleBackupHandles, Map.of());
    }

    @Override
    public SelfSignedBundleBackupHandle getSelfSignedBundleBackupHandle(int epoch) {
      return selfSignedBundleBackupHandles.getOrDefault(epoch, new FakeEmpty(epoch));
    }

    @Override
    public CrossSignedCertificateBackupHandle getCrossSignedCertificateBackupHandle(
        CrossSignedCertificateId id) {
      return crossSignedCertificateBackupHandles.getOrDefault(id, new FakeEmptyCrossSigned(id));
    }
  }

  private static StorageSnapshot snapshotOf(SelfSignedBundleBackupHandle epoch0Handle) {
    return new FakeSnapshot(Map.of(0, epoch0Handle));
  }

  private void stubCrossSignedStorage(
      Map<CrossSignedCertificateId, CrossSignedCertificateBackupHandle>
          crossSignedCertificateBackupHandles)
      throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            new FakeSnapshot(
                Map.of(0, completeHandle(0, BACKUP_0)), crossSignedCertificateBackupHandles));
  }

  @Test
  public void reload_loadsFromStorage() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_0)));

    trustPackageService.reload(CONFIG);
    SelfSignedBundle result = activeCertificate();

    assertSame(bundle0, result);
    assertSame(result, activeCertificate());
    verify(storage, times(1)).getSnapshot();
    verify(backupSealer, times(1)).unseal(BACKUP_0);
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.SUCCESS);
  }

  @Test
  public void reload_emptyStorage_throwsNotFoundAndDoesNotAcquireLock() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(new FakeEmpty(0)));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    assertEquals(BackupNotFoundException.class, thrown.getCause().getClass());
    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.BACKUP_NOT_FOUND);
  }

  @Test
  public void reload_storageThrowsException_propagatesWrappedError() throws Exception {
    doThrow(new BackupAccessFailedException("Failed to list")).when(storage).getSnapshot();

    assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    verify(storage, times(1)).getSnapshot();
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.S3_OPERATION_FAILED);
  }

  @Test
  public void reload_unexpectedRuntimeException_reportsCertificateLoadFailed() throws Exception {
    when(storage.getSnapshot()).thenThrow(new IllegalStateException("Unexpected error"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    assertEquals(IllegalStateException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.GENERAL_FAILURE);
  }

  @Test
  public void reload_kmsDecryptFails_reportsKmsOperationFailed() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_0)));
    when(backupSealer.unseal(BACKUP_0)).thenThrow(new KmsException("KMS error"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    assertEquals(KmsException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void reload_corruptedBackup_reportsCorrupted() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_0)));
    when(backupSealer.unseal(BACKUP_0)).thenThrow(new BackupCorruptedException("Corrupted backup"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    assertEquals(BackupCorruptedException.class, thrown.getCause().getClass());
    verify(storage, never()).acquireLock();
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    verify(mockMetrics, never()).recordLoadEvent(Metrics.LoadEvent.SUCCESS);
    assertThrows(IllegalStateException.class, trustPackageService::getActiveTrustPackage);
  }

  @Test
  public void reload_unchangedBackup_skipsUnsealAndKeepsSameCertificateBundle() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_0)));

    trustPackageService.reload(CONFIG);
    SelfSignedBundle firstCert = activeCertificate();

    trustPackageService.reload(CONFIG);
    SelfSignedBundle secondCert = activeCertificate();

    verify(backupSealer, times(1)).unseal(any());
    assertSame(firstCert, secondCert);
  }

  @Test
  public void reload_updatesTrustPackageWhenStorageChanges() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_0)));

    trustPackageService.reload(CONFIG);
    assertSame(bundle0, activeCertificate());
    verify(backupSealer, times(1)).unseal(BACKUP_0);

    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_1)));

    trustPackageService.reload(CONFIG);
    assertSame(bundle1, activeCertificate());
    verify(backupSealer, times(1)).unseal(BACKUP_1);
    verify(backupSealer, times(2)).unseal(any());
  }

  @Test
  public void reload_multipleActiveEpochs_loadsActiveAndIgnoresInactive() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            new FakeSnapshot(
                Map.of(
                    0, completeHandle(0, BACKUP_0),
                    1, completeHandle(1, BACKUP_1),
                    2, completeHandle(2, BACKUP_2))));

    trustPackageService.reload(
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1, 2))
            .setActiveSelfSignedCertificateIds(Set.of(2, 0))
            .build());

    TrustPackage pkg = trustPackageService.getActiveTrustPackage();
    assertEquals(Set.of(bundle0, bundle2), Set.copyOf(pkg.selfSignedBundles()));
    assertTrue(pkg.crossSignedCertificates().isEmpty());
    verify(backupSealer, times(1)).unseal(BACKUP_0);
    verify(backupSealer, never()).unseal(BACKUP_1);
    verify(backupSealer, times(1)).unseal(BACKUP_2);
  }

  @Test
  public void reload_activeEpochsChanged_reusesCachedBundlesAndUpdatesActiveSet() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            new FakeSnapshot(
                Map.of(
                    0, completeHandle(0, BACKUP_0),
                    2, completeHandle(2, BACKUP_2))));

    CertificatesConfig.Builder configBuilder =
        CertificatesConfig.builder().setSelfSignedCertificates(selfSignedCerts(0, 2));

    trustPackageService.reload(configBuilder.setActiveSelfSignedCertificateIds(Set.of(0)).build());
    assertSame(bundle0, trustPackageService.getActiveTrustPackage().selfSignedBundles().get(0));
    verify(backupSealer, times(1)).unseal(BACKUP_0);
    verify(backupSealer, never()).unseal(BACKUP_2);

    // Activating epoch 2 alongside epoch 0 reuses the cached epoch 0 bundle without re-unsealing.
    trustPackageService.reload(
        configBuilder.setActiveSelfSignedCertificateIds(Set.of(0, 2)).build());
    TrustPackage pkg0And2 = trustPackageService.getActiveTrustPackage();
    assertEquals(Set.of(bundle0, bundle2), Set.copyOf(pkg0And2.selfSignedBundles()));
    verify(backupSealer, times(1)).unseal(BACKUP_0);
    verify(backupSealer, times(1)).unseal(BACKUP_2);

    // Deactivating epoch 0 keeps only epoch 2 active and reuses its cached bundle.
    trustPackageService.reload(configBuilder.setActiveSelfSignedCertificateIds(Set.of(2)).build());
    TrustPackage pkg2 = trustPackageService.getActiveTrustPackage();
    assertEquals(1, pkg2.selfSignedBundles().size());
    assertSame(bundle2, pkg2.selfSignedBundles().get(0));
    verify(backupSealer, times(1)).unseal(BACKUP_2);
  }

  @Test
  public void reload_oneOfMultipleActiveEpochsMissing_retainsPreviousTrustPackage()
      throws Exception {
    when(storage.getSnapshot())
        .thenReturn(new FakeSnapshot(Map.of(0, completeHandle(0, BACKUP_0), 1, new FakeEmpty(1))));

    trustPackageService.reload(CONFIG);
    TrustPackage initialPackage = trustPackageService.getActiveTrustPackage();
    assertEquals(1, initialPackage.selfSignedBundles().size());

    CertificatesConfig config0And1 =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1))
            .setActiveSelfSignedCertificateIds(Set.of(0, 1))
            .build();
    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(config0And1));

    assertEquals(BackupNotFoundException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.BACKUP_NOT_FOUND);
    assertEquals(initialPackage, trustPackageService.getActiveTrustPackage());
    assertSame(
        initialPackage.selfSignedBundles().get(0),
        trustPackageService.getActiveTrustPackage().selfSignedBundles().get(0));
  }

  @Test
  public void reload_activeCrossSignedCertificates_loadsActiveAndUpdatesAcrossReloads()
      throws Exception {
    CrossSignedCertificateId id01 = new CrossSignedCertificateId(0, 1);
    CrossSignedCertificateId id10 = new CrossSignedCertificateId(1, 0);
    CrossSignedCertificateId id12 = new CrossSignedCertificateId(1, 2);

    stubCrossSignedStorage(
        Map.of(
            id01,
            completeCrossSignedHandle(id01, CROSS_01_BYTES),
            id10,
            completeCrossSignedHandle(id10, CROSS_10_BYTES),
            id12,
            completeCrossSignedHandle(id12, CROSS_12_BYTES)));

    CertificatesConfig.Builder configBuilder =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1, 2))
            .setCrossSignedCertificates(crossSignedCerts(id01, id10, id12))
            .setActiveSelfSignedCertificateIds(Set.of(0));

    trustPackageService.reload(
        configBuilder.setActiveCrossSignedCertificateIds(Set.of(id01, id10)).build());

    TrustPackage pkg1 = trustPackageService.getActiveTrustPackage();
    assertEquals(List.of(cross01Cert, cross10Cert), pkg1.crossSignedCertificates());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.SUCCESS);

    trustPackageService.reload(
        configBuilder.setActiveCrossSignedCertificateIds(Set.of(id12)).build());
    TrustPackage pkg2 = trustPackageService.getActiveTrustPackage();
    assertEquals(List.of(cross12Cert), pkg2.crossSignedCertificates());

    trustPackageService.reload(configBuilder.setActiveCrossSignedCertificateIds(Set.of()).build());
    TrustPackage pkg3 = trustPackageService.getActiveTrustPackage();
    assertTrue(pkg3.crossSignedCertificates().isEmpty());
  }

  @Test
  public void reload_missingActiveCrossSignedCertificate_retainsPreviousTrustPackage()
      throws Exception {
    CrossSignedCertificateId id01 = new CrossSignedCertificateId(0, 1);
    CrossSignedCertificateId id10 = new CrossSignedCertificateId(1, 0);

    stubCrossSignedStorage(Map.of(id01, completeCrossSignedHandle(id01, CROSS_01_BYTES)));

    CertificatesConfig.Builder configBuilder =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1))
            .setCrossSignedCertificates(crossSignedCerts(id01, id10))
            .setActiveSelfSignedCertificateIds(Set.of(0));

    trustPackageService.reload(
        configBuilder.setActiveCrossSignedCertificateIds(Set.of(id01)).build());
    TrustPackage initialPackage = trustPackageService.getActiveTrustPackage();
    assertEquals(List.of(cross01Cert), initialPackage.crossSignedCertificates());

    CertificatesConfig configWithMissingCross =
        configBuilder.setActiveCrossSignedCertificateIds(Set.of(id01, id10)).build();
    RuntimeException thrown =
        assertThrows(
            RuntimeException.class, () -> trustPackageService.reload(configWithMissingCross));

    assertEquals(BackupNotFoundException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.BACKUP_NOT_FOUND);
    assertEquals(initialPackage, trustPackageService.getActiveTrustPackage());
  }

  @Test
  public void reload_corruptedCrossSignedCertificate_retainsPreviousTrustPackage()
      throws Exception {
    CrossSignedCertificateId id01 = new CrossSignedCertificateId(0, 1);
    byte[] corruptedBytes = "corrupted-cert".getBytes(StandardCharsets.UTF_8);
    when(certificateCodec.toCertificate(corruptedBytes))
        .thenThrow(new IllegalArgumentException("Corrupted cert"));

    stubCrossSignedStorage(Map.of(id01, completeCrossSignedHandle(id01, CROSS_01_BYTES)));

    CertificatesConfig config =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(selfSignedCerts(0, 1))
            .setCrossSignedCertificates(crossSignedCerts(id01))
            .setActiveSelfSignedCertificateIds(Set.of(0))
            .setActiveCrossSignedCertificateIds(Set.of(id01))
            .build();
    trustPackageService.reload(config);
    TrustPackage initialPackage = trustPackageService.getActiveTrustPackage();
    assertEquals(List.of(cross01Cert), initialPackage.crossSignedCertificates());

    stubCrossSignedStorage(Map.of(id01, completeCrossSignedHandle(id01, corruptedBytes)));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(config));

    assertEquals(BackupCorruptedException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    assertEquals(initialPackage, trustPackageService.getActiveTrustPackage());
  }

  @Test
  public void reload_kmsFailureThrowsAndRetainsActiveTrustPackage() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_0)));

    trustPackageService.reload(CONFIG);
    SelfSignedBundle initial = activeCertificate();
    assertNotNull(initial);

    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_1)));
    when(backupSealer.unseal(BACKUP_1)).thenThrow(new KmsException("testing decrypt failure"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    assertEquals(KmsException.class, thrown.getCause().getClass());
    assertSame(initial, activeCertificate());
  }

  @Test
  public void reload_storageFailureThrowsAndRetainsActiveTrustPackage() throws Exception {
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle(BACKUP_0)));

    trustPackageService.reload(CONFIG);
    SelfSignedBundle initial = activeCertificate();
    assertNotNull(initial);

    doThrow(new BackupAccessFailedException("Failed to fetch object", new RuntimeException()))
        .when(storage)
        .getSnapshot();

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    assertEquals(BackupAccessFailedException.class, thrown.getCause().getClass());
    assertSame(initial, activeCertificate());
  }

  @Test
  public void getActiveTrustPackage_uninitialized_throwsIllegalStateException() {
    IllegalStateException ex =
        assertThrows(
            IllegalStateException.class, () -> trustPackageService.getActiveTrustPackage());
    assertEquals("Trust package has not been initialized yet", ex.getMessage());
  }

  @Test
  public void reload_backupLostArtifacts_reportsCorruptedAndDoesNotGenerate() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                new SelfSignedBundleBackupHandle.Incomplete(
                    0, List.of("public/0/root_certificate.pem"))));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    assertEquals(BackupIncompleteException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    verify(storage, never()).acquireLock();
    verify(backupSealer, never()).unseal(any());
  }

  @Test
  public void reload_backupPartiallyWritten_retriesAndLoadsOnceComplete() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                new SelfSignedBundleBackupHandle.PartiallyWritten(
                    0, List.of("public/0/root_certificate.pem"))))
        .thenReturn(snapshotOf(completeHandle(BACKUP_0)));

    trustPackageService.reload(CONFIG);

    assertSame(bundle0, activeCertificate());
    verify(mockMetrics, never()).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.SUCCESS);
    verify(storage, never()).acquireLock();
  }

  @Test
  public void reload_backupStaysPartiallyWritten_reportsCorruptedAfterRetry() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                new SelfSignedBundleBackupHandle.PartiallyWritten(
                    0, List.of("public/0/root_certificate.pem"))));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> trustPackageService.reload(CONFIG));

    assertEquals(BackupPartiallyWrittenException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordLoadEvent(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED);
    verify(storage, never()).acquireLock();
    verify(backupSealer, never()).unseal(any());
  }

  @Test
  public void reload_concurrentCalls_neverOverlap() throws Exception {
    AtomicInteger inFlight = new AtomicInteger();
    AtomicInteger peakInFlight = new AtomicInteger();
    when(storage.getSnapshot())
        .thenAnswer(
            invocation -> {
              peakInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
              Thread.sleep(20);
              inFlight.decrementAndGet();
              return snapshotOf(completeHandle(BACKUP_0));
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
                  trustPackageService.reload(CONFIG);
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
    assertSame(bundle0, activeCertificate());
  }
}
