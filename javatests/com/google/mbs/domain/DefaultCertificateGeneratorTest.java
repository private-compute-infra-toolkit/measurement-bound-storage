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

package com.google.mbs.domain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class DefaultCertificateGeneratorTest {

  private static final ValidityPeriod VALIDITY_PERIOD_0 =
      new ValidityPeriod(
          Instant.parse("1930-01-01T00:00:00Z"), Instant.parse("1930-02-01T00:00:00Z"));
  private static final ValidityPeriod VALIDITY_PERIOD_1 =
      new ValidityPeriod(
          Instant.parse("1931-01-01T00:00:00Z"), Instant.parse("1931-02-01T00:00:00Z"));
  private static final ValidityPeriod VALIDITY_PERIOD_2 =
      new ValidityPeriod(
          Instant.parse("1932-01-01T00:00:00Z"), Instant.parse("1932-02-01T00:00:00Z"));

  private static final SelfSignedCertificate CERT_0 =
      new SelfSignedCertificate(0, VALIDITY_PERIOD_0);
  private static final SelfSignedCertificate CERT_1 =
      new SelfSignedCertificate(1, VALIDITY_PERIOD_1);
  private static final SelfSignedCertificate CERT_2 =
      new SelfSignedCertificate(2, VALIDITY_PERIOD_2);

  private static final SelfSignedBundleBackup BACKUP_0 = dummyBackup("epoch-0");
  private static final SelfSignedBundleBackup BACKUP_1 = dummyBackup("epoch-1");
  private static final SelfSignedBundleBackup BACKUP_2 = dummyBackup("epoch-2");

  private static final CrossSignedCertificate CROSS_CERT_0_1 =
      new CrossSignedCertificate(0, 1, VALIDITY_PERIOD_1);
  private static final CrossSignedCertificate CROSS_CERT_1_0 =
      new CrossSignedCertificate(1, 0, VALIDITY_PERIOD_1);
  private static final CrossSignedCertificateBackup CROSS_BACKUP_0_1 =
      new CrossSignedCertificateBackup("cross-0-1".getBytes(StandardCharsets.UTF_8));
  private static final CrossSignedCertificateBackup CROSS_BACKUP_1_0 =
      new CrossSignedCertificateBackup("cross-1-0".getBytes(StandardCharsets.UTF_8));

  private static final CertificatesConfig CONFIG =
      CertificatesConfig.builder()
          .setSelfSignedCertificates(Map.of(0, CERT_0))
          .setActiveSelfSignedCertificateIds(Set.of(0))
          .setAcceptableSelfSignedCertificateIds(Set.of(0))
          .build();
  private static final CertificatesConfig TWO_EPOCH_WITH_CROSS_CERT_CONFIG =
      CertificatesConfig.builder()
          .setSelfSignedCertificates(Map.of(0, CERT_0, 1, CERT_1))
          .setCrossSignedCertificates(
              Map.of(CROSS_CERT_0_1.id(), CROSS_CERT_0_1, CROSS_CERT_1_0.id(), CROSS_CERT_1_0))
          .setActiveSelfSignedCertificateIds(Set.of(0))
          .setAcceptableSelfSignedCertificateIds(Set.of(0, 1))
          .build();

  @Mock private BackupStorage storage;
  @Mock private SelfSignedBundleBackupGenerator selfSignedBundleBackupGenerator;
  @Mock private CrossSignedCertificateBackupGenerator crossSignedCertificateBackupGenerator;
  @Mock private Metrics mockMetrics;

  private DefaultCertificateGenerator generator;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    when(selfSignedBundleBackupGenerator.generate(CERT_0)).thenReturn(BACKUP_0);
    when(selfSignedBundleBackupGenerator.generate(CERT_1)).thenReturn(BACKUP_1);
    when(selfSignedBundleBackupGenerator.generate(CERT_2)).thenReturn(BACKUP_2);
    when(crossSignedCertificateBackupGenerator.generate(CROSS_CERT_0_1, BACKUP_0, BACKUP_1))
        .thenReturn(CROSS_BACKUP_0_1);
    when(crossSignedCertificateBackupGenerator.generate(CROSS_CERT_1_0, BACKUP_1, BACKUP_0))
        .thenReturn(CROSS_BACKUP_1_0);

    generator =
        new DefaultCertificateGenerator(
            storage,
            selfSignedBundleBackupGenerator,
            crossSignedCertificateBackupGenerator,
            mockMetrics);
    generator.retryBackoff = Duration.ZERO;
  }

  private static SelfSignedBundleBackup dummyBackup(String label) {
    return new SelfSignedBundleBackup(
        ("cert-" + label).getBytes(StandardCharsets.UTF_8),
        ("key-" + label).getBytes(StandardCharsets.UTF_8),
        ("priv-" + label).getBytes(StandardCharsets.UTF_8),
        ("att-" + label).getBytes(StandardCharsets.UTF_8));
  }

  private static SelfSignedBundleBackupHandle.Complete completeSelfSignedHandle(int epoch) {
    return new FakeCompleteSelfSigned(epoch, null);
  }

  private static SelfSignedBundleBackupHandle.Complete completeSelfSignedHandle(
      int epoch, SelfSignedBundleBackup backup) {
    return new FakeCompleteSelfSigned(epoch, backup);
  }

  private record FakeCompleteSelfSigned(int epoch, SelfSignedBundleBackup read)
      implements SelfSignedBundleBackupHandle.Complete {}

  private static CrossSignedCertificateBackupHandle.Complete completeCrossSignedHandle(
      CrossSignedCertificateId id) {
    return new FakeCompleteCrossSigned(id, null);
  }

  private record FakeCompleteCrossSigned(
      CrossSignedCertificateId id, CrossSignedCertificateBackup read)
      implements CrossSignedCertificateBackupHandle.Complete {}

  private record FakeSnapshot(
      Collection<SelfSignedBundleBackupHandle> selfSignedHandles,
      Collection<CrossSignedCertificateBackupHandle> crossSignedHandles)
      implements StorageSnapshot {

    @Override
    public SelfSignedBundleBackupHandle getSelfSignedBundleBackupHandle(int epoch) {
      return selfSignedHandles.stream()
          .filter(h -> h.epoch() == epoch)
          .findFirst()
          .orElseGet(() -> emptySelfSignedHandle(epoch));
    }

    @Override
    public CrossSignedCertificateBackupHandle getCrossSignedCertificateBackupHandle(
        CrossSignedCertificateId id) {
      return crossSignedHandles.stream()
          .filter(h -> h.id().equals(id))
          .findFirst()
          .orElseGet(() -> emptyCrossSignedHandle(id));
    }
  }

  private static StorageSnapshot snapshotOf(
      Collection<SelfSignedBundleBackupHandle> selfSignedHandles,
      Collection<CrossSignedCertificateBackupHandle> crossSignedHandles) {
    return new FakeSnapshot(selfSignedHandles, crossSignedHandles);
  }

  private static SelfSignedBundleBackupHandle.Empty emptySelfSignedHandle(int epoch) {
    SelfSignedBundleBackupHandle.Empty empty = mock(SelfSignedBundleBackupHandle.Empty.class);
    when(empty.epoch()).thenReturn(epoch);
    return empty;
  }

  private static CrossSignedCertificateBackupHandle.Empty emptyCrossSignedHandle(
      CrossSignedCertificateId id) {
    CrossSignedCertificateBackupHandle.Empty empty =
        mock(CrossSignedCertificateBackupHandle.Empty.class);
    when(empty.id()).thenReturn(id);
    return empty;
  }

  private SelfSignedBundleBackupHandle.Empty stubEmptyStorage() throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = emptySelfSignedHandle(0);
    when(storage.getSnapshot()).thenReturn(snapshotOf(List.of(empty), List.of()));
    return empty;
  }

  @Test
  public void generateCertificates_emptyStorage_generatesAndWrites() throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = stubEmptyStorage();

    generator.generateCertificates(CONFIG);

    InOrder inOrder = inOrder(storage, selfSignedBundleBackupGenerator, empty);
    inOrder.verify(storage).getSnapshot();
    inOrder.verify(storage).acquireLock();
    inOrder.verify(storage).getSnapshot();
    inOrder.verify(selfSignedBundleBackupGenerator).generate(CERT_0);
    inOrder.verify(empty).write(BACKUP_0);
    inOrder.verify(storage).releaseLock();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_completeBackupExists_skipsWithoutLocking() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                List.of(completeSelfSignedHandle(0), completeSelfSignedHandle(1)),
                List.of(
                    completeCrossSignedHandle(CROSS_CERT_0_1.id()),
                    completeCrossSignedHandle(CROSS_CERT_1_0.id()))));

    generator.generateCertificates(TWO_EPOCH_WITH_CROSS_CERT_CONFIG);

    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(crossSignedCertificateBackupGenerator, never()).generate(any(), any(), any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_incompleteBackupExists_skipsWithoutLocking() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                List.of(
                    new SelfSignedBundleBackupHandle.Incomplete(
                        0, List.of("public/0/root_certificate.pem"))),
                List.of()));

    generator.generateCertificates(CONFIG);

    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_partiallyWrittenBackupExists_skipsWithoutLocking()
      throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                List.of(
                    new SelfSignedBundleBackupHandle.PartiallyWritten(
                        0, List.of("public/0/root_certificate.pem"))),
                List.of()));

    generator.generateCertificates(CONFIG);

    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_backupAppearsUnderLock_releasesLockWithoutGenerating()
      throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = emptySelfSignedHandle(0);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(List.of(empty), List.of()))
        .thenReturn(snapshotOf(List.of(completeSelfSignedHandle(0)), List.of()));

    generator.generateCertificates(CONFIG);

    verify(storage, times(3)).getSnapshot();
    verify(storage).acquireLock();
    verify(storage).releaseLock();
    verify(empty, never()).write(any());
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_partiallyWrittenUnderLock_releasesLockWithoutGenerating()
      throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = emptySelfSignedHandle(0);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(List.of(empty), List.of()))
        .thenReturn(
            snapshotOf(
                List.of(
                    new SelfSignedBundleBackupHandle.PartiallyWritten(
                        0, List.of("public/0/root_certificate.pem"))),
                List.of()));

    generator.generateCertificates(CONFIG);

    verify(storage, times(3)).getSnapshot();
    verify(storage).acquireLock();
    verify(storage).releaseLock();
    verify(empty, never()).write(any());
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_selfSignedGenerationFails_doesNotReleaseLock() throws Exception {
    SelfSignedBundleBackupHandle.Empty empty0 = emptySelfSignedHandle(0);
    SelfSignedBundleBackupHandle.Empty empty1 = emptySelfSignedHandle(1);
    when(storage.getSnapshot()).thenReturn(snapshotOf(List.of(empty0, empty1), List.of()));
    when(selfSignedBundleBackupGenerator.generate(CERT_1))
        .thenThrow(new KmsException("KMS error on epoch 1"));

    RuntimeException thrown =
        assertThrows(
            RuntimeException.class,
            () -> generator.generateCertificates(TWO_EPOCH_WITH_CROSS_CERT_CONFIG));

    assertEquals(KmsException.class, thrown.getCause().getClass());
    verify(empty0).write(BACKUP_0);
    verify(empty1, never()).write(any());
    verify(storage).acquireLock();
    verify(storage, never()).releaseLock();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void generateCertificates_crossSignedGenerationFails_doesNotReleaseLock()
      throws Exception {
    StorageSnapshot snapshot =
        snapshotOf(
            List.of(
                new SelfSignedBundleBackupHandle.Incomplete(
                    0, List.of("public/0/root_certificate.pem")),
                completeSelfSignedHandle(1, BACKUP_1)),
            List.of());
    when(storage.getSnapshot()).thenReturn(snapshot);

    RuntimeException thrown =
        assertThrows(
            RuntimeException.class,
            () -> generator.generateCertificates(TWO_EPOCH_WITH_CROSS_CERT_CONFIG));

    assertEquals(BackupIncompleteException.class, thrown.getCause().getClass());
    verify(storage).acquireLock();
    verify(storage, never()).releaseLock();
    verify(crossSignedCertificateBackupGenerator, never()).generate(any(), any(), any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.GENERAL_FAILURE);
  }

  @Test
  public void generateCertificates_alreadyLocked_waitsAndSkipsWhenWinnerPublishes()
      throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = emptySelfSignedHandle(0);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(List.of(empty), List.of()))
        .thenReturn(snapshotOf(List.of(completeSelfSignedHandle(0)), List.of()));
    doThrow(new BackupStorageAlreadyLockedException("Generation lock present"))
        .when(storage)
        .acquireLock();

    generator.generateCertificates(CONFIG);

    verify(storage, times(2)).getSnapshot();
    verify(storage, times(1)).acquireLock();
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(empty, never()).write(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_lockHeldOnBothAttempts_reportsWaitingForMbsLock()
      throws Exception {
    stubEmptyStorage();
    doThrow(new BackupStorageAlreadyLockedException("Generation lock present"))
        .when(storage)
        .acquireLock();

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> generator.generateCertificates(CONFIG));

    assertEquals(BackupStorageAlreadyLockedException.class, thrown.getCause().getClass());
    verify(storage, times(2)).acquireLock();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.WAITING_FOR_MBS_LOCK);
  }

  @Test
  public void generateCertificates_storageThrowsException_propagatesWrappedError()
      throws Exception {
    doThrow(new BackupAccessFailedException("Failed to list")).when(storage).getSnapshot();

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> generator.generateCertificates(CONFIG));

    assertEquals(BackupAccessFailedException.class, thrown.getCause().getClass());
    verify(storage, times(1)).getSnapshot();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.S3_OPERATION_FAILED);
  }

  @Test
  public void generateCertificates_writeFails_reportsS3OperationFailed() throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = stubEmptyStorage();
    doThrow(new BackupAccessFailedException("S3 write failed")).when(empty).write(any());

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> generator.generateCertificates(CONFIG));

    assertEquals(BackupAccessFailedException.class, thrown.getCause().getClass());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.S3_OPERATION_FAILED);
  }

  @Test
  public void generateCertificates_unexpectedException_reportsGeneralFailure() throws Exception {
    stubEmptyStorage();
    when(selfSignedBundleBackupGenerator.generate(CERT_0))
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
            .setSelfSignedCertificates(Map.of(0, CERT_0, 1, CERT_1, 2, CERT_2))
            .setActiveSelfSignedCertificateIds(Set.of(0, 2))
            .setAcceptableSelfSignedCertificateIds(Set.of(0, 1, 2))
            .build();

    SelfSignedBundleBackupHandle.Empty empty1 = emptySelfSignedHandle(1);
    SelfSignedBundleBackupHandle.Empty empty2 = emptySelfSignedHandle(2);
    StorageSnapshot snapshot =
        snapshotOf(List.of(completeSelfSignedHandle(0), empty1, empty2), List.of());
    when(storage.getSnapshot()).thenReturn(snapshot);

    generator.generateCertificates(multiEpochConfig);

    InOrder inOrder = inOrder(storage, selfSignedBundleBackupGenerator, empty1, empty2);
    inOrder.verify(storage).getSnapshot();
    inOrder.verify(storage).acquireLock();
    inOrder.verify(storage).getSnapshot();
    inOrder.verify(selfSignedBundleBackupGenerator).generate(CERT_1);
    inOrder.verify(empty1).write(BACKUP_1);
    inOrder.verify(selfSignedBundleBackupGenerator).generate(CERT_2);
    inOrder.verify(empty2).write(BACKUP_2);
    inOrder.verify(storage).releaseLock();
    verify(selfSignedBundleBackupGenerator, never()).generate(CERT_0);
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void
      generateCertificates_oneOfMultipleEpochsAppearsUnderLock_generatesOnlyRemainingMissingEpoch()
          throws Exception {
    SelfSignedBundleBackupHandle.Empty empty0 = emptySelfSignedHandle(0);
    SelfSignedBundleBackupHandle.Empty empty1 = emptySelfSignedHandle(1);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(List.of(empty0, empty1), List.of()))
        .thenReturn(snapshotOf(List.of(completeSelfSignedHandle(0), empty1), List.of()))
        .thenReturn(
            snapshotOf(
                List.of(
                    completeSelfSignedHandle(0, BACKUP_0), completeSelfSignedHandle(1, BACKUP_1)),
                List.of()));

    generator.generateCertificates(TWO_EPOCH_WITH_CROSS_CERT_CONFIG);

    verify(storage, times(3)).getSnapshot();
    verify(storage).acquireLock();
    verify(empty0, never()).write(any());
    verify(selfSignedBundleBackupGenerator, never()).generate(CERT_0);
    verify(selfSignedBundleBackupGenerator).generate(CERT_1);
    verify(empty1).write(BACKUP_1);
    verify(storage).releaseLock();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  // This test also has full coverage for case when only cross signed certificates are generated
  @Test
  public void
      generateCertificates_missingSelfSignedAndCrossSigned_refreshesSnapshotAndGeneratesBoth()
          throws Exception {
    SelfSignedBundleBackupHandle.Complete complete0 = completeSelfSignedHandle(0, BACKUP_0);
    SelfSignedBundleBackupHandle.Empty empty1 = emptySelfSignedHandle(1);
    SelfSignedBundleBackupHandle.Complete complete1 = completeSelfSignedHandle(1, BACKUP_1);
    CrossSignedCertificateBackupHandle.Empty emptyCross01 =
        emptyCrossSignedHandle(CROSS_CERT_0_1.id());
    CrossSignedCertificateBackupHandle.Empty emptyCross10 =
        emptyCrossSignedHandle(CROSS_CERT_1_0.id());

    StorageSnapshot initialSnapshot = snapshotOf(List.of(complete0, empty1), List.of());
    StorageSnapshot refreshedSnapshot =
        snapshotOf(List.of(complete0, complete1), List.of(emptyCross01, emptyCross10));
    when(storage.getSnapshot())
        .thenReturn(initialSnapshot)
        .thenReturn(initialSnapshot)
        .thenReturn(refreshedSnapshot);

    generator.generateCertificates(TWO_EPOCH_WITH_CROSS_CERT_CONFIG);

    record CrossCertGenerationInputs(
        CrossSignedCertificateBackupHandle.Empty handle,
        CrossSignedCertificate cert,
        SelfSignedBundleBackup source,
        SelfSignedBundleBackup target,
        CrossSignedCertificateBackup backup) {}

    // Order between the two cross-signed generations is unspecified, so verify each separately.
    for (CrossCertGenerationInputs c :
        List.of(
            new CrossCertGenerationInputs(
                emptyCross01, CROSS_CERT_0_1, BACKUP_0, BACKUP_1, CROSS_BACKUP_0_1),
            new CrossCertGenerationInputs(
                emptyCross10, CROSS_CERT_1_0, BACKUP_1, BACKUP_0, CROSS_BACKUP_1_0))) {
      InOrder inOrder =
          inOrder(
              storage,
              selfSignedBundleBackupGenerator,
              crossSignedCertificateBackupGenerator,
              empty1,
              c.handle());
      inOrder.verify(storage).getSnapshot();
      inOrder.verify(storage).acquireLock();
      inOrder.verify(storage).getSnapshot();
      inOrder.verify(selfSignedBundleBackupGenerator).generate(CERT_1);
      inOrder.verify(empty1).write(BACKUP_1);
      inOrder.verify(storage).getSnapshot();
      inOrder
          .verify(crossSignedCertificateBackupGenerator)
          .generate(c.cert(), c.source(), c.target());
      inOrder.verify(c.handle()).write(c.backup());
      inOrder.verify(storage).releaseLock();
    }
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }
}
