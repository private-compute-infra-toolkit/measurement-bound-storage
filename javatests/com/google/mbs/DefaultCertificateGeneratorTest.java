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

import com.google.mbs.domain.BackupAccessFailedException;
import com.google.mbs.domain.BackupStorage;
import com.google.mbs.domain.BackupStorageAlreadyLockedException;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertificateBackupHandle;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedBundleBackup;
import com.google.mbs.domain.SelfSignedBundleBackupHandle;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.StorageSnapshot;
import com.google.mbs.domain.ValidityPeriod;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
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

  private static final CertificatesConfig CONFIG =
      CertificatesConfig.builder()
          .setSelfSignedCertificates(Map.of(0, CERT_0))
          .setActiveSelfSignedCertificateIds(Set.of(0))
          .setAcceptableSelfSignedCertificateIds(Set.of(0))
          .build();
  private static final CertificatesConfig TWO_EPOCH_CONFIG =
      CertificatesConfig.builder()
          .setSelfSignedCertificates(Map.of(0, CERT_0, 1, CERT_1))
          .setActiveSelfSignedCertificateIds(Set.of(0, 1))
          .setAcceptableSelfSignedCertificateIds(Set.of(0, 1))
          .build();

  @Mock private BackupStorage storage;
  @Mock private SelfSignedBundleBackupGenerator selfSignedBundleBackupGenerator;
  @Mock private Metrics mockMetrics;

  private DefaultCertificateGenerator generator;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    when(selfSignedBundleBackupGenerator.generate(CERT_0)).thenReturn(BACKUP_0);
    when(selfSignedBundleBackupGenerator.generate(CERT_1)).thenReturn(BACKUP_1);
    when(selfSignedBundleBackupGenerator.generate(CERT_2)).thenReturn(BACKUP_2);

    generator =
        new DefaultCertificateGenerator(storage, selfSignedBundleBackupGenerator, mockMetrics);
    generator.retryBackoff = Duration.ZERO;
  }

  private static SelfSignedBundleBackup dummyBackup(String label) {
    return new SelfSignedBundleBackup(
        ("cert-" + label).getBytes(StandardCharsets.UTF_8),
        ("key-" + label).getBytes(StandardCharsets.UTF_8),
        ("priv-" + label).getBytes(StandardCharsets.UTF_8),
        ("att-" + label).getBytes(StandardCharsets.UTF_8));
  }

  private static SelfSignedBundleBackupHandle completeHandle() {
    return mock(SelfSignedBundleBackupHandle.Complete.class);
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
      return selfSignedBundleBackupHandles.getOrDefault(epoch, emptyHandle(epoch));
    }

    @Override
    public CrossSignedCertificateBackupHandle getCrossSignedCertificateBackupHandle(
        CrossSignedCertificateId id) {
      return crossSignedCertificateBackupHandles.getOrDefault(
          id, mock(CrossSignedCertificateBackupHandle.Empty.class));
    }
  }

  private static StorageSnapshot snapshotOf(SelfSignedBundleBackupHandle epoch0Handle) {
    return new FakeSnapshot(Map.of(0, epoch0Handle));
  }

  private static SelfSignedBundleBackupHandle.Empty emptyHandle(int epoch) {
    SelfSignedBundleBackupHandle.Empty empty = mock(SelfSignedBundleBackupHandle.Empty.class);
    when(empty.epoch()).thenReturn(epoch);
    return empty;
  }

  private SelfSignedBundleBackupHandle.Empty stubEmptyStorage() throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = emptyHandle(0);
    when(storage.getSnapshot()).thenReturn(snapshotOf(empty));
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
    when(storage.getSnapshot()).thenReturn(snapshotOf(completeHandle()));

    generator.generateCertificates(CONFIG);

    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_incompleteBackupExists_skipsWithoutLocking() throws Exception {
    when(storage.getSnapshot())
        .thenReturn(
            snapshotOf(
                new SelfSignedBundleBackupHandle.Incomplete(
                    0, List.of("public/0/root_certificate.pem"))));

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
                new SelfSignedBundleBackupHandle.PartiallyWritten(
                    0, List.of("public/0/root_certificate.pem"))));

    generator.generateCertificates(CONFIG);

    verify(storage, times(1)).getSnapshot();
    verify(storage, never()).acquireLock();
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_backupAppearsUnderLock_releasesLockWithoutGenerating()
      throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = mock(SelfSignedBundleBackupHandle.Empty.class);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(empty))
        .thenReturn(snapshotOf(completeHandle()));

    generator.generateCertificates(CONFIG);

    verify(storage, times(2)).getSnapshot();
    verify(storage).acquireLock();
    verify(storage).releaseLock();
    verify(empty, never()).write(any());
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_partiallyWrittenUnderLock_releasesLockWithoutGenerating()
      throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = mock(SelfSignedBundleBackupHandle.Empty.class);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(empty))
        .thenReturn(
            snapshotOf(
                new SelfSignedBundleBackupHandle.PartiallyWritten(
                    0, List.of("public/0/root_certificate.pem"))));

    generator.generateCertificates(CONFIG);

    verify(storage, times(2)).getSnapshot();
    verify(storage).acquireLock();
    verify(storage).releaseLock();
    verify(empty, never()).write(any());
    verify(selfSignedBundleBackupGenerator, never()).generate(any());
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }

  @Test
  public void generateCertificates_generationFails_doesNotReleaseLock() throws Exception {
    SelfSignedBundleBackupHandle.Empty empty0 = emptyHandle(0);
    SelfSignedBundleBackupHandle.Empty empty1 = emptyHandle(1);
    when(storage.getSnapshot()).thenReturn(new FakeSnapshot(Map.of(0, empty0, 1, empty1)));
    when(selfSignedBundleBackupGenerator.generate(CERT_1))
        .thenThrow(new KmsException("KMS error on epoch 1"));

    RuntimeException thrown =
        assertThrows(
            RuntimeException.class, () -> generator.generateCertificates(TWO_EPOCH_CONFIG));

    assertEquals(KmsException.class, thrown.getCause().getClass());
    verify(empty0).write(BACKUP_0);
    verify(empty1, never()).write(any());
    verify(storage).acquireLock();
    verify(storage, never()).releaseLock();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void generateCertificates_alreadyLocked_waitsAndSkipsWhenWinnerPublishes()
      throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = mock(SelfSignedBundleBackupHandle.Empty.class);
    when(storage.getSnapshot())
        .thenReturn(snapshotOf(empty))
        .thenReturn(snapshotOf(completeHandle()));
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

    SelfSignedBundleBackupHandle.Empty empty1 = emptyHandle(1);
    SelfSignedBundleBackupHandle.Empty empty2 = emptyHandle(2);
    StorageSnapshot snapshot =
        new FakeSnapshot(
            Map.of(
                0, completeHandle(),
                1, empty1,
                2, empty2));
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
    SelfSignedBundleBackupHandle.Empty empty0 = emptyHandle(0);
    SelfSignedBundleBackupHandle.Empty empty1 = emptyHandle(1);
    when(storage.getSnapshot())
        .thenReturn(new FakeSnapshot(Map.of(0, empty0, 1, empty1)))
        .thenReturn(new FakeSnapshot(Map.of(0, completeHandle(), 1, empty1)));

    generator.generateCertificates(TWO_EPOCH_CONFIG);

    verify(storage, times(2)).getSnapshot();
    verify(storage).acquireLock();
    verify(empty0, never()).write(any());
    verify(selfSignedBundleBackupGenerator, never()).generate(CERT_0);
    verify(selfSignedBundleBackupGenerator).generate(CERT_1);
    verify(empty1).write(BACKUP_1);
    verify(storage).releaseLock();
    verify(mockMetrics).recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
  }
}
