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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.flogger.FluentLogger;
import com.google.mbs.domain.BackupAccessFailedException;
import com.google.mbs.domain.BackupStorage;
import com.google.mbs.domain.BackupStorageAlreadyLockedException;
import com.google.mbs.domain.BackupStorageException;
import com.google.mbs.domain.CertificateGenerator;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedBundleBackupHandle;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.StorageSnapshot;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

public class DefaultCertificateGenerator implements CertificateGenerator {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  @VisibleForTesting Duration retryBackoff = Duration.ofSeconds(10);

  private final BackupStorage storage;
  private final SelfSignedBundleBackupGenerator selfSignedBundleBackupGenerator;
  private final Metrics metrics;

  @Inject
  DefaultCertificateGenerator(
      BackupStorage storage,
      SelfSignedBundleBackupGenerator selfSignedBundleBackupGenerator,
      Metrics metrics) {
    this.storage = Objects.requireNonNull(storage);
    this.selfSignedBundleBackupGenerator = Objects.requireNonNull(selfSignedBundleBackupGenerator);
    this.metrics = Objects.requireNonNull(metrics);
  }

  @Override
  public void generateCertificates(CertificatesConfig config) {
    try {
      generateMissingSelfSignedBundleBackupsWithRetryOnTransientError(config);
      metrics.recordGenerationEvent(Metrics.GenerationEvent.SUCCESS);
    } catch (Exception failure) {
      metrics.recordGenerationEvent(mapFailureToEvent(failure));
      logger.atSevere().withCause(failure).log("Failed to generate certificate");
      if (failure instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      throw new RuntimeException("Failed to generate certificate", failure);
    }
  }

  private void generateMissingSelfSignedBundleBackupsWithRetryOnTransientError(
      CertificatesConfig config)
      throws InterruptedException,
          KmsException,
          BackupStorageAlreadyLockedException,
          BackupStorageException {
    try {
      generateMissingSelfSignedBundleBackups(config);
    } catch (BackupStorageAlreadyLockedException transientState) {
      logger.atWarning().withCause(transientState).log(
          "Transient backup state, retrying in %d ms", retryBackoff.toMillis());
      Thread.sleep(retryBackoff.toMillis());
      generateMissingSelfSignedBundleBackups(config);
    }
  }

  private void generateMissingSelfSignedBundleBackups(CertificatesConfig config)
      throws KmsException, BackupStorageAlreadyLockedException, BackupStorageException {
    if (findMissingSelfSignedBundleBackups(config, storage.getSnapshot()).isEmpty()) {
      return;
    }
    storage.acquireLock();
    List<SelfSignedBundleBackupHandle.Empty> missingSelfSignedBundleBackups =
        findMissingSelfSignedBundleBackups(config, storage.getSnapshot());

    // Intentionally no try/finally: a failure under the lock leaves the backup in an unknown state,
    // so the lock stays behind until an operator has investigated and removed it by hand.
    for (SelfSignedBundleBackupHandle.Empty empty : missingSelfSignedBundleBackups) {
      SelfSignedCertificate certConfig = config.selfSignedCertificates().get(empty.epoch());
      empty.write(selfSignedBundleBackupGenerator.generate(certConfig));
    }
    storage.releaseLock();
  }

  private static List<SelfSignedBundleBackupHandle.Empty> findMissingSelfSignedBundleBackups(
      CertificatesConfig config, StorageSnapshot snapshot) {
    return config.getSelfSignedCertificates().stream()
        .<SelfSignedBundleBackupHandle.Empty>mapMulti(
            (certConfig, consumer) -> {
              SelfSignedBundleBackupHandle handle =
                  snapshot.getSelfSignedBundleBackupHandle(certConfig.epochId());
              if (handle instanceof SelfSignedBundleBackupHandle.Empty empty) {
                consumer.accept(empty);
              } else if (!(handle instanceof SelfSignedBundleBackupHandle.Complete)) {
                logger.atWarning().log(
                    "Skipping certificate generation for epoch %d in state %s",
                    certConfig.epochId(), handle.getClass().getSimpleName());
              }
            })
        .toList();
  }

  private static Metrics.GenerationEvent mapFailureToEvent(Exception failure) {
    if (failure instanceof BackupStorageAlreadyLockedException) {
      return Metrics.GenerationEvent.WAITING_FOR_MBS_LOCK;
    } else if (failure instanceof BackupAccessFailedException) {
      return Metrics.GenerationEvent.S3_OPERATION_FAILED;
    } else if (failure instanceof KmsException) {
      return Metrics.GenerationEvent.KMS_OPERATION_FAILED;
    } else {
      return Metrics.GenerationEvent.GENERAL_FAILURE;
    }
  }
}
