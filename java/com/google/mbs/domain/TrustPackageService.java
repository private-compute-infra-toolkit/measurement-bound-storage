/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.mbs.domain;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.flogger.FluentLogger;
import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public class TrustPackageService implements TrustPackageProvider, TrustPackageReloader {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  @VisibleForTesting Duration retryBackoff = Duration.ofSeconds(10);

  private final SelfSignedBundleBackupSealer backupSealer;
  private final CertificateCodec certificateCodec;
  private final BackupStorage storage;
  private final Metrics metrics;

  private record LoadedSelfSignedBundle(SelfSignedBundleBackup backup, SelfSignedBundle bundle) {
    private LoadedSelfSignedBundle {
      Objects.requireNonNull(backup);
      Objects.requireNonNull(bundle);
    }
  }

  private record ActiveTrustState(
      Map<Integer, LoadedSelfSignedBundle> selfSignedBundlesByEpoch,
      Map<CrossSignedCertificateId, X509Certificate> crossSignedCertificatesById) {
    private ActiveTrustState {
      selfSignedBundlesByEpoch = Collections.unmodifiableMap(selfSignedBundlesByEpoch);
      crossSignedCertificatesById = Collections.unmodifiableMap(crossSignedCertificatesById);
    }
  }

  private final AtomicReference<ActiveTrustState> activeTrustState = new AtomicReference<>();

  @Inject
  TrustPackageService(
      SelfSignedBundleBackupSealer backupSealer,
      CertificateCodec certificateCodec,
      BackupStorage storage,
      Metrics metrics) {
    this.backupSealer = Objects.requireNonNull(backupSealer);
    this.certificateCodec = Objects.requireNonNull(certificateCodec);
    this.storage = Objects.requireNonNull(storage);
    this.metrics = Objects.requireNonNull(metrics);
  }

  @Override
  public TrustPackage getActiveTrustPackage() {
    ActiveTrustState state = activeTrustState.get();
    if (state == null) {
      throw new IllegalStateException("Trust package has not been initialized yet");
    }
    List<SelfSignedBundle> selfSignedBundles =
        state.selfSignedBundlesByEpoch().values().stream()
            .map(LoadedSelfSignedBundle::bundle)
            .toList();
    List<X509Certificate> crossSignedCertificates =
        List.copyOf(state.crossSignedCertificatesById().values());
    return new TrustPackage(selfSignedBundles, crossSignedCertificates);
  }

  @Override
  public synchronized void reload(CertificatesConfig config) {
    try {
      reloadTrustPackageWithRetryOnTransientError(config);
      recordActiveCertificatesMetrics();
      metrics.recordLoadEvent(Metrics.LoadEvent.SUCCESS);
    } catch (Exception failure) {
      metrics.recordLoadEvent(mapFailureToEvent(failure));
      logger.atSevere().withCause(failure).log(
          "Failed to reload trust package, previously loaded one still in use");
      if (failure instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      throw new RuntimeException("Failed to reload trust package", failure);
    }
  }

  private void recordActiveCertificatesMetrics() {
    ActiveTrustState state = activeTrustState.get();
    metrics.recordActiveSelfSignedCertificates(state.selfSignedBundlesByEpoch().keySet());
    metrics.recordActiveCrossSignedCertificates(state.crossSignedCertificatesById().keySet());
  }

  private void reloadTrustPackageWithRetryOnTransientError(CertificatesConfig config)
      throws BackupCorruptedException, InterruptedException, KmsException, BackupStorageException {
    try {
      loadActiveTrustState(config);
    } catch (BackupPartiallyWrittenException transientState) {
      logger.atWarning().withCause(transientState).log(
          "Transient backup state, retrying in %d ms", retryBackoff.toMillis());
      Thread.sleep(retryBackoff.toMillis());
      loadActiveTrustState(config);
    }
  }

  private void loadActiveTrustState(CertificatesConfig config)
      throws BackupCorruptedException, KmsException, BackupStorageException {
    StorageSnapshot snapshot = storage.getSnapshot();
    Map<Integer, LoadedSelfSignedBundle> nextBundles =
        loadActiveSelfSignedBundles(snapshot, config);
    Map<CrossSignedCertificateId, X509Certificate> nextCrossSigned =
        loadActiveCrossSignedCertificates(snapshot, config);
    activeTrustState.set(new ActiveTrustState(nextBundles, nextCrossSigned));
  }

  private Map<Integer, LoadedSelfSignedBundle> loadActiveSelfSignedBundles(
      StorageSnapshot snapshot, CertificatesConfig config)
      throws BackupCorruptedException, KmsException, BackupStorageException {
    ActiveTrustState previousState = activeTrustState.get();
    Map<Integer, LoadedSelfSignedBundle> previouslyLoaded =
        previousState != null ? previousState.selfSignedBundlesByEpoch() : Map.of();
    Map<Integer, LoadedSelfSignedBundle> nextLoaded = new LinkedHashMap<>();

    for (SelfSignedCertificate certConfig : config.activeSelfSignedCertificates()) {
      int epochId = certConfig.epochId();
      SelfSignedBundleBackup backup = readSelfSignedBundleBackup(snapshot, epochId);
      nextLoaded.put(
          epochId, useLoadedOrLoadSelfSignedBundle(previouslyLoaded.get(epochId), backup));
    }
    return nextLoaded;
  }

  private Map<CrossSignedCertificateId, X509Certificate> loadActiveCrossSignedCertificates(
      StorageSnapshot snapshot, CertificatesConfig config)
      throws BackupCorruptedException, KmsException, BackupStorageException {
    Map<CrossSignedCertificateId, X509Certificate> crossSignedCertificates = new LinkedHashMap<>();
    for (CrossSignedCertificate crossCertConfig : config.activeCrossSignedCertificates()) {
      crossSignedCertificates.put(
          crossCertConfig.id(), loadCrossSignedCertificate(snapshot, crossCertConfig));
    }
    return crossSignedCertificates;
  }

  private X509Certificate loadCrossSignedCertificate(
      StorageSnapshot snapshot, CrossSignedCertificate crossCertConfig)
      throws BackupCorruptedException, KmsException, BackupStorageException {
    CrossSignedCertificateBackup backup =
        snapshot
            .getCrossSignedCertificateBackupHandle(crossCertConfig.id())
            .expect(CrossSignedCertificateBackupHandle.Complete.class)
            .read();
    X509Certificate crossCert;
    try {
      crossCert = certificateCodec.toCertificate(backup.certBytes());
    } catch (IllegalArgumentException e) {
      throw new BackupCorruptedException("Certificate could not be decoded", e);
    }
    SelfSignedBundle signer =
        backupSealer.unseal(
            readSelfSignedBundleBackup(snapshot, crossCertConfig.privateKeyEpochId()));
    SelfSignedBundle subject =
        backupSealer.unseal(
            readSelfSignedBundleBackup(snapshot, crossCertConfig.publicKeyEpochId()));
    verifyCrossSignedCertificate(crossCert, signer.certificate(), subject.certificate());
    return crossCert;
  }

  private static void verifyCrossSignedCertificate(
      X509Certificate crossCert, X509Certificate signerCert, X509Certificate subjectCert)
      throws BackupCorruptedException {
    if (!crossCert.getPublicKey().equals(subjectCert.getPublicKey())) {
      throw new BackupCorruptedException(
          "Cross-signed certificate public key does not match subject certificate");
    }
    try {
      crossCert.verify(signerCert.getPublicKey());
    } catch (GeneralSecurityException e) {
      throw new BackupCorruptedException(
          "Cross-signed certificate signature verification failed", e);
    }
  }

  private static SelfSignedBundleBackup readSelfSignedBundleBackup(
      StorageSnapshot snapshot, int epochId) throws BackupStorageException {
    return snapshot
        .getSelfSignedBundleBackupHandle(epochId)
        .expect(SelfSignedBundleBackupHandle.Complete.class)
        .read();
  }

  private LoadedSelfSignedBundle useLoadedOrLoadSelfSignedBundle(
      LoadedSelfSignedBundle previous, SelfSignedBundleBackup backup)
      throws KmsException, BackupCorruptedException {
    if (previous != null && previous.backup().equals(backup)) {
      return previous;
    }
    return new LoadedSelfSignedBundle(backup, backupSealer.unseal(backup));
  }

  private static Metrics.LoadEvent mapFailureToEvent(Exception failure) {
    if (failure instanceof BackupNotFoundException) {
      return Metrics.LoadEvent.BACKUP_NOT_FOUND;
    } else if (failure instanceof BackupAccessFailedException) {
      return Metrics.LoadEvent.S3_OPERATION_FAILED;
    } else if (failure instanceof KmsException) {
      return Metrics.LoadEvent.KMS_OPERATION_FAILED;
    } else if (failure instanceof BackupCorruptedException
        || failure instanceof BackupIncompleteException
        || failure instanceof BackupPartiallyWrittenException) {
      return Metrics.LoadEvent.STORED_BACKUP_CORRUPTED;
    } else {
      return Metrics.LoadEvent.GENERAL_FAILURE;
    }
  }
}
