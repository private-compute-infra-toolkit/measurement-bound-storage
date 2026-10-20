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

package com.google.mbs;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.flogger.FluentLogger;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.util.SecretBytes;
import com.google.mbs.domain.AttestationToken;
import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.BundleCorruptedException;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertHandle;
import com.google.mbs.domain.CrossSignedCertificate;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupIncompleteException;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupPartiallyWrittenException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KeyBackupStorageException;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.MeasurementBoundBundle;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.StorageSnapshot;
import com.google.mbs.domain.TrustPackage;
import com.google.mbs.domain.TrustPackageProvider;
import com.google.mbs.domain.TrustPackageReloader;
import com.google.mbs.qualifier.KmsKeyArn;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KmsMeasurementBoundCertificateProvider
    implements TrustPackageProvider, TrustPackageReloader {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final String CERTIFICATE_TYPE = "X.509";

  @VisibleForTesting Duration retryBackoff = Duration.ofSeconds(10);

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    try {
      AeadConfig.register();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Tink AEAD registration failed", e);
    }
  }

  private final KmsClientInterface kmsClient;
  private final KeyBackupStorage storage;
  private final String kmsKeyArn;
  private final Metrics metrics;

  private record LoadedBundle(KeyBackup backup, MeasurementBoundBundle bundle) {
    private LoadedBundle {
      Objects.requireNonNull(backup);
      Objects.requireNonNull(bundle);
    }
  }

  private record ActiveTrustState(
      Map<Integer, LoadedBundle> bundlesByEpoch, List<X509Certificate> crossSignedCertificates) {
    private ActiveTrustState {
      bundlesByEpoch = Map.copyOf(bundlesByEpoch);
      crossSignedCertificates = List.copyOf(crossSignedCertificates);
    }
  }

  private final AtomicReference<ActiveTrustState> activeTrustState = new AtomicReference<>();

  @Inject
  KmsMeasurementBoundCertificateProvider(
      KmsClientInterface kmsClient,
      KeyBackupStorage storage,
      @KmsKeyArn String kmsKeyArn,
      Metrics metrics) {
    this.kmsClient = Objects.requireNonNull(kmsClient);
    this.storage = Objects.requireNonNull(storage);
    this.kmsKeyArn = Objects.requireNonNull(kmsKeyArn);
    this.metrics = Objects.requireNonNull(metrics);
  }

  @Override
  public TrustPackage getActiveTrustPackage() {
    ActiveTrustState state = activeTrustState.get();
    if (state == null) {
      throw new IllegalStateException("Trust package has not been initialized yet");
    }
    List<MeasurementBoundBundle> bundles =
        state.bundlesByEpoch().values().stream().map(LoadedBundle::bundle).toList();
    return new TrustPackage(bundles, state.crossSignedCertificates());
  }

  @Override
  public synchronized void reload(CertificatesConfig config) {
    try {
      reloadTrustPackageWithRetryOnTransientError(config);
      metrics.recordLoadEvent(Metrics.LoadEvent.SUCCESS);
    } catch (Exception failure) {
      metrics.recordLoadEvent(mapFailureToEvent(failure));
      logger.atSevere().withCause(failure).log(
          "Failed to reload certificate, previously loaded one still in use");
      if (failure instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      throw new RuntimeException("Failed to reload certificate", failure);
    }
  }

  private void reloadTrustPackageWithRetryOnTransientError(CertificatesConfig config)
      throws BundleCorruptedException,
          InterruptedException,
          KmsException,
          KeyBackupStorageException {
    try {
      loadActiveTrustState(config);
    } catch (KeyBackupPartiallyWrittenException transientState) {
      logger.atWarning().withCause(transientState).log(
          "Transient backup state, retrying in %d ms", retryBackoff.toMillis());
      Thread.sleep(retryBackoff.toMillis());
      loadActiveTrustState(config);
    }
  }

  private void loadActiveTrustState(CertificatesConfig config)
      throws BundleCorruptedException, KmsException, KeyBackupStorageException {
    StorageSnapshot snapshot = storage.getSnapshot();
    Map<Integer, LoadedBundle> nextBundles = loadActiveBundles(snapshot, config);
    List<X509Certificate> nextCrossSigned = loadActiveCrossSignedCertificates(snapshot, config);
    activeTrustState.set(new ActiveTrustState(nextBundles, nextCrossSigned));
  }

  private Map<Integer, LoadedBundle> loadActiveBundles(
      StorageSnapshot snapshot, CertificatesConfig config)
      throws BundleCorruptedException, KmsException, KeyBackupStorageException {
    ActiveTrustState previousState = activeTrustState.get();
    Map<Integer, LoadedBundle> previouslyLoaded =
        previousState != null ? previousState.bundlesByEpoch() : Map.of();
    Map<Integer, LoadedBundle> nextLoaded = new HashMap<>();

    for (SelfSignedCertificate certConfig : config.activeSelfSignedCertificates()) {
      int epochId = certConfig.epochId();
      KeyBackup backup =
          snapshot.getBundleHandle(epochId).expect(BackupHandle.Complete.class).read();
      nextLoaded.put(epochId, useLoadedOrLoadFromBackup(previouslyLoaded.get(epochId), backup));
    }
    return nextLoaded;
  }

  private List<X509Certificate> loadActiveCrossSignedCertificates(
      StorageSnapshot snapshot, CertificatesConfig config)
      throws BundleCorruptedException, KeyBackupStorageException {
    List<X509Certificate> crossSignedCertificates = new ArrayList<>();
    for (CrossSignedCertificate crossCertConfig : config.activeCrossSignedCertificates()) {
      CrossSignedCertificateBackup backup =
          snapshot
              .getCrossSignedCertHandle(crossCertConfig.id())
              .expect(CrossSignedCertHandle.Complete.class)
              .read();
      // Parsing X.509 is local (no KMS call), so no need to cache decoded certs across reloads.
      crossSignedCertificates.add(parseCertificate(backup.certBytes()));
    }
    return crossSignedCertificates;
  }

  private LoadedBundle useLoadedOrLoadFromBackup(LoadedBundle previous, KeyBackup backup)
      throws KmsException, BundleCorruptedException {
    if (previous != null && previous.backup().equals(backup)) {
      return previous;
    }
    return new LoadedBundle(backup, toMeasurementBoundBundle(backup));
  }

  private static Metrics.LoadEvent mapFailureToEvent(Exception failure) {
    if (failure instanceof KeyBackupNotFoundException) {
      return Metrics.LoadEvent.KEY_BACKUP_NOT_FOUND;
    } else if (failure instanceof KeyBackupAccessFailedException) {
      return Metrics.LoadEvent.S3_OPERATION_FAILED;
    } else if (failure instanceof KmsException) {
      return Metrics.LoadEvent.KMS_OPERATION_FAILED;
    } else if (failure instanceof BundleCorruptedException
        || failure instanceof KeyBackupIncompleteException
        || failure instanceof KeyBackupPartiallyWrittenException) {
      return Metrics.LoadEvent.STORED_BACKUP_CORRUPTED;
    } else {
      return Metrics.LoadEvent.GENERAL_FAILURE;
    }
  }

  private MeasurementBoundBundle toMeasurementBoundBundle(KeyBackup keyBackup)
      throws KmsException, BundleCorruptedException {
    byte[] dataKey = kmsClient.decrypt(keyBackup.kmsEncryptedDataKey(), kmsKeyArn);

    X509Certificate certificate = parseCertificate(keyBackup.certBytes());
    PrivateKey privateKey;
    AttestationToken token;
    try {
      token = AttestationToken.fromBytes(keyBackup.attestationDocBytes());
      byte[] decryptedPrivateKeyBytes = decrypt(keyBackup.aeadEncryptedPrivateKey(), dataKey);
      privateKey =
          parsePrivateKey(decryptedPrivateKeyBytes, certificate.getPublicKey().getAlgorithm());
    } catch (GeneralSecurityException e) {
      throw new BundleCorruptedException("Key material could not be decoded", e);
    }

    if (!isKeyMatchingCertificate(certificate, privateKey)) {
      throw new BundleCorruptedException("Private key does not match certificate");
    }
    return new MeasurementBoundBundle(certificate, privateKey, token);
  }

  private X509Certificate parseCertificate(byte[] certBytes) throws BundleCorruptedException {
    try {
      CertificateFactory x509CertFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
      return (X509Certificate)
          x509CertFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    } catch (GeneralSecurityException e) {
      throw new BundleCorruptedException("Certificate could not be decoded", e);
    }
  }

  private boolean isKeyMatchingCertificate(X509Certificate certificate, PrivateKey privateKey) {
    byte[] probe = "mbs-key-certificate-consistency-check".getBytes(StandardCharsets.UTF_8);
    try {
      Signature signer = Signature.getInstance(certificate.getSigAlgName());
      signer.initSign(privateKey);
      signer.update(probe);
      byte[] signature = signer.sign();

      Signature verifier = Signature.getInstance(certificate.getSigAlgName());
      verifier.initVerify(certificate.getPublicKey());
      verifier.update(probe);
      return verifier.verify(signature);
    } catch (GeneralSecurityException e) {
      logger.atSevere().withCause(e).log("Key and certificate consistency check failed");
      return false;
    }
  }

  private PrivateKey parsePrivateKey(byte[] privateKeyBytes, String algorithm)
      throws GeneralSecurityException {
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    return keyFactory.generatePrivate(privateKeySpec);
  }

  private byte[] decrypt(byte[] ciphertext, byte[] key) throws GeneralSecurityException {
    if (key.length != 32) {
      throw new GeneralSecurityException("Invalid key size. Expected 32 bytes for AES-256-GCM.");
    }

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
