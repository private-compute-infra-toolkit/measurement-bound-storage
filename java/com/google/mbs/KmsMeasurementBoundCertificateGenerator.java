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
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.util.SecretBytes;
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.AttestationToken;
import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KeyBackupStorageException;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.KmsGeneratedKey;
import com.google.mbs.domain.MeasurementBoundCertificateGenerator;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.StorageAlreadyLockedException;
import com.google.mbs.domain.StorageSnapshot;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.KmsKeyArn;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class KmsMeasurementBoundCertificateGenerator
    implements MeasurementBoundCertificateGenerator {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  @VisibleForTesting Duration retryBackoff = Duration.ofSeconds(10);

  static {
    try {
      AeadConfig.register();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Tink AEAD registration failed", e);
    }
  }

  private final KmsClientInterface kmsClient;
  private final KeyBackupStorage storage;
  private final String kmsKeyArn;
  private final AttestationCollector attestationCollector;
  private final byte[] userDataBoundToAttestation;
  private final MbsCertificateFactory certificateFactory;
  private final Metrics metrics;

  @Inject
  KmsMeasurementBoundCertificateGenerator(
      KmsClientInterface kmsClient,
      KeyBackupStorage storage,
      @KmsKeyArn String kmsKeyArn,
      @AttestationUserData byte[] userDataBoundToAttestation,
      AttestationCollector attestationCollector,
      MbsCertificateFactory certificateFactory,
      Metrics metrics) {
    this.kmsClient = Objects.requireNonNull(kmsClient);
    this.storage = Objects.requireNonNull(storage);
    this.kmsKeyArn = Objects.requireNonNull(kmsKeyArn);
    this.userDataBoundToAttestation = Objects.requireNonNull(userDataBoundToAttestation);
    this.attestationCollector = Objects.requireNonNull(attestationCollector);
    this.certificateFactory = Objects.requireNonNull(certificateFactory);
    this.metrics = Objects.requireNonNull(metrics);
  }

  @Override
  public void generateCertificates(CertificatesConfig config) {
    try {
      generateCertificatesWithRetryOnTransientError(config);
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

  private void generateCertificatesWithRetryOnTransientError(CertificatesConfig config)
      throws IOException,
          GeneralSecurityException,
          InterruptedException,
          KmsException,
          StorageAlreadyLockedException,
          KeyBackupStorageException {
    try {
      generateMissingKeyBackups(config);
    } catch (StorageAlreadyLockedException transientState) {
      logger.atWarning().withCause(transientState).log(
          "Transient backup state, retrying in %d ms", retryBackoff.toMillis());
      Thread.sleep(retryBackoff.toMillis());
      generateMissingKeyBackups(config);
    }
  }

  private void generateMissingKeyBackups(CertificatesConfig config)
      throws IOException,
          GeneralSecurityException,
          KmsException,
          StorageAlreadyLockedException,
          KeyBackupStorageException {
    if (findMissingCertificates(config, storage.getSnapshot()).isEmpty()) {
      return;
    }
    storage.acquireLock();
    List<BackupHandle.Empty> missingCerts = findMissingCertificates(config, storage.getSnapshot());

    // Intentionally no try/finally: a failure under the lock leaves the backup in an unknown state,
    // so the lock stays behind until an operator has investigated and removed it by hand.
    for (BackupHandle.Empty empty : missingCerts) {
      SelfSignedCertificate certConfig = config.selfSignedCertificates().get(empty.epoch());
      empty.write(generateKeyBackup(certConfig));
    }
    storage.releaseLock();
  }

  private static List<BackupHandle.Empty> findMissingCertificates(
      CertificatesConfig config, StorageSnapshot snapshot) {
    return config.getSelfSignedCertificates().stream()
        .<BackupHandle.Empty>mapMulti(
            (certConfig, consumer) -> {
              BackupHandle handle = snapshot.getBundleHandle(certConfig.epochId());
              if (handle instanceof BackupHandle.Empty empty) {
                consumer.accept(empty);
              } else if (!(handle instanceof BackupHandle.Complete)) {
                logger.atWarning().log(
                    "Skipping certificate generation for epoch %d in state %s",
                    certConfig.epochId(), handle.getClass().getSimpleName());
              }
            })
        .toList();
  }

  private static Metrics.GenerationEvent mapFailureToEvent(Exception failure) {
    if (failure instanceof StorageAlreadyLockedException) {
      return Metrics.GenerationEvent.WAITING_FOR_MBS_LOCK;
    } else if (failure instanceof KeyBackupAccessFailedException) {
      return Metrics.GenerationEvent.S3_OPERATION_FAILED;
    } else if (failure instanceof KmsException) {
      return Metrics.GenerationEvent.KMS_OPERATION_FAILED;
    } else {
      return Metrics.GenerationEvent.GENERAL_FAILURE;
    }
  }

  private KeyBackup generateKeyBackup(SelfSignedCertificate certConfig)
      throws IOException, GeneralSecurityException, KmsException {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        certificateFactory.generate(certConfig);

    X509Certificate certificate = certAndKey.certificate();
    PrivateKey privateKey = certAndKey.privateKey();

    AttestationToken token =
        attestationCollector.collectBoundToPubkey(
            certificate.getPublicKey(), userDataBoundToAttestation);

    KmsGeneratedKey dataKey = kmsClient.generateDataKey(kmsKeyArn);
    byte[] aeadEncryptedPrivateKey = encrypt(privateKey.getEncoded(), dataKey.plaintext());

    return new KeyBackup(
        toPemBytes(certificate), dataKey.ciphertext(), aeadEncryptedPrivateKey, token.getBytes());
  }

  private byte[] encrypt(byte[] plaintext, byte[] key) throws GeneralSecurityException {
    if (key.length != 32) {
      throw new GeneralSecurityException("Invalid key size. Expected 32 bytes for AES-256-GCM.");
    }

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

  static byte[] toPemBytes(X509Certificate certificate)
      throws IOException, GeneralSecurityException {
    StringWriter stringWriter = new StringWriter();
    try (PemWriter pemWriter = new PemWriter(stringWriter)) {
      pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
    }
    return stringWriter.toString().getBytes(StandardCharsets.UTF_8);
  }
}
