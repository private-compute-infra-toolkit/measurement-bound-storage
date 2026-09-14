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

import static com.google.mbs.domain.Metrics.ReloadStatus.FAILURE;
import static com.google.mbs.domain.Metrics.ReloadStatus.SUCCESS;

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
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KeyBackupStorageException;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.KmsGeneratedKey;
import com.google.mbs.domain.MeasurementBoundCertificate;
import com.google.mbs.domain.MeasurementBoundCertificateProvider;
import com.google.mbs.domain.MeasurementBoundCertificateReloader;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.StorageAlreadyLockedException;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.KmsKeyArn;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class KmsMeasurementBoundCertificateProvider
    implements MeasurementBoundCertificateProvider, MeasurementBoundCertificateReloader {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final String CERTIFICATE_TYPE = "X.509";
  @VisibleForTesting Duration initialRetryBackoff = Duration.ofMillis(500);
  @VisibleForTesting Duration maxRetryBackoff = Duration.ofSeconds(5);
  @VisibleForTesting int maxLoadRetries = 0;

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
  private final AttestationCollector attestationCollector;
  private final byte[] userDataBoundToAttestation;
  private final MbsCertificateFactory certificateFactory;
  private final Metrics metrics;

  private final AtomicReference<MeasurementBoundCertificate> currentCertificate =
      new AtomicReference<>();

  @Inject
  KmsMeasurementBoundCertificateProvider(
      KmsClientInterface kmsClient,
      KeyBackupStorage storage,
      @KmsKeyArn String kmsKeyArn,
      @AttestationUserData byte[] userDataBoundToAttestation,
      AttestationCollector attestationCollector,
      MbsCertificateFactory certificateFactory,
      Metrics metrics) {
    this.kmsClient = kmsClient;
    this.storage = storage;
    this.kmsKeyArn = kmsKeyArn;
    this.userDataBoundToAttestation = userDataBoundToAttestation;
    this.attestationCollector = attestationCollector;
    this.certificateFactory = certificateFactory;
    this.metrics = metrics;
  }

  @Override
  public MeasurementBoundCertificate getCertificate() {
    MeasurementBoundCertificate cert = currentCertificate.get();
    if (cert == null) {
      throw new IllegalStateException("Measurement-bound certificate has not been initialized yet");
    }
    return cert;
  }

  @Override
  public synchronized void reloadCertificate() {
    try {
      MeasurementBoundCertificate reloaded = executeLoadOrGenerateCertificate();
      currentCertificate.set(reloaded);
      metrics.setReloadStatus(SUCCESS);
    } catch (Exception e) {
      metrics.setReloadStatus(FAILURE);
      logger.atSevere().withCause(e).log(
          "Failed to reload certificate from storage; active certificate remains unchanged");
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      if (e instanceof RuntimeException re) {
        throw re;
      }
      throw new RuntimeException("Failed to reload certificate", e);
    }
  }

  private MeasurementBoundCertificate executeLoadOrGenerateCertificate()
      throws IOException, GeneralSecurityException, InterruptedException, KmsException {
    Duration backoff = initialRetryBackoff;
    for (int attempt = 1; ; attempt++) {
      Optional<MeasurementBoundCertificate> cert = tryLoadExistingCertificate();
      if (cert.isPresent()) {
        return cert.get();
      }

      Optional<MeasurementBoundCertificate> lockedCert = tryAcquireLockAndLoadOrGenerate();
      if (lockedCert.isPresent()) {
        return lockedCert.get();
      }

      handleLockContention(attempt);
      checkMaxRetries(attempt);

      Thread.sleep(backoff.toMillis());
      backoff = Duration.ofMillis(Math.min(backoff.toMillis() * 2, maxRetryBackoff.toMillis()));
    }
  }

  private Optional<MeasurementBoundCertificate> tryLoadExistingCertificate()
      throws GeneralSecurityException, KmsException, KeyBackupStorageException {
    try {
      return Optional.of(loadCertificate());
    } catch (KeyBackupNotFoundException ignored) {
      return Optional.empty();
    }
  }

  private Optional<MeasurementBoundCertificate> tryAcquireLockAndLoadOrGenerate()
      throws IOException, GeneralSecurityException, KmsException {
    try {
      storage.acquireLock();
      MeasurementBoundCertificate mbc;
      try {
        mbc = loadCertificate();
      } catch (KeyBackupNotFoundException ignored) {
        mbc = generateAndStoreCertificate();
      }
      storage.releaseLock();
      return Optional.of(mbc);
    } catch (StorageAlreadyLockedException e) {
      return Optional.empty();
    }
  }

  private void checkMaxRetries(int attempt) {
    if (maxLoadRetries > 0 && attempt >= maxLoadRetries) {
      logger.atSevere().log(
          "Max retries (%d) exceeded while waiting for root certificate or lock."
              + " Manual resolution / lock removal may be required.",
          maxLoadRetries);
      throw new IllegalStateException(
          "Max retries exceeded while waiting for root certificate or lock. Manual lock"
              + " resolution may be required.");
    }
  }

  private void handleLockContention(int attempt) {
    logger.atInfo().log(
        "Root certificate generation lock is currently held (attempt %d). Waiting...", attempt);
    metrics.recordEvent(Metrics.MbsEvent.WAITING_FOR_MBS_LOCK);
  }

  private MeasurementBoundCertificate loadCertificate()
      throws GeneralSecurityException, KmsException, KeyBackupNotFoundException {
    byte[] certBytes = storage.getCertBytes();
    CertificateFactory x509CertFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
    X509Certificate certificate =
        (X509Certificate) x509CertFactory.generateCertificate(new ByteArrayInputStream(certBytes));

    byte[] kmsEncryptedDataKey = storage.getKmsEncryptedDataKey();
    byte[] dataKey = decryptDataKey(kmsEncryptedDataKey);

    byte[] aeadEncryptedPrivateKey = storage.getAeadEncryptedPrivateKey();
    byte[] attestationDocBytes = storage.getAttestationDocBytes();
    AttestationToken token = AttestationToken.fromBytes(attestationDocBytes);

    byte[] decryptedPrivateKeyBytes = decrypt(aeadEncryptedPrivateKey, dataKey);
    PrivateKey privateKey =
        parsePrivateKey(decryptedPrivateKeyBytes, certificate.getPublicKey().getAlgorithm());

    metrics.recordEvent(Metrics.MbsEvent.SUCCESS);
    return new MeasurementBoundCertificate(certificate, privateKey, token);
  }

  private MeasurementBoundCertificate generateAndStoreCertificate()
      throws IOException, GeneralSecurityException, KmsException {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey = certificateFactory.generate();

    X509Certificate certificate = certAndKey.certificate();
    PrivateKey privateKey = certAndKey.privateKey();

    AttestationToken token =
        attestationCollector.collectBoundToPubkey(
            certificate.getPublicKey(), userDataBoundToAttestation);

    KmsGeneratedKey dataKey = generateDataKey();
    byte[] aeadEncryptedPrivateKey = encrypt(privateKey.getEncoded(), dataKey.plaintext());

    storage.putAeadEncryptedPrivateKey(aeadEncryptedPrivateKey);
    storage.putKmsEncryptedDataKey(dataKey.ciphertext());
    storage.putAttestationDocBytes(token.getBytes());
    // The public root certificate (certBytes) is written last as an atomic completion sentinel
    // for polling readers in loadCertificate().
    storage.putCertBytes(toPemBytes(certificate));

    metrics.recordEvent(Metrics.MbsEvent.SUCCESS);
    return new MeasurementBoundCertificate(certificate, privateKey, token);
  }

  private KmsGeneratedKey generateDataKey() throws KmsException {
    try {
      return kmsClient.generateDataKey(kmsKeyArn);
    } catch (KmsException e) {
      metrics.recordEvent(Metrics.MbsEvent.KMS_OPERATION_FAILED);
      throw e;
    }
  }

  private byte[] decryptDataKey(byte[] kmsEncryptedDataKey) throws KmsException {
    try {
      return kmsClient.decrypt(kmsEncryptedDataKey, kmsKeyArn);
    } catch (KmsException e) {
      metrics.recordEvent(Metrics.MbsEvent.KMS_OPERATION_FAILED);
      throw e;
    }
  }

  private PrivateKey parsePrivateKey(byte[] privateKeyBytes, String algorithm)
      throws GeneralSecurityException {
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    return keyFactory.generatePrivate(privateKeySpec);
  }

  private byte[] encrypt(byte[] plaintext, byte[] key) throws GeneralSecurityException {
    if (key.length != 32) {
      throw new GeneralSecurityException("Invalid key size. Expected 32 bytes for AES-256-GCM.");
    }

    return getAead(key).encrypt(plaintext, new byte[0]);
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

  static byte[] toPemBytes(X509Certificate certificate)
      throws IOException, GeneralSecurityException {
    StringWriter stringWriter = new StringWriter();
    try (PemWriter pemWriter = new PemWriter(stringWriter)) {
      pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
    }
    return stringWriter.toString().getBytes(StandardCharsets.UTF_8);
  }
}
