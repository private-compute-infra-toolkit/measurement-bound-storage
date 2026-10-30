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

package com.google.mbs.adapters;

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
import com.google.mbs.domain.BackupCorruptedException;
import com.google.mbs.domain.CertificateCodec;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.KmsGeneratedKey;
import com.google.mbs.domain.SelfSignedBundle;
import com.google.mbs.domain.SelfSignedBundleBackup;
import com.google.mbs.domain.SelfSignedBundleBackupSealer;
import com.google.mbs.qualifier.KmsKeyArn;
import jakarta.inject.Inject;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Objects;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AeadSelfSignedBundleBackupSealer implements SelfSignedBundleBackupSealer {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static final int ASSOCIATED_DATA_VERSION = 1;

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
  private final String kmsKeyArn;
  private final CertificateCodec certificateCodec;

  @Inject
  AeadSelfSignedBundleBackupSealer(
      KmsClientInterface kmsClient,
      @KmsKeyArn String kmsKeyArn,
      CertificateCodec certificateCodec) {
    this.kmsClient = Objects.requireNonNull(kmsClient);
    this.kmsKeyArn = Objects.requireNonNull(kmsKeyArn);
    this.certificateCodec = Objects.requireNonNull(certificateCodec);
  }

  @Override
  public SelfSignedBundleBackup seal(SelfSignedBundle bundle) throws KmsException {
    byte[] certBytes = certificateCodec.toBytes(bundle.certificate());
    byte[] attestationDocBytes = bundle.attestationToken().getBytes();
    KmsGeneratedKey dataKey = kmsClient.generateDataKey(kmsKeyArn);
    byte[] aeadEncryptedPrivateKey;
    try {
      aeadEncryptedPrivateKey =
          getAead(dataKey.plaintext())
              .encrypt(
                  bundle.privateKey().getEncoded(),
                  buildAssociatedData(certBytes, attestationDocBytes));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Failed to encrypt private key", e);
    }
    return new SelfSignedBundleBackup(
        certBytes, dataKey.ciphertext(), aeadEncryptedPrivateKey, attestationDocBytes);
  }

  @Override
  public SelfSignedBundle unseal(SelfSignedBundleBackup backup)
      throws KmsException, BackupCorruptedException {
    byte[] dataKey = kmsClient.decrypt(backup.kmsEncryptedDataKey(), kmsKeyArn);

    X509Certificate certificate;
    PrivateKey privateKey;
    AttestationToken token = AttestationToken.fromBytes(backup.attestationDocBytes());
    try {
      byte[] decryptedPrivateKeyBytes = decryptPrivateKey(backup, dataKey);
      certificate = certificateCodec.toCertificate(backup.certBytes());
      privateKey =
          parsePrivateKey(decryptedPrivateKeyBytes, certificate.getPublicKey().getAlgorithm());
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new BackupCorruptedException("Key material could not be decoded", e);
    }

    if (!isKeyMatchingCertificate(certificate, privateKey)) {
      throw new BackupCorruptedException("Private key does not match certificate");
    }
    return new SelfSignedBundle(certificate, privateKey, token);
  }

  @VisibleForTesting
  public static byte[] buildAssociatedData(byte[] certBytes, byte[] attestationDocBytes) {
    // Modifying the associated data format will break decryption of keys encrypted with this
    // associated data format. If changes are needed, create new format and support both for
    // decryption.
    return ByteBuffer.allocate(3 * Integer.BYTES + certBytes.length + attestationDocBytes.length)
        .putInt(ASSOCIATED_DATA_VERSION)
        .putInt(certBytes.length)
        .put(certBytes)
        .putInt(attestationDocBytes.length)
        .put(attestationDocBytes)
        .array();
  }

  private static byte[] decryptPrivateKey(SelfSignedBundleBackup backup, byte[] dataKey)
      throws GeneralSecurityException {
    Aead aead = getAead(dataKey);
    byte[] expectedAssociatedData =
        buildAssociatedData(backup.certBytes(), backup.attestationDocBytes());
    try {
      return aead.decrypt(backup.aeadEncryptedPrivateKey(), expectedAssociatedData);
    } catch (GeneralSecurityException e) {
      // Legacy backups created before associated data binding was introduced were encrypted
      // with empty associated data; retry without associated data for backward compatibility.
      logger.atInfo().log(
          "AEAD decryption with associated data failed; retrying with empty associated data for"
              + " legacy backup compatibility");
      return aead.decrypt(backup.aeadEncryptedPrivateKey(), new byte[0]);
    }
  }

  private static boolean isKeyMatchingCertificate(
      X509Certificate certificate, PrivateKey privateKey) {
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

  private static PrivateKey parsePrivateKey(byte[] privateKeyBytes, String algorithm)
      throws GeneralSecurityException {
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    return keyFactory.generatePrivate(privateKeySpec);
  }

  @VisibleForTesting
  @AccessesPartialKey
  static Aead getAead(byte[] key) throws GeneralSecurityException {
    if (key.length != 32) {
      throw new GeneralSecurityException("Invalid key size. Expected 32 bytes for AES-256-GCM.");
    }
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
