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

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.flogger.FluentLogger;
import com.google.common.io.ByteStreams;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.util.SecretBytes;
import com.google.kmsclient.KmsClientInterface;
import com.google.kmsclient.KmsException;
import com.google.kmsclient.KmsGeneratedKey;
import com.google.mbs.attestationcollection.AttestationCollector;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.tlog.TlogEntry;
import com.google.tlog.TransparencyLogClient;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Optional;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

public class KmsMeasurementBoundCertificateProvider implements MeasurementBoundCertificateProvider {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final String KEY_ALGORITHM = "RSA";
  private static final int KEY_SIZE = 4096;
  private static final String CERTIFICATE_TYPE = "X.509";

  private static final SecureRandom secureRandom = new SecureRandom();

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
  private final S3Client s3Client;
  private final KeyBackupBucketProperties bucketProperties;
  private final String kmsKeyArn;
  private final TransparencyLogClient tlogClient;
  private final AttestationCollector attestationCollector;
  private final byte[] userDataBoundToAttestation;
  private final MbsCertificateFactory certificateFactory;

  private final Supplier<MeasurementBoundCertificate> cachedCertificate =
      Suppliers.memoize(
          () -> {
            try {
              return executeLoadOrGenerateCertificate();
            } catch (IOException
                | GeneralSecurityException
                | InterruptedException
                | KmsException e) {
              throw new RuntimeException(e);
            }
          });

  @Inject
  public KmsMeasurementBoundCertificateProvider(
      KmsClientInterface kmsClient,
      S3Client s3Client,
      KeyBackupBucketProperties bucketProperties,
      String kmsKeyArn,
      byte[] userDataBoundToAttestation,
      TransparencyLogClient tlogClient,
      AttestationCollector attestationCollector,
      MbsCertificateFactory certificateFactory) {
    this.kmsClient = kmsClient;
    this.s3Client = s3Client;
    this.bucketProperties = bucketProperties;
    this.kmsKeyArn = kmsKeyArn;
    this.userDataBoundToAttestation = userDataBoundToAttestation;
    this.tlogClient = tlogClient;
    this.attestationCollector = attestationCollector;
    this.certificateFactory = certificateFactory;
  }

  public MeasurementBoundCertificate loadOrGenerateCertificate() {
    return cachedCertificate.get();
  }

  /**
   * Loads the TCA's root certificate and key from S3, or generates a new one if it doesn't exist.
   *
   * @return the root {@link MeasurementBoundCertificate}
   * @throws IOException if an I/O error occurs
   * @throws GeneralSecurityException if a security error occurs
   * @throws InterruptedException if the current thread is interrupted
   */
  private MeasurementBoundCertificate executeLoadOrGenerateCertificate()
      throws IOException, GeneralSecurityException, InterruptedException, KmsException {
    try {
      // Fetch certificate from S3
      ResponseInputStream<GetObjectResponse> s3CertObject =
          s3Client.getObject(
              GetObjectRequest.builder()
                  .bucket(bucketProperties.getPublicBucketName())
                  .key(bucketProperties.getCertPath())
                  .build());
      byte[] certBytes = ByteStreams.toByteArray(s3CertObject);
      CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
      X509Certificate certificate =
          (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

      // Fetch the KMS-encrypted data key from S3
      ResponseInputStream<GetObjectResponse> s3KmsKeyObject =
          s3Client.getObject(
              GetObjectRequest.builder()
                  .bucket(bucketProperties.getPrivateBucketName())
                  .key(bucketProperties.getKmsEncryptedDataKeyPath())
                  .build());
      byte[] kmsEncryptedDataKey = ByteStreams.toByteArray(s3KmsKeyObject);

      // Decrypt the data key using KMS
      byte[] dataKey = kmsClient.decrypt(kmsEncryptedDataKey, kmsKeyArn);

      // Fetch the AES-encrypted private key from S3
      ResponseInputStream<GetObjectResponse> s3AesKeyObject =
          s3Client.getObject(
              GetObjectRequest.builder()
                  .bucket(bucketProperties.getPrivateBucketName())
                  .key(bucketProperties.getAesEncryptedPrivateKeyPath())
                  .build());
      byte[] aeadEncryptedPrivateKey = ByteStreams.toByteArray(s3AesKeyObject);

      // Fetch attestation token from S3.
      ResponseInputStream<GetObjectResponse> s3AttestationDoc =
          s3Client.getObject(
              GetObjectRequest.builder()
                  .bucket(bucketProperties.getPublicBucketName())
                  .key(bucketProperties.getAttestationDocPath())
                  .build());
      byte[] attestationDocBytes = ByteStreams.toByteArray(s3AttestationDoc);
      AttestationToken token = AttestationToken.fromBytes(attestationDocBytes);

      // Decrypt the private key locally using the data key
      byte[] decryptedPrivateKey = decrypt(aeadEncryptedPrivateKey, dataKey);
      PrivateKey privateKey =
          createPrivateKey(decryptedPrivateKey, certificate.getPublicKey().getAlgorithm());

      // Reconcile tlog artifacts if necessary
      reconcileTlogArtifacts(certificate);

      return new MeasurementBoundCertificate(certificate, privateKey, token);
    } catch (NoSuchKeyException e) {
      // If the key or cert doesn't exist, generate a new one.
      return generateAndStoreCertificate();
    }
  }

  private MeasurementBoundCertificate generateAndStoreCertificate()
      throws NoSuchAlgorithmException,
          IOException,
          InterruptedException,
          GeneralSecurityException,
          KmsException {
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey = certificateFactory.generate();

    X509Certificate certificate = certAndKey.certificate();
    PrivateKey privateKey = certAndKey.privateKey();

    AttestationToken token =
        attestationCollector.collectBoundToPubkey(
            certificate.getPublicKey(), userDataBoundToAttestation);

    // Generate a data key from KMS
    KmsGeneratedKey generatedKey = kmsClient.generateDataKey(kmsKeyArn);

    // Encrypt the private key locally with the plaintext data key
    byte[] aeadEncryptedPrivateKey = encrypt(privateKey.getEncoded(), generatedKey.plaintext());

    // Store the AES-encrypted private key in S3
    s3Client.putObject(
        PutObjectRequest.builder()
            .bucket(bucketProperties.getPrivateBucketName())
            .key(bucketProperties.getAesEncryptedPrivateKeyPath())
            .checksumAlgorithm(ChecksumAlgorithm.SHA256)
            .build(),
        RequestBody.fromBytes(aeadEncryptedPrivateKey));

    // Store the KMS-encrypted data key in S3
    s3Client.putObject(
        PutObjectRequest.builder()
            .bucket(bucketProperties.getPrivateBucketName())
            .key(bucketProperties.getKmsEncryptedDataKeyPath())
            .checksumAlgorithm(ChecksumAlgorithm.SHA256)
            .build(),
        RequestBody.fromBytes(generatedKey.ciphertext()));

    // Store the certificate in S3
    s3Client.putObject(
        PutObjectRequest.builder()
            .bucket(bucketProperties.getPublicBucketName())
            .key(bucketProperties.getCertPath())
            .checksumAlgorithm(ChecksumAlgorithm.SHA256)
            .build(),
        RequestBody.fromBytes(certificate.getEncoded()));

    // Store the attestation doc in S3
    s3Client.putObject(
        PutObjectRequest.builder()
            .bucket(bucketProperties.getPublicBucketName())
            .key(bucketProperties.getAttestationDocPath())
            .checksumAlgorithm(ChecksumAlgorithm.SHA256)
            .build(),
        RequestBody.fromBytes(token.getBytes()));

    // Record the certificate in the transparency log
    TlogEntry tlogEntry;
    try {
      tlogEntry = tlogClient.recordCertificate(certificate, privateKey);
    } catch (Exception e) {
      // Per requirements, failure to register the root is a catastrophic failure.
      throw new RuntimeException(
          "Failed to record root certificate in transparency log: " + e.getMessage(), e);
    }

    // Store the tlog artifacts in S3
    s3Client.putObject(
        PutObjectRequest.builder()
            .bucket(bucketProperties.getPublicBucketName())
            .key(bucketProperties.getTlogEntryPath())
            .checksumAlgorithm(ChecksumAlgorithm.SHA256)
            .build(),
        RequestBody.fromString(tlogEntry.getEntryJson()));

    return new MeasurementBoundCertificate(certificate, privateKey, token);
  }

  private PrivateKey createPrivateKey(byte[] privateKeyBytes, String algorithm)
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
    AesGcmKey aesGcmkey =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES256_GCM)
            .setKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
            .setIdRequirement(1)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmkey).withFixedId(1).makePrimary())
            .build();
    return keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
  }

  private boolean s3ObjectExists(String bucketName, String key) {
    try {
      s3Client.headObject(HeadObjectRequest.builder().bucket(bucketName).key(key).build());
      return true;
    } catch (NoSuchKeyException e) {
      return false;
    }
  }

  private void reconcileTlogArtifacts(X509Certificate certificate)
      throws GeneralSecurityException, IOException {
    // This reconciliation step is necessary to handle cases where the TCA might have crashed
    // after successfully submitting the certificate to the transparency log (Rekor)
    // but before it could store the returned tlog entry JSON in the S3 bucket.
    // By checking for the existence of the entry in S3 and fetching it from Rekor
    // if it's missing, we ensure the system self-heals and maintains consistency.
    if (!s3ObjectExists(
        bucketProperties.getPublicBucketName(), bucketProperties.getTlogEntryPath())) {
      logger.atInfo().log("Tlog entry not found in S3, attempting to reconcile from Rekor.");
      // Tlog entry is missing, try to retrieve from Rekor
      try {
        Optional<TlogEntry> tlogEntryOpt = tlogClient.getTlogEntryByCertificate(certificate);

        if (tlogEntryOpt.isPresent()) {
          TlogEntry tlogEntry = tlogEntryOpt.get();
          s3Client.putObject(
              PutObjectRequest.builder()
                  .bucket(bucketProperties.getPublicBucketName())
                  .key(bucketProperties.getTlogEntryPath())
                  .checksumAlgorithm(ChecksumAlgorithm.SHA256)
                  .build(),
              RequestBody.fromString(tlogEntry.getEntryJson()));
          logger.atInfo().log("Successfully reconciled tlog entry from Rekor.");
        } else {
          logger.atWarning().log(
              "Tlog entry not found in S3 and could not be retrieved from Rekor.");
        }
      } catch (Exception e) {
        // Log the exception, but don't fail the whole process
        logger.atSevere().withCause(e).log("Error during tlog reconciliation.");
      }
    }
  }
}
