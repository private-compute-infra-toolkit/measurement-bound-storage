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

import com.google.common.flogger.FluentLogger;
import com.google.mbs.domain.BackupAccessFailedException;
import com.google.mbs.domain.BackupIncompleteException;
import com.google.mbs.domain.BackupNotFoundException;
import com.google.mbs.domain.BackupPartiallyWrittenException;
import com.google.mbs.domain.BackupStorageException;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.SelfSignedBundleBackup;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

/** Reads backup artifacts from S3. */
@Singleton
public class S3BackupReader {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private final S3Client s3Client;
  private final BackupBucketProperties bucketProperties;

  @Inject
  public S3BackupReader(S3Client s3Client, BackupBucketProperties bucketProperties) {
    this.s3Client = Objects.requireNonNull(s3Client);
    this.bucketProperties = Objects.requireNonNull(bucketProperties);
  }

  /**
   * Reads the self-signed bundle backup of {@code epoch}.
   *
   * <p>Callers have already established that the backup is complete via bucket listing, but storage
   * may have changed since, so missing artifacts are classified according to the state actually
   * observed.
   *
   * @throws BackupNotFoundException if all artifacts are missing
   * @throws BackupPartiallyWrittenException if the certificate is missing while other artifacts
   *     exist
   * @throws BackupIncompleteException if the certificate exists while other artifacts are missing
   * @throws BackupAccessFailedException if the artifacts could not be read
   */
  public SelfSignedBundleBackup readSelfSignedBundleBackup(int epoch)
      throws BackupStorageException {
    logger.atInfo().log("Reading backup artifacts from S3 for epoch %d", epoch);
    Optional<byte[]> certBytes =
        tryGetS3Object(
            bucketProperties.getPublicBucketName(), S3BackupPaths.getRootCertPath(epoch));
    Optional<byte[]> kmsEncryptedDataKey =
        tryGetS3Object(
            bucketProperties.getPrivateBucketName(),
            S3BackupPaths.getKmsEncryptedDataKeyPath(epoch));
    Optional<byte[]> aeadEncryptedPrivateKey =
        tryGetS3Object(
            bucketProperties.getPrivateBucketName(),
            S3BackupPaths.getAesEncryptedPrivateKeyPath(epoch));
    Optional<byte[]> attestationDocBytes =
        tryGetS3Object(
            bucketProperties.getPublicBucketName(), S3BackupPaths.getAttestationDocPath(epoch));

    List<String> missing = new ArrayList<>();
    if (certBytes.isEmpty()) {
      missing.add(S3BackupPaths.ROOT_CERT_FILE);
    }
    if (kmsEncryptedDataKey.isEmpty()) {
      missing.add(S3BackupPaths.KMS_ENCRYPTED_DATA_KEY_FILE);
    }
    if (aeadEncryptedPrivateKey.isEmpty()) {
      missing.add(S3BackupPaths.AES_ENCRYPTED_PRIVATE_KEY_FILE);
    }
    if (attestationDocBytes.isEmpty()) {
      missing.add(S3BackupPaths.ATTESTATION_DOC_FILE);
    }

    if (!missing.isEmpty()) {
      if (missing.size() == 4) {
        throw new BackupNotFoundException("Self-signed bundle backup absent for epoch " + epoch);
      }
      if (certBytes.isEmpty()) {
        throw new BackupPartiallyWrittenException(
            "Self-signed bundle backup partially written for epoch "
                + epoch
                + ", missing "
                + missing);
      }
      throw new BackupIncompleteException(
          "Self-signed bundle backup incomplete, missing " + missing);
    }

    logger.atInfo().log("Successfully read backup artifacts from S3 for epoch %d", epoch);
    return new SelfSignedBundleBackup(
        certBytes.get(),
        kmsEncryptedDataKey.get(),
        aeadEncryptedPrivateKey.get(),
        attestationDocBytes.get());
  }

  /**
   * Reads the cross-signed certificate backup for {@code id}.
   *
   * @throws BackupNotFoundException if the certificate is absent
   * @throws BackupAccessFailedException if the certificate could not be read
   */
  public CrossSignedCertificateBackup readCrossSignedCertificateBackup(CrossSignedCertificateId id)
      throws BackupStorageException {
    logger.atInfo().log("Reading cross-signed certificate from S3 for %s", id.toKeyString());
    Optional<byte[]> certBytes =
        tryGetS3Object(
            bucketProperties.getPublicBucketName(),
            S3BackupPaths.getCrossSignedCertificatePath(id));
    if (certBytes.isEmpty()) {
      throw new BackupNotFoundException("Cross-signed certificate absent for " + id.toKeyString());
    }
    logger.atInfo().log(
        "Successfully read cross-signed certificate from S3 for %s", id.toKeyString());
    return new CrossSignedCertificateBackup(certBytes.get());
  }

  private Optional<byte[]> tryGetS3Object(String bucket, String key)
      throws BackupAccessFailedException {
    try {
      return Optional.of(
          s3Client
              .getObject(
                  GetObjectRequest.builder().bucket(bucket).key(key).build(),
                  ResponseTransformer.toBytes())
              .asByteArray());
    } catch (NoSuchKeyException e) {
      return Optional.empty();
    } catch (SdkException e) {
      logger.atWarning().withCause(e).log("Failed to read S3 object %s/%s", bucket, key);
      throw new BackupAccessFailedException(
          "Failed to read object: " + key + " from bucket: " + bucket, e);
    }
  }
}
