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
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupAlreadyExistsException;
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.KeyBackupStorageException;
import com.google.mbs.domain.StorageAlreadyLockedException;
import com.google.mbs.qualifier.InstanceId;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/** Writes key backup artifacts to S3 and holds the generation lock. */
@Singleton
public class S3BackupWriter {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static final int HTTP_STATUS_PRECONDITION_FAILED = 412;
  private static final String AWS_ERROR_CODE_PRECONDITION_FAILED = "PreconditionFailed";
  private static final String HEADER_IF_NONE_MATCH = "If-None-Match";

  private final S3Client s3Client;
  private final KeyBackupBucketProperties bucketProperties;
  private final String instanceId;

  @Inject
  public S3BackupWriter(
      S3Client s3Client,
      KeyBackupBucketProperties bucketProperties,
      @InstanceId String instanceId) {
    this.s3Client = Objects.requireNonNull(s3Client);
    this.bucketProperties = Objects.requireNonNull(bucketProperties);
    this.instanceId = Objects.requireNonNull(instanceId);
  }

  /**
   * Takes the generation lock shared by all epochs.
   *
   * @throws StorageAlreadyLockedException if the lock is already held by another instance
   * @throws KeyBackupAccessFailedException if the lock could not be written
   */
  public void acquireLock() throws StorageAlreadyLockedException, KeyBackupAccessFailedException {
    String bucket = bucketProperties.getPrivateBucketName();
    String key = S3BackupPaths.getLockPath();
    try {
      putIfAbsent(bucket, key, instanceId.getBytes(StandardCharsets.UTF_8), "no-cache");
      logger.atInfo().log("Acquired S3 generation lock %s/%s", bucket, key);
    } catch (KeyBackupAlreadyExistsException e) {
      logger.atInfo().log(
          "S3 generation lock %s/%s is already held by another instance", bucket, key);
      throw new StorageAlreadyLockedException("Generation lock present at " + key, e.getCause());
    }
  }

  /**
   * Releases the generation lock.
   *
   * @throws KeyBackupAccessFailedException if the lock could not be removed
   */
  public void releaseLock() throws KeyBackupAccessFailedException {
    try {
      s3Client.deleteObject(
          DeleteObjectRequest.builder()
              .bucket(bucketProperties.getPrivateBucketName())
              .key(S3BackupPaths.getLockPath())
              .build());
      logger.atInfo().log(
          "Released S3 generation lock %s/%s",
          bucketProperties.getPrivateBucketName(), S3BackupPaths.getLockPath());
    } catch (SdkException e) {
      logger.atWarning().withCause(e).log(
          "Failed to delete S3 generation lock %s/%s",
          bucketProperties.getPrivateBucketName(), S3BackupPaths.getLockPath());
      throw new KeyBackupAccessFailedException("Failed to delete S3 generation lock file", e);
    }
  }

  /**
   * Writes the backup of {@code epoch}, certificate last so that it acts as a completion sentinel
   * for concurrent readers.
   *
   * @throws KeyBackupAlreadyExistsException if any artifact for {@code epoch} already exists
   * @throws KeyBackupAccessFailedException if any artifact could not be written
   */
  public void write(int epoch, KeyBackup keyBackup) throws KeyBackupStorageException {
    logger.atInfo().log("Writing backup artifacts to S3 for epoch %d", epoch);
    putS3Object(
        bucketProperties.getPrivateBucketName(),
        S3BackupPaths.getAesEncryptedPrivateKeyPath(epoch),
        keyBackup.aeadEncryptedPrivateKey());
    putS3Object(
        bucketProperties.getPrivateBucketName(),
        S3BackupPaths.getKmsEncryptedDataKeyPath(epoch),
        keyBackup.kmsEncryptedDataKey());
    putS3Object(
        bucketProperties.getPublicBucketName(),
        S3BackupPaths.getAttestationDocPath(epoch),
        keyBackup.attestationDocBytes());
    // Written last, as the completion sentinel readers rely on.
    putS3Object(
        bucketProperties.getPublicBucketName(),
        S3BackupPaths.getRootCertPath(epoch),
        keyBackup.certBytes());
    logger.atInfo().log("Successfully wrote backup artifacts to S3 for epoch %d", epoch);
  }

  /**
   * Writes the cross-signed certificate for {@code id}.
   *
   * @throws KeyBackupAlreadyExistsException if the certificate for {@code id} already exists
   * @throws KeyBackupAccessFailedException if the certificate could not be written
   */
  public void writeCrossSignedCert(CrossSignedCertificateId id, CrossSignedCertificateBackup backup)
      throws KeyBackupStorageException {
    logger.atInfo().log("Writing cross-signed certificate to S3 for %s", id.toKeyString());
    putS3Object(
        bucketProperties.getPublicBucketName(),
        S3BackupPaths.getCrossSignedCertPath(id),
        backup.certBytes());
    logger.atInfo().log(
        "Successfully wrote cross-signed certificate to S3 for %s", id.toKeyString());
  }

  static boolean isPreconditionFailed(S3Exception e) {
    return e.statusCode() == HTTP_STATUS_PRECONDITION_FAILED
        || (e.awsErrorDetails() != null
            && AWS_ERROR_CODE_PRECONDITION_FAILED.equalsIgnoreCase(
                e.awsErrorDetails().errorCode()));
  }

  private void putS3Object(String bucket, String key, byte[] content)
      throws KeyBackupAlreadyExistsException, KeyBackupAccessFailedException {
    putIfAbsent(bucket, key, content, bucketProperties.getCacheControl());
  }

  private void putIfAbsent(String bucket, String key, byte[] content, String cacheControl)
      throws KeyBackupAlreadyExistsException, KeyBackupAccessFailedException {
    try {
      PutObjectRequest request =
          PutObjectRequest.builder()
              .bucket(bucket)
              .key(key)
              .checksumAlgorithm(ChecksumAlgorithm.SHA256)
              .cacheControl(cacheControl)
              .overrideConfiguration(o -> o.putHeader(HEADER_IF_NONE_MATCH, "*"))
              .build();
      s3Client.putObject(request, RequestBody.fromBytes(content));
    } catch (SdkException e) {
      if (e instanceof S3Exception s3Exception && isPreconditionFailed(s3Exception)) {
        throw new KeyBackupAlreadyExistsException(
            "Object already exists: " + key + " in bucket: " + bucket, e);
      }
      logger.atWarning().withCause(e).log("Failed to put S3 object %s/%s", bucket, key);
      throw new KeyBackupAccessFailedException(
          "Failed to put object: " + key + " in bucket: " + bucket, e);
    }
  }
}
