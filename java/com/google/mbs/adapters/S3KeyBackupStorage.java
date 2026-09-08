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
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KeyBackupStorageException;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.Metrics.MbsEvent;
import com.google.mbs.domain.StorageAlreadyLockedException;
import com.google.mbs.qualifier.InstanceId;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Storage adapter handling S3 interactions and distributed locking for MBS certificates and keys.
 */
@Singleton
public class S3KeyBackupStorage implements KeyBackupStorage {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static final int HTTP_STATUS_PRECONDITION_FAILED = 412;
  private static final String AWS_ERROR_CODE_PRECONDITION_FAILED = "PreconditionFailed";
  private static final String HEADER_IF_NONE_MATCH = "If-None-Match";

  private final S3Client s3Client;
  private final KeyBackupBucketProperties bucketProperties;
  private final String instanceId;
  private final Metrics metrics;

  @Inject
  public S3KeyBackupStorage(
      S3Client s3Client,
      KeyBackupBucketProperties bucketProperties,
      @InstanceId String instanceId,
      Metrics metrics) {
    this.s3Client = s3Client;
    this.bucketProperties = bucketProperties;
    this.instanceId = instanceId;
    this.metrics = metrics;
  }

  @Override
  public void acquireLock() throws StorageAlreadyLockedException {
    try {
      PutObjectRequest request =
          PutObjectRequest.builder()
              .bucket(bucketProperties.getPrivateBucketName())
              .key(bucketProperties.getLockPath())
              .checksumAlgorithm(ChecksumAlgorithm.SHA256)
              .cacheControl("no-cache")
              .overrideConfiguration(o -> o.putHeader(HEADER_IF_NONE_MATCH, "*"))
              .build();
      s3Client.putObject(request, RequestBody.fromString(instanceId));
    } catch (S3Exception e) {
      if (isAlreadyLocked(e)) {
        throw new StorageAlreadyLockedException(
            "Root certificate generation lock is already held at " + bucketProperties.getLockPath(),
            e);
      }
      metrics.recordEvent(MbsEvent.S3_WRITE_FAILED);
      throw new KeyBackupStorageException("Failed to write S3 generation lock file", e);
    } catch (SdkException e) {
      metrics.recordEvent(MbsEvent.S3_WRITE_FAILED);
      throw new KeyBackupStorageException("Failed to write S3 generation lock file", e);
    }
  }

  @Override
  public void releaseLock() {
    try {
      s3Client.deleteObject(
          DeleteObjectRequest.builder()
              .bucket(bucketProperties.getPrivateBucketName())
              .key(bucketProperties.getLockPath())
              .build());
    } catch (Exception e) {
      logger.atWarning().withCause(e).log(
          "Failed to delete generation lock file %s/%s after successful generation",
          bucketProperties.getPrivateBucketName(), bucketProperties.getLockPath());
    }
  }

  static boolean isAlreadyLocked(S3Exception e) {
    return e.statusCode() == HTTP_STATUS_PRECONDITION_FAILED
        || (e.awsErrorDetails() != null
            && AWS_ERROR_CODE_PRECONDITION_FAILED.equalsIgnoreCase(
                e.awsErrorDetails().errorCode()));
  }

  @Override
  public byte[] getCertBytes() throws KeyBackupNotFoundException {
    return getS3Object(bucketProperties.getPublicBucketName(), bucketProperties.getCertPath());
  }

  @Override
  public byte[] getKmsEncryptedDataKey() throws KeyBackupNotFoundException {
    return getS3Object(
        bucketProperties.getPrivateBucketName(), bucketProperties.getKmsEncryptedDataKeyPath());
  }

  @Override
  public byte[] getAeadEncryptedPrivateKey() throws KeyBackupNotFoundException {
    return getS3Object(
        bucketProperties.getPrivateBucketName(), bucketProperties.getAesEncryptedPrivateKeyPath());
  }

  @Override
  public byte[] getAttestationDocBytes() throws KeyBackupNotFoundException {
    return getS3Object(
        bucketProperties.getPublicBucketName(), bucketProperties.getAttestationDocPath());
  }

  @Override
  public void putCertBytes(byte[] content) {
    putS3Object(bucketProperties.getPublicBucketName(), bucketProperties.getCertPath(), content);
  }

  @Override
  public void putKmsEncryptedDataKey(byte[] content) {
    putS3Object(
        bucketProperties.getPrivateBucketName(),
        bucketProperties.getKmsEncryptedDataKeyPath(),
        content);
  }

  @Override
  public void putAeadEncryptedPrivateKey(byte[] content) {
    putS3Object(
        bucketProperties.getPrivateBucketName(),
        bucketProperties.getAesEncryptedPrivateKeyPath(),
        content);
  }

  @Override
  public void putAttestationDocBytes(byte[] content) {
    putS3Object(
        bucketProperties.getPublicBucketName(), bucketProperties.getAttestationDocPath(), content);
  }

  private byte[] getS3Object(String bucket, String key) throws KeyBackupNotFoundException {
    try {
      return s3Client
          .getObject(
              GetObjectRequest.builder().bucket(bucket).key(key).build(),
              ResponseTransformer.toBytes())
          .asByteArray();
    } catch (NoSuchKeyException e) {
      throw new KeyBackupNotFoundException("Object not found: " + key + " in bucket: " + bucket, e);
    } catch (SdkException e) {
      metrics.recordEvent(MbsEvent.S3_FETCH_FAILED);
      throw new KeyBackupStorageException(
          "Failed to fetch object: " + key + " from bucket: " + bucket, e);
    }
  }

  private void putS3Object(String bucket, String key, byte[] content) {
    try {
      s3Client.putObject(
          PutObjectRequest.builder()
              .bucket(bucket)
              .key(key)
              .checksumAlgorithm(ChecksumAlgorithm.SHA256)
              .cacheControl(bucketProperties.getCacheControl())
              .build(),
          RequestBody.fromBytes(content));
    } catch (SdkException e) {
      metrics.recordEvent(MbsEvent.S3_WRITE_FAILED);
      throw new KeyBackupStorageException(
          "Failed to put object: " + key + " in bucket: " + bucket, e);
    }
  }
}
