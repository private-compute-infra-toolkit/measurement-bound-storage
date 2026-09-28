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
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.KeyBackupIncompleteException;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupPartiallyWrittenException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.Metrics.MbsEvent;
import com.google.mbs.domain.StorageAlreadyLockedException;
import com.google.mbs.qualifier.InstanceId;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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

  private static final int KEY_BACKUP_ARTIFACT_COUNT = 4;

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
  public void acquireLock() throws StorageAlreadyLockedException, KeyBackupAccessFailedException {
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
    } catch (SdkException e) {
      if (e instanceof S3Exception s3Exception && isAlreadyLocked(s3Exception)) {
        throw new StorageAlreadyLockedException(
            "Generation lock present at " + bucketProperties.getLockPath(), e);
      }
      metrics.recordEvent(MbsEvent.S3_WRITE_FAILED);
      logger.atWarning().withCause(e).log(
          "Failed to write S3 generation lock %s/%s",
          bucketProperties.getPrivateBucketName(), bucketProperties.getLockPath());
      throw new KeyBackupAccessFailedException("Failed to write S3 generation lock file", e);
    }
  }

  @Override
  public void releaseLock() throws KeyBackupAccessFailedException {
    try {
      s3Client.deleteObject(
          DeleteObjectRequest.builder()
              .bucket(bucketProperties.getPrivateBucketName())
              .key(bucketProperties.getLockPath())
              .build());
    } catch (SdkException e) {
      metrics.recordEvent(MbsEvent.S3_WRITE_FAILED);
      logger.atWarning().withCause(e).log(
          "Failed to delete S3 generation lock %s/%s",
          bucketProperties.getPrivateBucketName(), bucketProperties.getLockPath());
      throw new KeyBackupAccessFailedException("Failed to delete S3 generation lock file", e);
    }
  }

  static boolean isAlreadyLocked(S3Exception e) {
    return e.statusCode() == HTTP_STATUS_PRECONDITION_FAILED
        || (e.awsErrorDetails() != null
            && AWS_ERROR_CODE_PRECONDITION_FAILED.equalsIgnoreCase(
                e.awsErrorDetails().errorCode()));
  }

  @Override
  public KeyBackup getKeyBackup()
      throws KeyBackupNotFoundException,
          KeyBackupPartiallyWrittenException,
          KeyBackupIncompleteException,
          KeyBackupAccessFailedException {
    // putKeyBackup() writes the certificate last, so it is the completion sentinel: read it first,
    // and observing it means the other artifacts were already durable.
    Optional<byte[]> certBytes =
        tryGetS3Object(bucketProperties.getPublicBucketName(), bucketProperties.getCertPath());
    Optional<byte[]> kmsEncryptedDataKey =
        tryGetS3Object(
            bucketProperties.getPrivateBucketName(), bucketProperties.getKmsEncryptedDataKeyPath());
    Optional<byte[]> aeadEncryptedPrivateKey =
        tryGetS3Object(
            bucketProperties.getPrivateBucketName(),
            bucketProperties.getAesEncryptedPrivateKeyPath());
    Optional<byte[]> attestationDocBytes =
        tryGetS3Object(
            bucketProperties.getPublicBucketName(), bucketProperties.getAttestationDocPath());

    List<String> missing = new ArrayList<>();
    if (certBytes.isEmpty()) {
      missing.add(bucketProperties.getCertPath());
    }
    if (kmsEncryptedDataKey.isEmpty()) {
      missing.add(bucketProperties.getKmsEncryptedDataKeyPath());
    }
    if (aeadEncryptedPrivateKey.isEmpty()) {
      missing.add(bucketProperties.getAesEncryptedPrivateKeyPath());
    }
    if (attestationDocBytes.isEmpty()) {
      missing.add(bucketProperties.getAttestationDocPath());
    }

    if (missing.size() == KEY_BACKUP_ARTIFACT_COUNT) {
      throw new KeyBackupNotFoundException("Key backup absent");
    }
    if (certBytes.isEmpty()) {
      // The certificate is written last, so a backup lacking it was never completed.
      throw new KeyBackupPartiallyWrittenException(
          "Key backup partially written, missing " + missing);
    }
    if (!missing.isEmpty()) {
      // Certificate present, so a complete backup was published and has since lost artifacts.
      throw new KeyBackupIncompleteException("Key backup incomplete, missing " + missing);
    }

    return new KeyBackup(
        certBytes.get(),
        kmsEncryptedDataKey.get(),
        aeadEncryptedPrivateKey.get(),
        attestationDocBytes.get());
  }

  @Override
  public void putKeyBackup(KeyBackup keyBackup) throws KeyBackupAccessFailedException {
    putS3Object(
        bucketProperties.getPrivateBucketName(),
        bucketProperties.getAesEncryptedPrivateKeyPath(),
        keyBackup.aeadEncryptedPrivateKey());
    putS3Object(
        bucketProperties.getPrivateBucketName(),
        bucketProperties.getKmsEncryptedDataKeyPath(),
        keyBackup.kmsEncryptedDataKey());
    putS3Object(
        bucketProperties.getPublicBucketName(),
        bucketProperties.getAttestationDocPath(),
        keyBackup.attestationDocBytes());
    // Written last, as the completion sentinel getKeyBackup() relies on.
    putS3Object(
        bucketProperties.getPublicBucketName(),
        bucketProperties.getCertPath(),
        keyBackup.certBytes());
  }

  private Optional<byte[]> tryGetS3Object(String bucket, String key)
      throws KeyBackupAccessFailedException {
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
      metrics.recordEvent(MbsEvent.S3_FETCH_FAILED);
      logger.atWarning().withCause(e).log("Failed to fetch S3 object %s/%s", bucket, key);
      throw new KeyBackupAccessFailedException(
          "Failed to fetch object: " + key + " from bucket: " + bucket, e);
    }
  }

  private void putS3Object(String bucket, String key, byte[] content)
      throws KeyBackupAccessFailedException {
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
      logger.atWarning().withCause(e).log("Failed to put S3 object %s/%s", bucket, key);
      throw new KeyBackupAccessFailedException(
          "Failed to put object: " + key + " in bucket: " + bucket, e);
    }
  }
}
