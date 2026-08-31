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

import com.google.mbs.KeyBackupBucketProperties;
import com.google.mbs.KeyBackupNotFoundException;
import com.google.mbs.KeyBackupStorage;
import com.google.mbs.KeyBackupStorageException;
import com.google.mbs.Metrics;
import com.google.mbs.Metrics.MbsEvent;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/** Storage adapter handling S3 interactions for MBS certificates and keys. */
@Singleton
public class S3KeyBackupStorage implements KeyBackupStorage {

  private final S3Client s3Client;
  private final KeyBackupBucketProperties bucketProperties;
  private final Metrics metrics;

  @Inject
  public S3KeyBackupStorage(
      S3Client s3Client, KeyBackupBucketProperties bucketProperties, Metrics metrics) {
    this.s3Client = s3Client;
    this.bucketProperties = bucketProperties;
    this.metrics = metrics;
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
