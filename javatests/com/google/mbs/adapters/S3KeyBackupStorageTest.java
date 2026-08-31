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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.mbs.KeyBackupBucketProperties;
import com.google.mbs.KeyBackupBucketPropertiesFactory;
import com.google.mbs.KeyBackupNotFoundException;
import com.google.mbs.KeyBackupStorageException;
import com.google.mbs.Metrics;
import com.google.mbs.Metrics.MbsEvent;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@RunWith(JUnit4.class)
public class S3KeyBackupStorageTest {

  private static final String PUBLIC_BUCKET = "public-bucket";
  private static final String PRIVATE_BUCKET = "private-bucket";
  private static final byte[] SAMPLE_DATA = "test-bytes".getBytes(StandardCharsets.UTF_8);

  @Mock private S3Client s3Client;
  @Mock private Metrics metrics;

  private KeyBackupBucketProperties bucketProperties;
  private S3KeyBackupStorage storage;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    bucketProperties = new KeyBackupBucketPropertiesFactory(PUBLIC_BUCKET, PRIVATE_BUCKET).create();
    storage = new S3KeyBackupStorage(s3Client, bucketProperties, metrics);
  }

  @Test
  public void getCertBytes_success() throws Exception {
    when(s3Client.getObject(
            eq(
                GetObjectRequest.builder()
                    .bucket(PUBLIC_BUCKET)
                    .key(bucketProperties.getCertPath())
                    .build()),
            any(ResponseTransformer.class)))
        .thenReturn(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), SAMPLE_DATA));

    byte[] result = storage.getCertBytes();

    assertThat(result).isEqualTo(SAMPLE_DATA);
    verifyNoInteractions(metrics);
  }

  @Test
  public void getCertBytes_noSuchKey_translatesToKeyBackupNotFoundException() {
    when(s3Client.getObject(
            eq(
                GetObjectRequest.builder()
                    .bucket(PUBLIC_BUCKET)
                    .key(bucketProperties.getCertPath())
                    .build()),
            any(ResponseTransformer.class)))
        .thenThrow(NoSuchKeyException.builder().build());

    assertThrows(KeyBackupNotFoundException.class, () -> storage.getCertBytes());
    verifyNoInteractions(metrics);
  }

  @Test
  public void getCertBytes_sdkException_recordsMetricAndTranslatesToKeyBackupStorageException() {
    when(s3Client.getObject(
            eq(
                GetObjectRequest.builder()
                    .bucket(PUBLIC_BUCKET)
                    .key(bucketProperties.getCertPath())
                    .build()),
            any(ResponseTransformer.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(KeyBackupStorageException.class, () -> storage.getCertBytes());
    verify(metrics).recordEvent(MbsEvent.S3_FETCH_FAILED);
  }

  @Test
  public void getKmsEncryptedDataKey_success() throws Exception {
    when(s3Client.getObject(
            eq(
                GetObjectRequest.builder()
                    .bucket(PRIVATE_BUCKET)
                    .key(bucketProperties.getKmsEncryptedDataKeyPath())
                    .build()),
            any(ResponseTransformer.class)))
        .thenReturn(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), SAMPLE_DATA));

    byte[] result = storage.getKmsEncryptedDataKey();

    assertThat(result).isEqualTo(SAMPLE_DATA);
  }

  @Test
  public void getKmsEncryptedDataKey_sdkException_recordsMetricAndTranslatesException() {
    when(s3Client.getObject(
            eq(
                GetObjectRequest.builder()
                    .bucket(PRIVATE_BUCKET)
                    .key(bucketProperties.getKmsEncryptedDataKeyPath())
                    .build()),
            any(ResponseTransformer.class)))
        .thenThrow(SdkClientException.create("S3 error"));

    assertThrows(KeyBackupStorageException.class, () -> storage.getKmsEncryptedDataKey());
    verify(metrics).recordEvent(MbsEvent.S3_FETCH_FAILED);
  }

  @Test
  public void getAeadEncryptedPrivateKey_success() throws Exception {
    when(s3Client.getObject(
            eq(
                GetObjectRequest.builder()
                    .bucket(PRIVATE_BUCKET)
                    .key(bucketProperties.getAesEncryptedPrivateKeyPath())
                    .build()),
            any(ResponseTransformer.class)))
        .thenReturn(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), SAMPLE_DATA));

    byte[] result = storage.getAeadEncryptedPrivateKey();

    assertThat(result).isEqualTo(SAMPLE_DATA);
  }

  @Test
  public void getAttestationDocBytes_success() throws Exception {
    when(s3Client.getObject(
            eq(
                GetObjectRequest.builder()
                    .bucket(PUBLIC_BUCKET)
                    .key(bucketProperties.getAttestationDocPath())
                    .build()),
            any(ResponseTransformer.class)))
        .thenReturn(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), SAMPLE_DATA));

    byte[] result = storage.getAttestationDocBytes();

    assertThat(result).isEqualTo(SAMPLE_DATA);
  }

  @Test
  public void putCertBytes_success() throws Exception {
    storage.putCertBytes(SAMPLE_DATA);

    ArgumentCaptor<PutObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    verify(s3Client).putObject(requestCaptor.capture(), any(RequestBody.class));
    assertThat(requestCaptor.getValue().bucket()).isEqualTo(PUBLIC_BUCKET);
    assertThat(requestCaptor.getValue().key()).isEqualTo(bucketProperties.getCertPath());
    assertThat(requestCaptor.getValue().checksumAlgorithm()).isEqualTo(ChecksumAlgorithm.SHA256);
    assertThat(requestCaptor.getValue().cacheControl())
        .isEqualTo(bucketProperties.getCacheControl());
    verifyNoInteractions(metrics);
  }

  @Test
  public void putCertBytes_sdkException_recordsMetricAndTranslatesToKeyBackupStorageException() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(SdkClientException.create("S3 write failure"));

    assertThrows(KeyBackupStorageException.class, () -> storage.putCertBytes(SAMPLE_DATA));
    verify(metrics).recordEvent(MbsEvent.S3_WRITE_FAILED);
  }

  @Test
  public void putKmsEncryptedDataKey_success() throws Exception {
    storage.putKmsEncryptedDataKey(SAMPLE_DATA);

    ArgumentCaptor<PutObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    verify(s3Client).putObject(requestCaptor.capture(), any(RequestBody.class));
    assertThat(requestCaptor.getValue().bucket()).isEqualTo(PRIVATE_BUCKET);
    assertThat(requestCaptor.getValue().key())
        .isEqualTo(bucketProperties.getKmsEncryptedDataKeyPath());
  }

  @Test
  public void putAeadEncryptedPrivateKey_success() throws Exception {
    storage.putAeadEncryptedPrivateKey(SAMPLE_DATA);

    ArgumentCaptor<PutObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    verify(s3Client).putObject(requestCaptor.capture(), any(RequestBody.class));
    assertThat(requestCaptor.getValue().bucket()).isEqualTo(PRIVATE_BUCKET);
    assertThat(requestCaptor.getValue().key())
        .isEqualTo(bucketProperties.getAesEncryptedPrivateKeyPath());
  }

  @Test
  public void putAttestationDocBytes_success() throws Exception {
    storage.putAttestationDocBytes(SAMPLE_DATA);

    ArgumentCaptor<PutObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    verify(s3Client).putObject(requestCaptor.capture(), any(RequestBody.class));
    assertThat(requestCaptor.getValue().bucket()).isEqualTo(PUBLIC_BUCKET);
    assertThat(requestCaptor.getValue().key()).isEqualTo(bucketProperties.getAttestationDocPath());
  }
}
