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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.mbs.KeyBackupBucketPropertiesFactory;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.KeyBackupIncompleteException;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupPartiallyWrittenException;
import com.google.mbs.domain.KeyBackupStorageException;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.Metrics.MbsEvent;
import com.google.mbs.domain.StorageAlreadyLockedException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
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
  private static final String TEST_INSTANCE_ID = "i-testinstance123";

  private static final byte[] CERT_BYTES = "cert-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] KMS_ENCRYPTED_DATA_KEY_BYTES =
      "kms-encrypted-data-key-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] AEAD_ENCRYPTED_PRIVATE_KEY_BYTES =
      "aead-encrypted-private-key-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] ATTESTATION_DOC_BYTES =
      "attestation-doc-bytes".getBytes(StandardCharsets.UTF_8);

  @Mock private S3Client s3Client;
  @Mock private Metrics metrics;

  private KeyBackupBucketProperties bucketProperties;
  private S3KeyBackupStorage storage;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    bucketProperties = new KeyBackupBucketPropertiesFactory(PUBLIC_BUCKET, PRIVATE_BUCKET).create();
    storage = new S3KeyBackupStorage(s3Client, bucketProperties, TEST_INSTANCE_ID, metrics);
  }

  /**
   * The read-side half of the sentinel invariant: observing the certificate must imply the other
   * artifacts are already durable. Reading it last would let a concurrent writer produce a spurious
   * {@link KeyBackupIncompleteException}, which is a hard failure.
   */
  @Test
  public void getKeyBackup_allArtifactsPresent_returnsAggregateReadingCertificateFirst()
      throws Exception {
    stubAllPresent();

    KeyBackup keyBackup = storage.getKeyBackup();

    assertThat(keyBackup.certBytes()).isEqualTo(CERT_BYTES);
    assertThat(keyBackup.kmsEncryptedDataKey()).isEqualTo(KMS_ENCRYPTED_DATA_KEY_BYTES);
    assertThat(keyBackup.aeadEncryptedPrivateKey()).isEqualTo(AEAD_ENCRYPTED_PRIVATE_KEY_BYTES);
    assertThat(keyBackup.attestationDocBytes()).isEqualTo(ATTESTATION_DOC_BYTES);
    // The stubs above are keyed on the exact bucket/key pair, so reading an artifact from the
    // wrong bucket would not match; these verifications state that expectation explicitly.
    verifyRead(PUBLIC_BUCKET, bucketProperties.getCertPath());
    verifyRead(PRIVATE_BUCKET, bucketProperties.getKmsEncryptedDataKeyPath());
    verifyRead(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath());
    verifyRead(PUBLIC_BUCKET, bucketProperties.getAttestationDocPath());

    List<String> nonCertKeys =
        List.of(
            bucketProperties.getKmsEncryptedDataKeyPath(),
            bucketProperties.getAesEncryptedPrivateKeyPath(),
            bucketProperties.getAttestationDocPath());
    for (String nonCertKey : nonCertKeys) {
      InOrder inOrder = inOrder(s3Client);
      inOrder
          .verify(s3Client)
          .getObject(
              getRequestWithKey(bucketProperties.getCertPath()), any(ResponseTransformer.class));
      inOrder
          .verify(s3Client)
          .getObject(getRequestWithKey(nonCertKey), any(ResponseTransformer.class));
    }
    verifyNoInteractions(metrics);
  }

  @Test
  public void getKeyBackup_noArtifacts_throwsKeyBackupNotFound() {
    stubMissing(PUBLIC_BUCKET, bucketProperties.getCertPath());
    stubMissing(PRIVATE_BUCKET, bucketProperties.getKmsEncryptedDataKeyPath());
    stubMissing(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath());
    stubMissing(PUBLIC_BUCKET, bucketProperties.getAttestationDocPath());

    assertThrows(KeyBackupNotFoundException.class, () -> storage.getKeyBackup());
    verifyNoInteractions(metrics);
  }

  @Test
  public void getKeyBackup_certMissingOthersPresent_throwsKeyBackupPartiallyWritten() {
    stubAllPresentExcept(PUBLIC_BUCKET, bucketProperties.getCertPath());

    assertThrows(KeyBackupPartiallyWrittenException.class, () -> storage.getKeyBackup());
    verifyNoInteractions(metrics);
  }

  @Test
  public void getKeyBackup_certPresentKmsDataKeyMissing_throwsKeyBackupIncomplete() {
    stubAllPresentExcept(PRIVATE_BUCKET, bucketProperties.getKmsEncryptedDataKeyPath());

    assertThrows(KeyBackupIncompleteException.class, () -> storage.getKeyBackup());
    verifyNoInteractions(metrics);
  }

  @Test
  public void getKeyBackup_certPresentPrivateKeyMissing_throwsKeyBackupIncomplete() {
    stubAllPresentExcept(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath());

    assertThrows(KeyBackupIncompleteException.class, () -> storage.getKeyBackup());
    verifyNoInteractions(metrics);
  }

  @Test
  public void getKeyBackup_certPresentAttestationDocMissing_throwsKeyBackupIncomplete() {
    stubAllPresentExcept(PUBLIC_BUCKET, bucketProperties.getAttestationDocPath());

    assertThrows(KeyBackupIncompleteException.class, () -> storage.getKeyBackup());
    verifyNoInteractions(metrics);
  }

  @Test
  public void getKeyBackup_sdkException_recordsMetricAndThrowsAccessFailed() {
    when(s3Client.getObject(
            eq(getObjectRequest(PUBLIC_BUCKET, bucketProperties.getCertPath())),
            any(ResponseTransformer.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(KeyBackupAccessFailedException.class, () -> storage.getKeyBackup());
    verify(metrics).recordEvent(MbsEvent.S3_FETCH_FAILED);
  }

  /**
   * The certificate is the completion sentinel {@code getKeyBackup()} keys its partial-write
   * classification on, so it must become visible only after every other artifact is durable.
   */
  @Test
  public void putKeyBackup_writesAllArtifactsToCorrectLocationsWithCertificateLast()
      throws Exception {
    storage.putKeyBackup(sampleKeyBackup());

    ArgumentCaptor<PutObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    ArgumentCaptor<RequestBody> bodyCaptor = ArgumentCaptor.forClass(RequestBody.class);
    verify(s3Client, times(4)).putObject(requestCaptor.capture(), bodyCaptor.capture());

    Map<String, PutObjectRequest> requestsByKey = new HashMap<>();
    Map<String, byte[]> contentsByKey = new HashMap<>();
    List<PutObjectRequest> requests = requestCaptor.getAllValues();
    List<RequestBody> bodies = bodyCaptor.getAllValues();
    for (int i = 0; i < requests.size(); i++) {
      requestsByKey.put(requests.get(i).key(), requests.get(i));
      contentsByKey.put(requests.get(i).key(), readContent(bodies.get(i)));
    }

    List<String> nonCertKeys =
        List.of(
            bucketProperties.getKmsEncryptedDataKeyPath(),
            bucketProperties.getAesEncryptedPrivateKeyPath(),
            bucketProperties.getAttestationDocPath());
    assertThat(requestsByKey.keySet())
        .containsExactly(
            bucketProperties.getCertPath(),
            bucketProperties.getKmsEncryptedDataKeyPath(),
            bucketProperties.getAesEncryptedPrivateKeyPath(),
            bucketProperties.getAttestationDocPath());
    assertPut(
        requestsByKey, contentsByKey, bucketProperties.getCertPath(), PUBLIC_BUCKET, CERT_BYTES);
    assertPut(
        requestsByKey,
        contentsByKey,
        bucketProperties.getKmsEncryptedDataKeyPath(),
        PRIVATE_BUCKET,
        KMS_ENCRYPTED_DATA_KEY_BYTES);
    assertPut(
        requestsByKey,
        contentsByKey,
        bucketProperties.getAesEncryptedPrivateKeyPath(),
        PRIVATE_BUCKET,
        AEAD_ENCRYPTED_PRIVATE_KEY_BYTES);
    assertPut(
        requestsByKey,
        contentsByKey,
        bucketProperties.getAttestationDocPath(),
        PUBLIC_BUCKET,
        ATTESTATION_DOC_BYTES);

    for (String nonCertKey : nonCertKeys) {
      // A fresh InOrder per artifact pins "cert after this artifact" without over-specifying the
      // relative order of the three non-sentinel writes.
      InOrder inOrder = inOrder(s3Client);
      inOrder.verify(s3Client).putObject(requestWithKey(nonCertKey), any(RequestBody.class));
      inOrder
          .verify(s3Client)
          .putObject(requestWithKey(bucketProperties.getCertPath()), any(RequestBody.class));
    }
    verifyNoInteractions(metrics);
  }

  @Test
  public void putKeyBackup_sdkException_recordsMetricAndThrowsAccessFailed() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(SdkClientException.create("S3 write failure"));

    assertThrows(
        KeyBackupAccessFailedException.class, () -> storage.putKeyBackup(sampleKeyBackup()));
    verify(metrics).recordEvent(MbsEvent.S3_WRITE_FAILED);
  }

  @Test
  public void acquireLock_success() throws Exception {
    storage.acquireLock();

    ArgumentCaptor<PutObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    ArgumentCaptor<RequestBody> bodyCaptor = ArgumentCaptor.forClass(RequestBody.class);
    verify(s3Client).putObject(requestCaptor.capture(), bodyCaptor.capture());
    assertThat(requestCaptor.getValue().bucket()).isEqualTo(PRIVATE_BUCKET);
    assertThat(requestCaptor.getValue().key()).isEqualTo(bucketProperties.getLockPath());
    assertThat(requestCaptor.getValue().cacheControl()).isEqualTo("no-cache");
    assertThat(requestCaptor.getValue().overrideConfiguration().isPresent()).isTrue();
    assertThat(
            requestCaptor.getValue().overrideConfiguration().get().headers().get("If-None-Match"))
        .containsExactly("*");
    byte[] content = bodyCaptor.getValue().contentStreamProvider().newStream().readAllBytes();
    assertThat(new String(content, StandardCharsets.UTF_8)).isEqualTo(TEST_INSTANCE_ID);
  }

  @Test
  public void acquireLock_lockFileAlreadyExists_throwsStorageAlreadyLockedException() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(
            software.amazon.awssdk.services.s3.model.S3Exception.builder()
                .statusCode(412)
                .message("PreconditionFailed")
                .build());

    assertThrows(StorageAlreadyLockedException.class, () -> storage.acquireLock());
  }

  @Test
  public void acquireLock_s3WriteFailure_recordsMetricAndThrowsStorageException() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(KeyBackupStorageException.class, () -> storage.acquireLock());
    verify(metrics).recordEvent(MbsEvent.S3_WRITE_FAILED);
  }

  @Test
  public void releaseLock_success() throws Exception {
    storage.releaseLock();

    ArgumentCaptor<software.amazon.awssdk.services.s3.model.DeleteObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(software.amazon.awssdk.services.s3.model.DeleteObjectRequest.class);
    verify(s3Client).deleteObject(requestCaptor.capture());
    assertThat(requestCaptor.getValue().bucket()).isEqualTo(PRIVATE_BUCKET);
    assertThat(requestCaptor.getValue().key()).isEqualTo(bucketProperties.getLockPath());
  }

  @Test
  public void releaseLock_s3Failure_recordsMetricAndThrowsAccessFailed() {
    when(s3Client.deleteObject(
            any(software.amazon.awssdk.services.s3.model.DeleteObjectRequest.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(KeyBackupAccessFailedException.class, () -> storage.releaseLock());
    verify(metrics).recordEvent(MbsEvent.S3_WRITE_FAILED);
  }

  private static KeyBackup sampleKeyBackup() {
    return new KeyBackup(
        CERT_BYTES,
        KMS_ENCRYPTED_DATA_KEY_BYTES,
        AEAD_ENCRYPTED_PRIVATE_KEY_BYTES,
        ATTESTATION_DOC_BYTES);
  }

  private static GetObjectRequest getObjectRequest(String bucket, String key) {
    return GetObjectRequest.builder().bucket(bucket).key(key).build();
  }

  /** Matches any {@link PutObjectRequest} targeting {@code key}, regardless of bucket. */
  private static PutObjectRequest requestWithKey(String key) {
    return argThat(request -> request != null && key.equals(request.key()));
  }

  /** Matches any {@link GetObjectRequest} targeting {@code key}, regardless of bucket. */
  private static GetObjectRequest getRequestWithKey(String key) {
    return argThat(request -> request != null && key.equals(request.key()));
  }

  private void stubPresent(String bucket, String key, byte[] content) {
    when(s3Client.getObject(eq(getObjectRequest(bucket, key)), any(ResponseTransformer.class)))
        .thenReturn(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), content));
  }

  /** A missing object surfaces from S3 as {@link NoSuchKeyException}, not as a read failure. */
  private void stubMissing(String bucket, String key) {
    when(s3Client.getObject(eq(getObjectRequest(bucket, key)), any(ResponseTransformer.class)))
        .thenThrow(NoSuchKeyException.builder().build());
  }

  private void stubAllPresent() {
    stubPresent(PUBLIC_BUCKET, bucketProperties.getCertPath(), CERT_BYTES);
    stubPresent(
        PRIVATE_BUCKET,
        bucketProperties.getKmsEncryptedDataKeyPath(),
        KMS_ENCRYPTED_DATA_KEY_BYTES);
    stubPresent(
        PRIVATE_BUCKET,
        bucketProperties.getAesEncryptedPrivateKeyPath(),
        AEAD_ENCRYPTED_PRIVATE_KEY_BYTES);
    stubPresent(PUBLIC_BUCKET, bucketProperties.getAttestationDocPath(), ATTESTATION_DOC_BYTES);
  }

  /** The second stubbing of the same bucket/key pair replaces the first, leaving it missing. */
  private void stubAllPresentExcept(String missingBucket, String missingKey) {
    stubAllPresent();
    stubMissing(missingBucket, missingKey);
  }

  private void verifyRead(String bucket, String key) {
    verify(s3Client).getObject(eq(getObjectRequest(bucket, key)), any(ResponseTransformer.class));
  }

  private void assertPut(
      Map<String, PutObjectRequest> requestsByKey,
      Map<String, byte[]> contentsByKey,
      String key,
      String expectedBucket,
      byte[] expectedContent) {
    PutObjectRequest request = requestsByKey.get(key);
    assertThat(request).isNotNull();
    assertThat(request.bucket()).isEqualTo(expectedBucket);
    assertThat(request.checksumAlgorithm()).isEqualTo(ChecksumAlgorithm.SHA256);
    assertThat(request.cacheControl()).isEqualTo(bucketProperties.getCacheControl());
    assertThat(contentsByKey.get(key)).isEqualTo(expectedContent);
  }

  private static byte[] readContent(RequestBody body) throws IOException {
    return body.contentStreamProvider().newStream().readAllBytes();
  }
}
