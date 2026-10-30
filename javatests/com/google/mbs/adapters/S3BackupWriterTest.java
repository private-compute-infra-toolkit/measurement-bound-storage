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
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.BackupAccessFailedException;
import com.google.mbs.domain.BackupAlreadyExistsException;
import com.google.mbs.domain.BackupStorageAlreadyLockedException;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.SelfSignedBundleBackup;
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
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

@RunWith(JUnit4.class)
public class S3BackupWriterTest {

  private static final String PUBLIC_BUCKET = "public-bucket";
  private static final String PRIVATE_BUCKET = "private-bucket";
  private static final String TEST_INSTANCE_ID = "i-testinstance123";
  private static final int TEST_EPOCH = 0;
  private static final CrossSignedCertificateId TEST_CROSS_SIGNED_ID =
      new CrossSignedCertificateId(0, 1);

  private static final byte[] CERT_BYTES = "cert-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] CROSS_SIGNED_CERT_BYTES =
      "cross-signed-cert-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] KMS_ENCRYPTED_DATA_KEY_BYTES =
      "kms-encrypted-data-key-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] AEAD_ENCRYPTED_PRIVATE_KEY_BYTES =
      "aead-encrypted-private-key-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] ATTESTATION_DOC_BYTES =
      "attestation-doc-bytes".getBytes(StandardCharsets.UTF_8);

  @Mock private S3Client s3Client;

  private BackupBucketProperties bucketProperties;
  private S3BackupWriter writer;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    bucketProperties = new BackupBucketPropertiesFactory(PUBLIC_BUCKET, PRIVATE_BUCKET).create();
    writer = new S3BackupWriter(s3Client, bucketProperties, TEST_INSTANCE_ID);
  }

  /**
   * The certificate is the completion sentinel readers key their partial-write classification on,
   * so it must become visible only after every other artifact is durable.
   */
  @Test
  public void writeSelfSignedBundleBackup_writesAllArtifactsToCorrectLocationsWithCertificateLast()
      throws Exception {
    writer.writeSelfSignedBundleBackup(TEST_EPOCH, sampleSelfSignedBundleBackup());

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
            S3BackupPaths.getKmsEncryptedDataKeyPath(TEST_EPOCH),
            S3BackupPaths.getAesEncryptedPrivateKeyPath(TEST_EPOCH),
            S3BackupPaths.getAttestationDocPath(TEST_EPOCH));
    assertThat(requestsByKey.keySet())
        .containsExactly(
            S3BackupPaths.getRootCertPath(TEST_EPOCH),
            S3BackupPaths.getKmsEncryptedDataKeyPath(TEST_EPOCH),
            S3BackupPaths.getAesEncryptedPrivateKeyPath(TEST_EPOCH),
            S3BackupPaths.getAttestationDocPath(TEST_EPOCH));
    assertPut(
        requestsByKey,
        contentsByKey,
        S3BackupPaths.getRootCertPath(TEST_EPOCH),
        PUBLIC_BUCKET,
        CERT_BYTES);
    assertPut(
        requestsByKey,
        contentsByKey,
        S3BackupPaths.getKmsEncryptedDataKeyPath(TEST_EPOCH),
        PRIVATE_BUCKET,
        KMS_ENCRYPTED_DATA_KEY_BYTES);
    assertPut(
        requestsByKey,
        contentsByKey,
        S3BackupPaths.getAesEncryptedPrivateKeyPath(TEST_EPOCH),
        PRIVATE_BUCKET,
        AEAD_ENCRYPTED_PRIVATE_KEY_BYTES);
    assertPut(
        requestsByKey,
        contentsByKey,
        S3BackupPaths.getAttestationDocPath(TEST_EPOCH),
        PUBLIC_BUCKET,
        ATTESTATION_DOC_BYTES);

    for (String nonCertKey : nonCertKeys) {
      InOrder inOrder = inOrder(s3Client);
      inOrder.verify(s3Client).putObject(requestWithKey(nonCertKey), any(RequestBody.class));
      inOrder
          .verify(s3Client)
          .putObject(
              requestWithKey(S3BackupPaths.getRootCertPath(TEST_EPOCH)), any(RequestBody.class));
    }
  }

  @Test
  public void writeSelfSignedBundleBackup_objectAlreadyExists_throwsAlreadyExistsException() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(S3Exception.builder().statusCode(412).message("PreconditionFailed").build());

    assertThrows(
        BackupAlreadyExistsException.class,
        () -> writer.writeSelfSignedBundleBackup(TEST_EPOCH, sampleSelfSignedBundleBackup()));
  }

  @Test
  public void writeSelfSignedBundleBackup_sdkException_throwsAccessFailed() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(SdkClientException.create("S3 write failure"));

    assertThrows(
        BackupAccessFailedException.class,
        () -> writer.writeSelfSignedBundleBackup(TEST_EPOCH, sampleSelfSignedBundleBackup()));
  }

  @Test
  public void writeCrossSignedCertificateBackup_writesToPublicBucketWithExpectedHeaders()
      throws Exception {
    writer.writeCrossSignedCertificateBackup(
        TEST_CROSS_SIGNED_ID, new CrossSignedCertificateBackup(CROSS_SIGNED_CERT_BYTES));

    ArgumentCaptor<PutObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    ArgumentCaptor<RequestBody> bodyCaptor = ArgumentCaptor.forClass(RequestBody.class);
    verify(s3Client).putObject(requestCaptor.capture(), bodyCaptor.capture());

    String expectedKey = S3BackupPaths.getCrossSignedCertificatePath(TEST_CROSS_SIGNED_ID);
    Map<String, PutObjectRequest> requestsByKey =
        Map.of(requestCaptor.getValue().key(), requestCaptor.getValue());
    Map<String, byte[]> contentsByKey =
        Map.of(requestCaptor.getValue().key(), readContent(bodyCaptor.getValue()));

    assertPut(requestsByKey, contentsByKey, expectedKey, PUBLIC_BUCKET, CROSS_SIGNED_CERT_BYTES);
  }

  @Test
  public void writeCrossSignedCertificateBackup_alreadyExists_throwsAlreadyExistsException() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(S3Exception.builder().statusCode(412).message("PreconditionFailed").build());

    assertThrows(
        BackupAlreadyExistsException.class,
        () ->
            writer.writeCrossSignedCertificateBackup(
                TEST_CROSS_SIGNED_ID, new CrossSignedCertificateBackup(CROSS_SIGNED_CERT_BYTES)));
  }

  @Test
  public void writeCrossSignedCertificateBackup_sdkException_throwsAccessFailed() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(SdkClientException.create("S3 write failure"));

    assertThrows(
        BackupAccessFailedException.class,
        () ->
            writer.writeCrossSignedCertificateBackup(
                TEST_CROSS_SIGNED_ID, new CrossSignedCertificateBackup(CROSS_SIGNED_CERT_BYTES)));
  }

  @Test
  public void acquireLock_success() throws Exception {
    writer.acquireLock();

    ArgumentCaptor<PutObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    ArgumentCaptor<RequestBody> bodyCaptor = ArgumentCaptor.forClass(RequestBody.class);
    verify(s3Client).putObject(requestCaptor.capture(), bodyCaptor.capture());
    assertThat(requestCaptor.getValue().bucket()).isEqualTo(PRIVATE_BUCKET);
    assertThat(requestCaptor.getValue().key()).isEqualTo(S3BackupPaths.getLockPath());
    assertThat(requestCaptor.getValue().cacheControl()).isEqualTo("no-cache");
    assertThat(requestCaptor.getValue().overrideConfiguration().isPresent()).isTrue();
    assertThat(
            requestCaptor.getValue().overrideConfiguration().get().headers().get("If-None-Match"))
        .containsExactly("*");
    byte[] content = bodyCaptor.getValue().contentStreamProvider().newStream().readAllBytes();
    assertThat(new String(content, StandardCharsets.UTF_8)).isEqualTo(TEST_INSTANCE_ID);
  }

  @Test
  public void acquireLock_alreadyLocked_throwsBackupStorageAlreadyLockedException() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(S3Exception.builder().statusCode(412).message("PreconditionFailed").build());

    assertThrows(BackupStorageAlreadyLockedException.class, () -> writer.acquireLock());
  }

  @Test
  public void acquireLock_s3WriteFailure_throwsAccessFailed() {
    when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(BackupAccessFailedException.class, () -> writer.acquireLock());
  }

  @Test
  public void releaseLock_success() throws Exception {
    writer.releaseLock();

    ArgumentCaptor<DeleteObjectRequest> requestCaptor =
        ArgumentCaptor.forClass(DeleteObjectRequest.class);
    verify(s3Client).deleteObject(requestCaptor.capture());
    assertThat(requestCaptor.getValue().bucket()).isEqualTo(PRIVATE_BUCKET);
    assertThat(requestCaptor.getValue().key()).isEqualTo(S3BackupPaths.getLockPath());
  }

  @Test
  public void releaseLock_s3Failure_throwsAccessFailed() {
    when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(BackupAccessFailedException.class, () -> writer.releaseLock());
  }

  private static SelfSignedBundleBackup sampleSelfSignedBundleBackup() {
    return new SelfSignedBundleBackup(
        CERT_BYTES,
        KMS_ENCRYPTED_DATA_KEY_BYTES,
        AEAD_ENCRYPTED_PRIVATE_KEY_BYTES,
        ATTESTATION_DOC_BYTES);
  }

  private static PutObjectRequest requestWithKey(String key) {
    return argThat(request -> request != null && key.equals(request.key()));
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
    assertThat(request.overrideConfiguration().isPresent()).isTrue();
    assertThat(request.overrideConfiguration().get().headers().get("If-None-Match"))
        .containsExactly("*");
    assertThat(contentsByKey.get(key)).isEqualTo(expectedContent);
  }

  private static byte[] readContent(RequestBody body) throws IOException {
    return body.contentStreamProvider().newStream().readAllBytes();
  }
}
