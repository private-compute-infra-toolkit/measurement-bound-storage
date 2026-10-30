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
import static org.mockito.Mockito.when;

import com.google.mbs.domain.BackupAccessFailedException;
import com.google.mbs.domain.BackupIncompleteException;
import com.google.mbs.domain.BackupNotFoundException;
import com.google.mbs.domain.BackupPartiallyWrittenException;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.SelfSignedBundleBackup;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

@RunWith(JUnit4.class)
public class S3BackupReaderTest {

  private static final String PUBLIC_BUCKET = "public-bucket";
  private static final String PRIVATE_BUCKET = "private-bucket";
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
  private S3BackupReader reader;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    bucketProperties = new BackupBucketPropertiesFactory(PUBLIC_BUCKET, PRIVATE_BUCKET).create();
    reader = new S3BackupReader(s3Client, bucketProperties);
  }

  @Test
  public void readSelfSignedBundleBackup_allArtifactsPresent_returnsAggregate() throws Exception {
    stubAllPresent();

    SelfSignedBundleBackup backup = reader.readSelfSignedBundleBackup(TEST_EPOCH);

    assertThat(backup.certBytes()).isEqualTo(CERT_BYTES);
    assertThat(backup.kmsEncryptedDataKey()).isEqualTo(KMS_ENCRYPTED_DATA_KEY_BYTES);
    assertThat(backup.aeadEncryptedPrivateKey()).isEqualTo(AEAD_ENCRYPTED_PRIVATE_KEY_BYTES);
    assertThat(backup.attestationDocBytes()).isEqualTo(ATTESTATION_DOC_BYTES);

    verifyRead(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(TEST_EPOCH));
    verifyRead(PRIVATE_BUCKET, S3BackupPaths.getKmsEncryptedDataKeyPath(TEST_EPOCH));
    verifyRead(PRIVATE_BUCKET, S3BackupPaths.getAesEncryptedPrivateKeyPath(TEST_EPOCH));
    verifyRead(PUBLIC_BUCKET, S3BackupPaths.getAttestationDocPath(TEST_EPOCH));
  }

  @Test
  public void readSelfSignedBundleBackup_allArtifactsMissing_throwsBackupNotFound() {
    when(s3Client.getObject(any(GetObjectRequest.class), any(ResponseTransformer.class)))
        .thenThrow(NoSuchKeyException.builder().build());

    assertThrows(
        BackupNotFoundException.class, () -> reader.readSelfSignedBundleBackup(TEST_EPOCH));
  }

  @Test
  public void readSelfSignedBundleBackup_certMissing_throwsBackupPartiallyWritten() {
    stubAllPresentExcept(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(TEST_EPOCH));

    assertThrows(
        BackupPartiallyWrittenException.class, () -> reader.readSelfSignedBundleBackup(TEST_EPOCH));
  }

  @Test
  public void readSelfSignedBundleBackup_nonCertArtifactMissing_throwsBackupIncomplete() {
    stubAllPresentExcept(PRIVATE_BUCKET, S3BackupPaths.getKmsEncryptedDataKeyPath(TEST_EPOCH));

    assertThrows(
        BackupIncompleteException.class, () -> reader.readSelfSignedBundleBackup(TEST_EPOCH));
  }

  @Test
  public void readSelfSignedBundleBackup_sdkException_throwsAccessFailed() {
    when(s3Client.getObject(
            eq(getObjectRequest(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(TEST_EPOCH))),
            any(ResponseTransformer.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(
        BackupAccessFailedException.class, () -> reader.readSelfSignedBundleBackup(TEST_EPOCH));
  }

  @Test
  public void readCrossSignedCertificateBackup_present_returnsBackup() throws Exception {
    String key = S3BackupPaths.getCrossSignedCertificatePath(TEST_CROSS_SIGNED_ID);
    stubPresent(PUBLIC_BUCKET, key, CROSS_SIGNED_CERT_BYTES);

    CrossSignedCertificateBackup backup =
        reader.readCrossSignedCertificateBackup(TEST_CROSS_SIGNED_ID);

    assertThat(backup.certBytes()).isEqualTo(CROSS_SIGNED_CERT_BYTES);
    verifyRead(PUBLIC_BUCKET, key);
  }

  @Test
  public void readCrossSignedCertificateBackup_missing_throwsBackupNotFound() {
    stubMissing(PUBLIC_BUCKET, S3BackupPaths.getCrossSignedCertificatePath(TEST_CROSS_SIGNED_ID));

    assertThrows(
        BackupNotFoundException.class,
        () -> reader.readCrossSignedCertificateBackup(TEST_CROSS_SIGNED_ID));
  }

  @Test
  public void readCrossSignedCertificateBackup_sdkException_throwsAccessFailed() {
    when(s3Client.getObject(
            eq(
                getObjectRequest(
                    PUBLIC_BUCKET,
                    S3BackupPaths.getCrossSignedCertificatePath(TEST_CROSS_SIGNED_ID))),
            any(ResponseTransformer.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(
        BackupAccessFailedException.class,
        () -> reader.readCrossSignedCertificateBackup(TEST_CROSS_SIGNED_ID));
  }

  private static GetObjectRequest getObjectRequest(String bucket, String key) {
    return GetObjectRequest.builder().bucket(bucket).key(key).build();
  }

  private void stubPresent(String bucket, String key, byte[] content) {
    when(s3Client.getObject(eq(getObjectRequest(bucket, key)), any(ResponseTransformer.class)))
        .thenReturn(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), content));
  }

  private void stubMissing(String bucket, String key) {
    when(s3Client.getObject(eq(getObjectRequest(bucket, key)), any(ResponseTransformer.class)))
        .thenThrow(NoSuchKeyException.builder().build());
  }

  private void stubAllPresent() {
    stubPresent(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(TEST_EPOCH), CERT_BYTES);
    stubPresent(
        PRIVATE_BUCKET,
        S3BackupPaths.getKmsEncryptedDataKeyPath(TEST_EPOCH),
        KMS_ENCRYPTED_DATA_KEY_BYTES);
    stubPresent(
        PRIVATE_BUCKET,
        S3BackupPaths.getAesEncryptedPrivateKeyPath(TEST_EPOCH),
        AEAD_ENCRYPTED_PRIVATE_KEY_BYTES);
    stubPresent(
        PUBLIC_BUCKET, S3BackupPaths.getAttestationDocPath(TEST_EPOCH), ATTESTATION_DOC_BYTES);
  }

  private void stubAllPresentExcept(String missingBucket, String missingKey) {
    stubAllPresent();
    stubMissing(missingBucket, missingKey);
  }

  private void verifyRead(String bucket, String key) {
    verify(s3Client).getObject(eq(getObjectRequest(bucket, key)), any(ResponseTransformer.class));
  }
}
