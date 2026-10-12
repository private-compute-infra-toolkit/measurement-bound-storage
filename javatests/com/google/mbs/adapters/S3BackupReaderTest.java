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

import com.google.mbs.KeyBackupBucketPropertiesFactory;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.KeyBackupIncompleteException;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupPartiallyWrittenException;
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

  private static final byte[] CERT_BYTES = "cert-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] KMS_ENCRYPTED_DATA_KEY_BYTES =
      "kms-encrypted-data-key-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] AEAD_ENCRYPTED_PRIVATE_KEY_BYTES =
      "aead-encrypted-private-key-bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] ATTESTATION_DOC_BYTES =
      "attestation-doc-bytes".getBytes(StandardCharsets.UTF_8);

  @Mock private S3Client s3Client;

  private KeyBackupBucketProperties bucketProperties;
  private S3BackupReader reader;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    bucketProperties = new KeyBackupBucketPropertiesFactory(PUBLIC_BUCKET, PRIVATE_BUCKET).create();
    reader = new S3BackupReader(s3Client, bucketProperties);
  }

  @Test
  public void read_allArtifactsPresent_returnsAggregate() throws Exception {
    stubAllPresent();

    KeyBackup keyBackup = reader.read(TEST_EPOCH);

    assertThat(keyBackup.certBytes()).isEqualTo(CERT_BYTES);
    assertThat(keyBackup.kmsEncryptedDataKey()).isEqualTo(KMS_ENCRYPTED_DATA_KEY_BYTES);
    assertThat(keyBackup.aeadEncryptedPrivateKey()).isEqualTo(AEAD_ENCRYPTED_PRIVATE_KEY_BYTES);
    assertThat(keyBackup.attestationDocBytes()).isEqualTo(ATTESTATION_DOC_BYTES);

    verifyRead(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(TEST_EPOCH));
    verifyRead(PRIVATE_BUCKET, S3BackupPaths.getKmsEncryptedDataKeyPath(TEST_EPOCH));
    verifyRead(PRIVATE_BUCKET, S3BackupPaths.getAesEncryptedPrivateKeyPath(TEST_EPOCH));
    verifyRead(PUBLIC_BUCKET, S3BackupPaths.getAttestationDocPath(TEST_EPOCH));
  }

  @Test
  public void read_allArtifactsMissing_throwsKeyBackupNotFound() {
    when(s3Client.getObject(any(GetObjectRequest.class), any(ResponseTransformer.class)))
        .thenThrow(NoSuchKeyException.builder().build());

    assertThrows(KeyBackupNotFoundException.class, () -> reader.read(TEST_EPOCH));
  }

  @Test
  public void read_certMissing_throwsKeyBackupPartiallyWritten() {
    stubAllPresentExcept(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(TEST_EPOCH));

    assertThrows(KeyBackupPartiallyWrittenException.class, () -> reader.read(TEST_EPOCH));
  }

  @Test
  public void read_nonCertArtifactMissing_throwsKeyBackupIncomplete() {
    stubAllPresentExcept(PRIVATE_BUCKET, S3BackupPaths.getKmsEncryptedDataKeyPath(TEST_EPOCH));

    assertThrows(KeyBackupIncompleteException.class, () -> reader.read(TEST_EPOCH));
  }

  @Test
  public void read_sdkException_throwsAccessFailed() {
    when(s3Client.getObject(
            eq(getObjectRequest(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(TEST_EPOCH))),
            any(ResponseTransformer.class)))
        .thenThrow(SdkClientException.create("S3 network failure"));

    assertThrows(KeyBackupAccessFailedException.class, () -> reader.read(TEST_EPOCH));
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
