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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.mbs.KeyBackupBucketPropertiesFactory;
import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.CrossSignedCertHandle;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.StorageAlreadyLockedException;
import com.google.mbs.domain.StorageSnapshot;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.S3Object;

@RunWith(JUnit4.class)
public class S3KeyBackupStorageTest {

  private static final String PUBLIC_BUCKET = "public-bucket";
  private static final String PRIVATE_BUCKET = "private-bucket";
  private static final CrossSignedCertificateId CROSS_SIGNED_ID =
      new CrossSignedCertificateId(0, 1);
  private static final KeyBackup KEY_BACKUP =
      new KeyBackup(
          "cert".getBytes(StandardCharsets.UTF_8),
          "kmsKey".getBytes(StandardCharsets.UTF_8),
          "privKey".getBytes(StandardCharsets.UTF_8),
          "attestation".getBytes(StandardCharsets.UTF_8));
  private static final CrossSignedCertificateBackup CROSS_SIGNED_BACKUP =
      new CrossSignedCertificateBackup("cross-signed-cert".getBytes(StandardCharsets.UTF_8));

  @Mock private S3Client s3Client;
  @Mock private S3BackupReader reader;
  @Mock private S3BackupWriter writer;

  private KeyBackupBucketProperties bucketProperties;
  private S3KeyBackupStorage storage;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    bucketProperties = new KeyBackupBucketPropertiesFactory(PUBLIC_BUCKET, PRIVATE_BUCKET).create();
    when(s3Client.listObjectsV2Paginator(any(ListObjectsV2Request.class))).thenCallRealMethod();
    storage = new S3KeyBackupStorage(s3Client, bucketProperties, reader, writer);
  }

  @Test
  public void getSnapshot_allArtifactsPresent_populatesCompleteBackupHandle() throws Exception {
    stubListings(
        List.of(S3BackupPaths.getRootCertPath(0), S3BackupPaths.getAttestationDocPath(0)),
        List.of(
            S3BackupPaths.getKmsEncryptedDataKeyPath(0),
            S3BackupPaths.getAesEncryptedPrivateKeyPath(0)));

    when(reader.read(0)).thenReturn(KEY_BACKUP);

    StorageSnapshot snapshot = storage.getSnapshot();
    BackupHandle handle = snapshot.getBundleHandle(0);

    assertThat(handle).isInstanceOf(BackupHandle.Complete.class);
    assertThat(handle.epoch()).isEqualTo(0);
    assertThat(((BackupHandle.Complete) handle).read()).isSameInstanceAs(KEY_BACKUP);
    verify(reader).read(0);
  }

  @Test
  public void getSnapshot_certMissingOthersPresent_populatesPartiallyWrittenBackupHandle()
      throws Exception {
    stubListings(
        List.of(S3BackupPaths.getAttestationDocPath(0)),
        List.of(
            S3BackupPaths.getKmsEncryptedDataKeyPath(0),
            S3BackupPaths.getAesEncryptedPrivateKeyPath(0)));

    StorageSnapshot snapshot = storage.getSnapshot();
    BackupHandle handle = snapshot.getBundleHandle(0);

    assertThat(handle).isInstanceOf(BackupHandle.PartiallyWritten.class);
    BackupHandle.PartiallyWritten partiallyWritten = (BackupHandle.PartiallyWritten) handle;
    assertThat(partiallyWritten.epoch()).isEqualTo(0);
    assertThat(partiallyWritten.missingKeys()).containsExactly(S3BackupPaths.ROOT_CERT_FILE);
  }

  @Test
  public void getSnapshot_certPresentSomePrivateKeysMissing_populatesIncompleteBackupHandle()
      throws Exception {
    stubListings(
        List.of(S3BackupPaths.getRootCertPath(0), S3BackupPaths.getAttestationDocPath(0)),
        List.of(S3BackupPaths.getKmsEncryptedDataKeyPath(0)));

    StorageSnapshot snapshot = storage.getSnapshot();
    BackupHandle handle = snapshot.getBundleHandle(0);

    assertThat(handle).isInstanceOf(BackupHandle.Incomplete.class);
    BackupHandle.Incomplete incomplete = (BackupHandle.Incomplete) handle;
    assertThat(incomplete.epoch()).isEqualTo(0);
    assertThat(incomplete.missingKeys())
        .containsExactly(S3BackupPaths.AES_ENCRYPTED_PRIVATE_KEY_FILE);
  }

  @Test
  public void getSnapshot_ignoresLockFileAndUnrecognizedKeys() throws Exception {
    stubListings(
        List.of(
            "public/invalid-epoch/root_certificate.pem",
            "public/00/root_certificate.pem",
            "public/+0/root_certificate.pem",
            "public/extra/segment/root_certificate.pem",
            "public/cross-signed/invalid/cross_signed_certificate.pem",
            "public/cross-signed/0_0/cross_signed_certificate.pem",
            "public/cross-signed/00_1/cross_signed_certificate.pem",
            "public/cross-signed/+0_1/cross_signed_certificate.pem",
            "public/cross-signed/0_1/other.pem",
            "public/cross-signed/0_1/extra/cross_signed_certificate.pem",
            S3BackupPaths.getRootCertPath(0),
            S3BackupPaths.getAttestationDocPath(0),
            S3BackupPaths.getCrossSignedCertPath(CROSS_SIGNED_ID)),
        List.of(
            S3BackupPaths.getLockPath(),
            "private/not_a_number/root_data_key.kms",
            "private/00/root_data_key.kms",
            "private/cross-signed/1_0/cross_signed_certificate.pem",
            S3BackupPaths.getKmsEncryptedDataKeyPath(0),
            S3BackupPaths.getAesEncryptedPrivateKeyPath(0)));

    StorageSnapshot snapshot = storage.getSnapshot();
    BackupHandle handle = snapshot.getBundleHandle(0);
    CrossSignedCertHandle crossSignedHandle = snapshot.getCrossSignedCertHandle(CROSS_SIGNED_ID);

    assertThat(handle).isInstanceOf(BackupHandle.Complete.class);
    assertThat(handle.epoch()).isEqualTo(0);
    assertThat(snapshot.bundleHandles().keySet()).containsExactly(0);
    assertThat(crossSignedHandle).isInstanceOf(CrossSignedCertHandle.Complete.class);
    assertThat(crossSignedHandle.id()).isEqualTo(CROSS_SIGNED_ID);
    assertThat(snapshot.crossSignedCertHandles().keySet()).containsExactly(CROSS_SIGNED_ID);
  }

  @Test
  public void getSnapshot_unchangedETags_reusesSameCompleteBackupHandleInstance() throws Exception {
    stubCompleteListingWithETag("etag-v1");

    BackupHandle handleBefore = storage.getSnapshot().getBundleHandle(0);
    BackupHandle handleAfter = storage.getSnapshot().getBundleHandle(0);

    assertThat(handleAfter).isSameInstanceAs(handleBefore);
    verifyNoInteractions(reader);
  }

  @Test
  public void getSnapshot_changedETag_createsNewCompleteBackupHandleInstance() throws Exception {
    stubCompleteListingWithETag("etag-v1");
    BackupHandle handleBefore = storage.getSnapshot().getBundleHandle(0);

    stubCompleteListingWithETag("etag-v2");
    BackupHandle handleAfter = storage.getSnapshot().getBundleHandle(0);

    assertThat(handleAfter).isNotSameInstanceAs(handleBefore);
    verifyNoInteractions(reader);
  }

  @Test
  public void getSnapshot_removedEpoch_evictsBackupHandleFromSubsequentSnapshot() throws Exception {
    stubCompleteListingWithETag("etag-v1");
    assertThat(storage.getSnapshot().getBundleHandle(0)).isInstanceOf(BackupHandle.Complete.class);

    stubListings(List.of(), List.of());
    StorageSnapshot snapshotAfterRemoval = storage.getSnapshot();

    assertThat(snapshotAfterRemoval.bundleHandles()).isEmpty();
    assertThat(snapshotAfterRemoval.getBundleHandle(0)).isInstanceOf(BackupHandle.Empty.class);
  }

  @Test
  public void getSnapshot_absentEpoch_returnsEmptyBackupHandleWithoutAddingItToBundleHandles()
      throws Exception {
    stubCompleteListingWithETag("etag-v1");

    StorageSnapshot snapshot = storage.getSnapshot();
    BackupHandle emptyEpoch1 = snapshot.getBundleHandle(1);

    assertThat(emptyEpoch1).isInstanceOf(BackupHandle.Empty.class);
    assertThat(emptyEpoch1.epoch()).isEqualTo(1);
    assertThat(snapshot.bundleHandles().keySet()).containsExactly(0);
    ((BackupHandle.Empty) emptyEpoch1).write(KEY_BACKUP);
    verify(writer).write(1, KEY_BACKUP);
  }

  @Test
  public void getSnapshot_crossSignedCertPresent_populatesCompleteCrossSignedCertHandle()
      throws Exception {
    stubListings(List.of(S3BackupPaths.getCrossSignedCertPath(CROSS_SIGNED_ID)), List.of());
    when(reader.readCrossSignedCert(CROSS_SIGNED_ID)).thenReturn(CROSS_SIGNED_BACKUP);

    StorageSnapshot snapshot = storage.getSnapshot();
    CrossSignedCertHandle handle = snapshot.getCrossSignedCertHandle(CROSS_SIGNED_ID);

    assertThat(handle).isInstanceOf(CrossSignedCertHandle.Complete.class);
    assertThat(handle.id()).isEqualTo(CROSS_SIGNED_ID);
    assertThat(((CrossSignedCertHandle.Complete) handle).read())
        .isSameInstanceAs(CROSS_SIGNED_BACKUP);
    verify(reader).readCrossSignedCert(CROSS_SIGNED_ID);
  }

  @Test
  public void getSnapshot_unchangedCrossSignedETag_reusesSameCompleteCrossSignedCertHandleInstance()
      throws Exception {
    stubCrossSignedListingWithETag("etag-v1");

    CrossSignedCertHandle handleBefore =
        storage.getSnapshot().getCrossSignedCertHandle(CROSS_SIGNED_ID);
    CrossSignedCertHandle handleAfter =
        storage.getSnapshot().getCrossSignedCertHandle(CROSS_SIGNED_ID);

    assertThat(handleAfter).isSameInstanceAs(handleBefore);
    verifyNoInteractions(reader);
  }

  @Test
  public void getSnapshot_changedCrossSignedETag_createsNewCompleteCrossSignedCertHandleInstance()
      throws Exception {
    stubCrossSignedListingWithETag("etag-v1");
    CrossSignedCertHandle handleBefore =
        storage.getSnapshot().getCrossSignedCertHandle(CROSS_SIGNED_ID);

    stubCrossSignedListingWithETag("etag-v2");
    CrossSignedCertHandle handleAfter =
        storage.getSnapshot().getCrossSignedCertHandle(CROSS_SIGNED_ID);

    assertThat(handleAfter).isNotSameInstanceAs(handleBefore);
    verifyNoInteractions(reader);
  }

  @Test
  public void getSnapshot_removedCrossSignedCert_evictsCrossSignedCertHandleFromSubsequentSnapshot()
      throws Exception {
    stubCrossSignedListingWithETag("etag-v1");
    assertThat(storage.getSnapshot().getCrossSignedCertHandle(CROSS_SIGNED_ID))
        .isInstanceOf(CrossSignedCertHandle.Complete.class);

    stubListings(List.of(), List.of());
    StorageSnapshot snapshotAfterRemoval = storage.getSnapshot();

    assertThat(snapshotAfterRemoval.crossSignedCertHandles()).isEmpty();
    assertThat(snapshotAfterRemoval.getCrossSignedCertHandle(CROSS_SIGNED_ID))
        .isInstanceOf(CrossSignedCertHandle.Empty.class);
  }

  @Test
  public void
      getSnapshot_absentCrossSignedCert_returnsEmptyCrossSignedCertHandleWithoutAddingItToCrossSignedCertHandles()
          throws Exception {
    stubCrossSignedListingWithETag("etag-v1");
    CrossSignedCertificateId absentId = new CrossSignedCertificateId(1, 0);

    StorageSnapshot snapshot = storage.getSnapshot();
    CrossSignedCertHandle emptyHandle = snapshot.getCrossSignedCertHandle(absentId);

    assertThat(emptyHandle).isInstanceOf(CrossSignedCertHandle.Empty.class);
    assertThat(emptyHandle.id()).isEqualTo(absentId);
    assertThat(snapshot.crossSignedCertHandles().keySet()).containsExactly(CROSS_SIGNED_ID);
    ((CrossSignedCertHandle.Empty) emptyHandle).write(CROSS_SIGNED_BACKUP);
    verify(writer).writeCrossSignedCert(absentId, CROSS_SIGNED_BACKUP);
  }

  @Test
  public void acquireLock_delegatesToWriter() throws Exception {
    storage.acquireLock();
    verify(writer).acquireLock();
    verifyNoInteractions(s3Client);
  }

  @Test
  public void acquireLock_propagatesStorageAlreadyLockedException() throws Exception {
    doThrow(new StorageAlreadyLockedException("already locked")).when(writer).acquireLock();

    assertThrows(StorageAlreadyLockedException.class, () -> storage.acquireLock());
    verifyNoInteractions(s3Client);
  }

  @Test
  public void releaseLock_delegatesToWriter() throws Exception {
    storage.releaseLock();
    verify(writer).releaseLock();
    verifyNoInteractions(s3Client);
  }

  @Test
  public void getSnapshot_sdkExceptionOnListing_throwsAccessFailed() {
    when(s3Client.listObjectsV2(
            (ListObjectsV2Request)
                argThat(
                    r ->
                        r instanceof ListObjectsV2Request req
                            && PUBLIC_BUCKET.equals(req.bucket()))))
        .thenThrow(SdkClientException.create("S3 listing failure"));

    assertThrows(KeyBackupAccessFailedException.class, () -> storage.getSnapshot());
  }

  private void stubCrossSignedListingWithETag(String eTag) {
    stubListing(
        PUBLIC_BUCKET,
        S3BackupPaths.PUBLIC_PREFIX,
        List.of(S3BackupPaths.getCrossSignedCertPath(CROSS_SIGNED_ID)),
        eTag);
    stubListing(PRIVATE_BUCKET, S3BackupPaths.PRIVATE_PREFIX, List.of(), eTag);
  }

  private void stubCompleteListingWithETag(String eTag) {
    stubListing(
        PUBLIC_BUCKET,
        S3BackupPaths.PUBLIC_PREFIX,
        List.of(S3BackupPaths.getRootCertPath(0), S3BackupPaths.getAttestationDocPath(0)),
        eTag);
    stubListing(
        PRIVATE_BUCKET,
        S3BackupPaths.PRIVATE_PREFIX,
        List.of(
            S3BackupPaths.getKmsEncryptedDataKeyPath(0),
            S3BackupPaths.getAesEncryptedPrivateKeyPath(0)),
        eTag);
  }

  private void stubListings(List<String> publicKeys, List<String> privateKeys) {
    stubListing(PUBLIC_BUCKET, S3BackupPaths.PUBLIC_PREFIX, publicKeys, "default-etag");
    stubListing(PRIVATE_BUCKET, S3BackupPaths.PRIVATE_PREFIX, privateKeys, "default-etag");
  }

  private void stubListing(String bucket, String prefix, List<String> keys, String eTag) {
    List<S3Object> objects =
        keys.stream().map(key -> S3Object.builder().key(key).eTag(eTag).build()).toList();
    when(s3Client.listObjectsV2(
            (ListObjectsV2Request)
                argThat(
                    r ->
                        r instanceof ListObjectsV2Request req
                            && bucket.equals(req.bucket())
                            && prefix.equals(req.prefix()))))
        .thenReturn(
            software.amazon.awssdk.services.s3.model.ListObjectsV2Response.builder()
                .contents(objects)
                .isTruncated(false)
                .build());
  }
}
