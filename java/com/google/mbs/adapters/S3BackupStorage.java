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
import com.google.mbs.domain.BackupAccessFailedException;
import com.google.mbs.domain.BackupBucketProperties;
import com.google.mbs.domain.BackupStorage;
import com.google.mbs.domain.BackupStorageAlreadyLockedException;
import com.google.mbs.domain.CrossSignedCertificateBackupHandle;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.SelfSignedBundleBackupHandle;
import com.google.mbs.domain.StorageSnapshot;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * Storage adapter that tracks the S3 backup layout by listing the buckets, and delegates reads and
 * writes to {@link S3BackupReader} and {@link S3BackupWriter}.
 */
@Singleton
public class S3BackupStorage implements BackupStorage {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final int EPOCH_KEY_SEGMENT_COUNT = 3;

  private static final Pattern CROSS_SIGNED_CERT_KEY_PATTERN =
      Pattern.compile(
          "^"
              + Pattern.quote(S3BackupPaths.CROSS_SIGNED_PREFIX)
              + "([^/]+)/"
              + Pattern.quote(S3BackupPaths.CROSS_SIGNED_CERTIFICATE_FILE)
              + "$");

  private static final Map<String, SelfSignedBundleBackupElement>
      PUBLIC_SELF_SIGNED_BUNDLE_BACKUP_ELEMENTS =
          Map.of(
              S3BackupPaths.getFileName(SelfSignedBundleBackupElement.CERT),
              SelfSignedBundleBackupElement.CERT,
              S3BackupPaths.getFileName(SelfSignedBundleBackupElement.ATTESTATION_DOC),
              SelfSignedBundleBackupElement.ATTESTATION_DOC);

  private static final Map<String, SelfSignedBundleBackupElement>
      PRIVATE_SELF_SIGNED_BUNDLE_BACKUP_ELEMENTS =
          Map.of(
              S3BackupPaths.getFileName(SelfSignedBundleBackupElement.KMS_DATA_KEY),
              SelfSignedBundleBackupElement.KMS_DATA_KEY,
              S3BackupPaths.getFileName(SelfSignedBundleBackupElement.PRIVATE_KEY),
              SelfSignedBundleBackupElement.PRIVATE_KEY);

  private final S3Client s3Client;
  private final BackupBucketProperties bucketProperties;
  private final S3BackupReader reader;
  private final S3BackupWriter writer;
  private final AtomicReference<S3StorageSnapshot> cachedSnapshot;

  @Inject
  public S3BackupStorage(
      S3Client s3Client,
      BackupBucketProperties bucketProperties,
      S3BackupReader reader,
      S3BackupWriter writer) {
    this.s3Client = Objects.requireNonNull(s3Client);
    this.bucketProperties = Objects.requireNonNull(bucketProperties);
    this.reader = Objects.requireNonNull(reader);
    this.writer = Objects.requireNonNull(writer);
    this.cachedSnapshot = new AtomicReference<>(new S3StorageSnapshot(Map.of(), Map.of(), writer));
  }

  @Override
  public StorageSnapshot getSnapshot() throws BackupAccessFailedException {
    Map<Integer, EnumMap<SelfSignedBundleBackupElement, String>> eTagsByEpoch = new HashMap<>();
    Map<CrossSignedCertificateId, String> eTagsByCrossSignedId = new HashMap<>();
    listBucket(
        bucketProperties.getPublicBucketName(),
        S3BackupPaths.PUBLIC_PREFIX,
        s3Object -> {
          recordSelfSignedBundleBackupElement(
              eTagsByEpoch, s3Object, PUBLIC_SELF_SIGNED_BUNDLE_BACKUP_ELEMENTS);
          recordCrossSignedCertificate(eTagsByCrossSignedId, s3Object);
        });
    listBucket(
        bucketProperties.getPrivateBucketName(),
        S3BackupPaths.PRIVATE_PREFIX,
        s3Object ->
            recordSelfSignedBundleBackupElement(
                eTagsByEpoch, s3Object, PRIVATE_SELF_SIGNED_BUNDLE_BACKUP_ELEMENTS));

    S3StorageSnapshot updated =
        cachedSnapshot.updateAndGet(
            previous ->
                new S3StorageSnapshot(
                    buildSelfSignedBundleBackupHandles(
                        eTagsByEpoch, previous.selfSignedBundleBackupHandles()),
                    buildCrossSignedCertificateBackupHandles(
                        eTagsByCrossSignedId, previous.crossSignedCertificateBackupHandles()),
                    writer));
    // Intentionally return a copy of both handle maps (for SelfSignedBundleBackup and
    // CrossSignedCertificateBackup) to protect internal cachedSnapshot state while allowing
    // callers to manipulate their own copy.
    return new S3StorageSnapshot(
        new HashMap<>(updated.selfSignedBundleBackupHandles()),
        new HashMap<>(updated.crossSignedCertificateBackupHandles()),
        writer);
  }

  @Override
  public void acquireLock()
      throws BackupStorageAlreadyLockedException, BackupAccessFailedException {
    writer.acquireLock();
  }

  @Override
  public void releaseLock() throws BackupAccessFailedException {
    writer.releaseLock();
  }

  private void listBucket(String bucket, String prefix, Consumer<S3Object> objectConsumer)
      throws BackupAccessFailedException {
    ListObjectsV2Request request =
        ListObjectsV2Request.builder().bucket(bucket).prefix(prefix).build();
    int count = 0;
    try {
      for (S3Object s3Object : s3Client.listObjectsV2Paginator(request).contents()) {
        count++;
        objectConsumer.accept(s3Object);
      }
      logger.atInfo().log("Listed S3 bucket %s/%s (%d objects)", bucket, prefix, count);
    } catch (SdkException e) {
      logger.atWarning().withCause(e).log("Failed to list S3 bucket %s/%s", bucket, prefix);
      throw new BackupAccessFailedException(
          "Failed to list prefix: " + prefix + " of bucket: " + bucket, e);
    }
  }

  private static void recordSelfSignedBundleBackupElement(
      Map<Integer, EnumMap<SelfSignedBundleBackupElement, String>> eTagsByEpoch,
      S3Object s3Object,
      Map<String, SelfSignedBundleBackupElement> allowedElements) {
    String key = s3Object.key();
    String[] segments = key.split("/", -1);
    if (segments.length != EPOCH_KEY_SEGMENT_COUNT) {
      return;
    }
    SelfSignedBundleBackupElement element = allowedElements.get(segments[2]);
    if (element == null) {
      return;
    }
    try {
      int epoch = Integer.parseInt(segments[1]);
      if (!Integer.toString(epoch).equals(segments[1])) {
        logger.atInfo().log("Ignoring non-canonical S3 key %s", key);
        return;
      }
      EnumMap<SelfSignedBundleBackupElement, String> epochElementETags =
          eTagsByEpoch.computeIfAbsent(
              epoch, k -> new EnumMap<>(SelfSignedBundleBackupElement.class));
      epochElementETags.put(element, s3Object.eTag());
    } catch (NumberFormatException notAnEpochDirectory) {
      logger.atInfo().log("Ignoring unrecognized S3 key %s", key);
    }
  }

  private static void recordCrossSignedCertificate(
      Map<CrossSignedCertificateId, String> eTagsByCrossSignedId, S3Object s3Object) {
    String key = s3Object.key();
    Matcher matcher = CROSS_SIGNED_CERT_KEY_PATTERN.matcher(key);
    if (!matcher.matches()) {
      return;
    }
    try {
      CrossSignedCertificateId id = CrossSignedCertificateId.fromKeyString(matcher.group(1));
      eTagsByCrossSignedId.put(id, s3Object.eTag());
    } catch (IllegalArgumentException ignored) {
      logger.atInfo().log("Ignoring unrecognized cross-signed S3 key %s", key);
    }
  }

  private Map<Integer, SelfSignedBundleBackupHandle> buildSelfSignedBundleBackupHandles(
      Map<Integer, EnumMap<SelfSignedBundleBackupElement, String>> eTagsByEpoch,
      Map<Integer, SelfSignedBundleBackupHandle> previousHandles) {
    Map<Integer, SelfSignedBundleBackupHandle> nextHandles = new HashMap<>();
    eTagsByEpoch.forEach(
        (epoch, presentElementETags) ->
            nextHandles.put(
                epoch,
                reuseCachedSelfSignedBundleBackupHandleOrCreateNew(
                    epoch, presentElementETags, previousHandles.get(epoch))));
    return nextHandles;
  }

  private Map<CrossSignedCertificateId, CrossSignedCertificateBackupHandle>
      buildCrossSignedCertificateBackupHandles(
          Map<CrossSignedCertificateId, String> eTagsByCrossSignedId,
          Map<CrossSignedCertificateId, CrossSignedCertificateBackupHandle>
              previousCrossSignedHandles) {
    Map<CrossSignedCertificateId, CrossSignedCertificateBackupHandle> nextCrossSignedHandles =
        new HashMap<>();
    eTagsByCrossSignedId.forEach(
        (id, eTag) ->
            nextCrossSignedHandles.put(
                id,
                reuseCachedCrossSignedCertificateBackupHandleOrCreateNew(
                    id, eTag, previousCrossSignedHandles.get(id))));
    return nextCrossSignedHandles;
  }

  private SelfSignedBundleBackupHandle reuseCachedSelfSignedBundleBackupHandleOrCreateNew(
      int epoch,
      EnumMap<SelfSignedBundleBackupElement, String> presentElementETags,
      SelfSignedBundleBackupHandle cachedHandle) {
    if (cachedHandle instanceof S3CompleteSelfSignedBundleBackupHandle cachedComplete
        && cachedComplete.elementETags().equals(presentElementETags)) {
      logger.atInfo().log(
          "Reusing cached SelfSignedBundleBackupHandle (%s) for epoch %d with matching ETags: %s",
          cachedComplete.getClass().getSimpleName(), epoch, presentElementETags);
      return cachedComplete;
    }
    SelfSignedBundleBackupHandle newHandle =
        createSelfSignedBundleBackupHandle(epoch, presentElementETags);
    logger.atInfo().log(
        "Created new SelfSignedBundleBackupHandle (%s) for epoch %d with ETags: %s",
        newHandle.getClass().getSimpleName(), epoch, presentElementETags);
    return newHandle;
  }

  private CrossSignedCertificateBackupHandle
      reuseCachedCrossSignedCertificateBackupHandleOrCreateNew(
          CrossSignedCertificateId id,
          String eTag,
          CrossSignedCertificateBackupHandle cachedHandle) {
    if (cachedHandle instanceof S3CompleteCrossSignedCertificateBackupHandle cachedComplete
        && Objects.equals(cachedComplete.eTag(), eTag)) {
      logger.atInfo().log(
          "Reusing cached CrossSignedCertificateBackupHandle (%s) for %s with matching ETag: %s",
          cachedComplete.getClass().getSimpleName(), id.toKeyString(), eTag);
      return cachedComplete;
    }
    CrossSignedCertificateBackupHandle newHandle =
        new S3CompleteCrossSignedCertificateBackupHandle(id, reader, eTag);
    logger.atInfo().log(
        "Created new CrossSignedCertificateBackupHandle (%s) for %s with ETag: %s",
        newHandle.getClass().getSimpleName(), id.toKeyString(), eTag);
    return newHandle;
  }

  private SelfSignedBundleBackupHandle createSelfSignedBundleBackupHandle(
      int epoch, EnumMap<SelfSignedBundleBackupElement, String> presentElementETags) {
    Set<SelfSignedBundleBackupElement> presentElements = presentElementETags.keySet();
    if (presentElements.size() == SelfSignedBundleBackupElement.values().length) {
      return new S3CompleteSelfSignedBundleBackupHandle(epoch, reader, presentElementETags);
    }
    List<String> missingFileNames =
        EnumSet.complementOf(EnumSet.copyOf(presentElements)).stream()
            .map(S3BackupPaths::getFileName)
            .toList();
    // The certificate is written last, so treat a backup lacking it as never completed.
    return presentElements.contains(SelfSignedBundleBackupElement.CERT)
        ? new SelfSignedBundleBackupHandle.Incomplete(epoch, missingFileNames)
        : new SelfSignedBundleBackupHandle.PartiallyWritten(epoch, missingFileNames);
  }
}
