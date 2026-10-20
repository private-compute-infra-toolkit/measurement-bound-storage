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
import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.CrossSignedCertHandle;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KeyBackupAccessFailedException;
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.StorageAlreadyLockedException;
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
public class S3KeyBackupStorage implements KeyBackupStorage {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final int EPOCH_KEY_SEGMENT_COUNT = 3;

  private static final Pattern CROSS_SIGNED_CERT_KEY_PATTERN =
      Pattern.compile(
          "^"
              + Pattern.quote(S3BackupPaths.CROSS_SIGNED_PREFIX)
              + "([^/]+)/"
              + Pattern.quote(S3BackupPaths.CROSS_SIGNED_CERT_FILE)
              + "$");

  private static final Map<String, KeyBackupElement> PUBLIC_KEY_BACKUP_ELEMENTS =
      Map.of(
          S3BackupPaths.getFileName(KeyBackupElement.CERT), KeyBackupElement.CERT,
          S3BackupPaths.getFileName(KeyBackupElement.ATTESTATION_DOC),
              KeyBackupElement.ATTESTATION_DOC);

  private static final Map<String, KeyBackupElement> PRIVATE_KEY_BACKUP_ELEMENTS =
      Map.of(
          S3BackupPaths.getFileName(KeyBackupElement.KMS_DATA_KEY), KeyBackupElement.KMS_DATA_KEY,
          S3BackupPaths.getFileName(KeyBackupElement.PRIVATE_KEY), KeyBackupElement.PRIVATE_KEY);

  private final S3Client s3Client;
  private final KeyBackupBucketProperties bucketProperties;
  private final S3BackupReader reader;
  private final S3BackupWriter writer;
  private final AtomicReference<S3StorageSnapshot> cachedSnapshot;

  @Inject
  public S3KeyBackupStorage(
      S3Client s3Client,
      KeyBackupBucketProperties bucketProperties,
      S3BackupReader reader,
      S3BackupWriter writer) {
    this.s3Client = Objects.requireNonNull(s3Client);
    this.bucketProperties = Objects.requireNonNull(bucketProperties);
    this.reader = Objects.requireNonNull(reader);
    this.writer = Objects.requireNonNull(writer);
    this.cachedSnapshot = new AtomicReference<>(new S3StorageSnapshot(Map.of(), Map.of(), writer));
  }

  @Override
  public StorageSnapshot getSnapshot() throws KeyBackupAccessFailedException {
    Map<Integer, EnumMap<KeyBackupElement, String>> eTagsByEpoch = new HashMap<>();
    Map<CrossSignedCertificateId, String> eTagsByCrossSignedId = new HashMap<>();
    listBucket(
        bucketProperties.getPublicBucketName(),
        S3BackupPaths.PUBLIC_PREFIX,
        s3Object -> {
          recordKeyBackupElement(eTagsByEpoch, s3Object, PUBLIC_KEY_BACKUP_ELEMENTS);
          recordCrossSignedCert(eTagsByCrossSignedId, s3Object);
        });
    listBucket(
        bucketProperties.getPrivateBucketName(),
        S3BackupPaths.PRIVATE_PREFIX,
        s3Object -> recordKeyBackupElement(eTagsByEpoch, s3Object, PRIVATE_KEY_BACKUP_ELEMENTS));

    S3StorageSnapshot updated =
        cachedSnapshot.updateAndGet(
            previous ->
                new S3StorageSnapshot(
                    buildBundleHandles(eTagsByEpoch, previous.bundleHandles()),
                    buildCrossSignedCertHandles(
                        eTagsByCrossSignedId, previous.crossSignedCertHandles()),
                    writer));
    // Intentionally return a copy of both handle maps (for KeyBackup and
    // CrossSignedCertificateBackup) to protect internal cachedSnapshot state while allowing
    // callers to manipulate their own copy.
    return new S3StorageSnapshot(
        new HashMap<>(updated.bundleHandles()),
        new HashMap<>(updated.crossSignedCertHandles()),
        writer);
  }

  @Override
  public void acquireLock() throws StorageAlreadyLockedException, KeyBackupAccessFailedException {
    writer.acquireLock();
  }

  @Override
  public void releaseLock() throws KeyBackupAccessFailedException {
    writer.releaseLock();
  }

  private void listBucket(String bucket, String prefix, Consumer<S3Object> objectConsumer)
      throws KeyBackupAccessFailedException {
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
      throw new KeyBackupAccessFailedException(
          "Failed to list prefix: " + prefix + " of bucket: " + bucket, e);
    }
  }

  private static void recordKeyBackupElement(
      Map<Integer, EnumMap<KeyBackupElement, String>> eTagsByEpoch,
      S3Object s3Object,
      Map<String, KeyBackupElement> allowedElements) {
    String key = s3Object.key();
    String[] segments = key.split("/", -1);
    if (segments.length != EPOCH_KEY_SEGMENT_COUNT) {
      return;
    }
    KeyBackupElement element = allowedElements.get(segments[2]);
    if (element == null) {
      return;
    }
    try {
      int epoch = Integer.parseInt(segments[1]);
      if (!Integer.toString(epoch).equals(segments[1])) {
        logger.atInfo().log("Ignoring non-canonical S3 key %s", key);
        return;
      }
      EnumMap<KeyBackupElement, String> epochElementETags =
          eTagsByEpoch.computeIfAbsent(epoch, k -> new EnumMap<>(KeyBackupElement.class));
      epochElementETags.put(element, s3Object.eTag());
    } catch (NumberFormatException notAnEpochDirectory) {
      logger.atInfo().log("Ignoring unrecognized S3 key %s", key);
    }
  }

  private static void recordCrossSignedCert(
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

  private Map<Integer, BackupHandle> buildBundleHandles(
      Map<Integer, EnumMap<KeyBackupElement, String>> eTagsByEpoch,
      Map<Integer, BackupHandle> previousHandles) {
    Map<Integer, BackupHandle> nextHandles = new HashMap<>();
    eTagsByEpoch.forEach(
        (epoch, presentElementETags) ->
            nextHandles.put(
                epoch,
                reuseCachedBackupHandleOrCreateNew(
                    epoch, presentElementETags, previousHandles.get(epoch))));
    return nextHandles;
  }

  private Map<CrossSignedCertificateId, CrossSignedCertHandle> buildCrossSignedCertHandles(
      Map<CrossSignedCertificateId, String> eTagsByCrossSignedId,
      Map<CrossSignedCertificateId, CrossSignedCertHandle> previousCrossSignedHandles) {
    Map<CrossSignedCertificateId, CrossSignedCertHandle> nextCrossSignedHandles = new HashMap<>();
    eTagsByCrossSignedId.forEach(
        (id, eTag) ->
            nextCrossSignedHandles.put(
                id,
                reuseCachedCrossSignedHandleOrCreateNew(
                    id, eTag, previousCrossSignedHandles.get(id))));
    return nextCrossSignedHandles;
  }

  private BackupHandle reuseCachedBackupHandleOrCreateNew(
      int epoch, EnumMap<KeyBackupElement, String> presentElementETags, BackupHandle cachedHandle) {
    if (cachedHandle instanceof S3CompleteBackupHandle cachedComplete
        && cachedComplete.elementETags().equals(presentElementETags)) {
      logger.atInfo().log(
          "Reusing cached BackupHandle (%s) for epoch %d with matching ETags: %s",
          cachedComplete.getClass().getSimpleName(), epoch, presentElementETags);
      return cachedComplete;
    }
    BackupHandle newHandle = createHandle(epoch, presentElementETags);
    logger.atInfo().log(
        "Created new BackupHandle (%s) for epoch %d with ETags: %s",
        newHandle.getClass().getSimpleName(), epoch, presentElementETags);
    return newHandle;
  }

  private CrossSignedCertHandle reuseCachedCrossSignedHandleOrCreateNew(
      CrossSignedCertificateId id, String eTag, CrossSignedCertHandle cachedHandle) {
    if (cachedHandle instanceof S3CompleteCrossSignedCertHandle cachedComplete
        && Objects.equals(cachedComplete.eTag(), eTag)) {
      logger.atInfo().log(
          "Reusing cached CrossSignedCertHandle (%s) for %s with matching ETag: %s",
          cachedComplete.getClass().getSimpleName(), id.toKeyString(), eTag);
      return cachedComplete;
    }
    CrossSignedCertHandle newHandle = new S3CompleteCrossSignedCertHandle(id, reader, eTag);
    logger.atInfo().log(
        "Created new CrossSignedCertHandle (%s) for %s with ETag: %s",
        newHandle.getClass().getSimpleName(), id.toKeyString(), eTag);
    return newHandle;
  }

  private BackupHandle createHandle(
      int epoch, EnumMap<KeyBackupElement, String> presentElementETags) {
    Set<KeyBackupElement> presentElements = presentElementETags.keySet();
    if (presentElements.size() == KeyBackupElement.values().length) {
      return new S3CompleteBackupHandle(epoch, reader, presentElementETags);
    }
    List<String> missingFileNames =
        EnumSet.complementOf(EnumSet.copyOf(presentElements)).stream()
            .map(S3BackupPaths::getFileName)
            .toList();
    // The certificate is written last, so treat a backup lacking it as never completed.
    return presentElements.contains(KeyBackupElement.CERT)
        ? new BackupHandle.Incomplete(epoch, missingFileNames)
        : new BackupHandle.PartiallyWritten(epoch, missingFileNames);
  }
}
