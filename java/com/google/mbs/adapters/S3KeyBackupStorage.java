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
import com.google.mbs.domain.ArtifactType;
import com.google.mbs.domain.BackupHandle;
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
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.jspecify.annotations.NonNull;
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

  private static final Map<String, ArtifactType> PUBLIC_ARTIFACTS =
      Map.of(
          S3BackupPaths.getFileName(ArtifactType.CERT), ArtifactType.CERT,
          S3BackupPaths.getFileName(ArtifactType.ATTESTATION_DOC), ArtifactType.ATTESTATION_DOC);

  private static final Map<String, ArtifactType> PRIVATE_ARTIFACTS =
      Map.of(
          S3BackupPaths.getFileName(ArtifactType.KMS_DATA_KEY), ArtifactType.KMS_DATA_KEY,
          S3BackupPaths.getFileName(ArtifactType.PRIVATE_KEY), ArtifactType.PRIVATE_KEY);

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
    this.s3Client = s3Client;
    this.bucketProperties = bucketProperties;
    this.reader = reader;
    this.writer = writer;
    this.cachedSnapshot = new AtomicReference<>(new S3StorageSnapshot(Map.of(), writer));
  }

  @Override
  public @NonNull StorageSnapshot getSnapshot() throws KeyBackupAccessFailedException {
    Map<Integer, EnumMap<ArtifactType, String>> etagsByEpoch = new HashMap<>();
    listBucketInto(
        etagsByEpoch,
        bucketProperties.getPublicBucketName(),
        S3BackupPaths.PUBLIC_PREFIX,
        PUBLIC_ARTIFACTS);
    listBucketInto(
        etagsByEpoch,
        bucketProperties.getPrivateBucketName(),
        S3BackupPaths.PRIVATE_PREFIX,
        PRIVATE_ARTIFACTS);

    S3StorageSnapshot updated =
        cachedSnapshot.updateAndGet(
            previous -> {
              Map<Integer, BackupHandle> previousHandles = previous.bundleHandles();
              Map<Integer, BackupHandle> nextHandles = new HashMap<>();
              for (Map.Entry<Integer, EnumMap<ArtifactType, String>> epochEtagsEntry :
                  etagsByEpoch.entrySet()) {
                int epoch = epochEtagsEntry.getKey();
                EnumMap<ArtifactType, String> presentArtifactEtags = epochEtagsEntry.getValue();
                nextHandles.put(
                    epoch,
                    reuseCachedBackupHandleOrCreateNew(
                        epoch, presentArtifactEtags, previousHandles.get(epoch)));
              }
              return new S3StorageSnapshot(nextHandles, writer);
            });
    return new S3StorageSnapshot(new HashMap<>(updated.bundleHandles()), writer);
  }

  @Override
  public void acquireLock() throws StorageAlreadyLockedException, KeyBackupAccessFailedException {
    writer.acquireLock();
  }

  @Override
  public void releaseLock() throws KeyBackupAccessFailedException {
    writer.releaseLock();
  }

  private void listBucketInto(
      Map<Integer, EnumMap<ArtifactType, String>> etagsByEpoch,
      String bucket,
      String prefix,
      Map<String, ArtifactType> allowedArtifacts)
      throws KeyBackupAccessFailedException {
    ListObjectsV2Request request =
        ListObjectsV2Request.builder().bucket(bucket).prefix(prefix).build();
    int count = 0;
    try {
      for (S3Object s3Object : s3Client.listObjectsV2Paginator(request).contents()) {
        count++;
        recordArtifact(etagsByEpoch, s3Object, allowedArtifacts);
      }
      logger.atInfo().log("Listed S3 bucket %s/%s (%d objects)", bucket, prefix, count);
    } catch (SdkException e) {
      logger.atWarning().withCause(e).log("Failed to list S3 bucket %s/%s", bucket, prefix);
      throw new KeyBackupAccessFailedException(
          "Failed to list prefix: " + prefix + " of bucket: " + bucket, e);
    }
  }

  private static void recordArtifact(
      Map<Integer, EnumMap<ArtifactType, String>> etagsByEpoch,
      S3Object s3Object,
      Map<String, ArtifactType> allowedArtifacts) {
    String key = s3Object.key();
    String[] segments = key.split("/", -1);
    if (segments.length != EPOCH_KEY_SEGMENT_COUNT) {
      return;
    }
    ArtifactType artifact = allowedArtifacts.get(segments[2]);
    if (artifact == null) {
      return;
    }
    try {
      int epoch = Integer.parseInt(segments[1]);
      EnumMap<ArtifactType, String> epochArtifactEtags =
          etagsByEpoch.computeIfAbsent(epoch, k -> new EnumMap<>(ArtifactType.class));
      epochArtifactEtags.put(artifact, s3Object.eTag());
    } catch (NumberFormatException notAnEpochDirectory) {
      logger.atInfo().log("Ignoring unrecognized S3 key %s", key);
    }
  }

  private BackupHandle reuseCachedBackupHandleOrCreateNew(
      int epoch, EnumMap<ArtifactType, String> presentArtifactEtags, BackupHandle cachedHandle) {
    if (cachedHandle instanceof S3CompleteBackupHandle cachedComplete
        && cachedComplete.artifactEtags().equals(presentArtifactEtags)) {
      logger.atInfo().log(
          "Reusing cached BackupHandle (%s) for epoch %d with matching ETags: %s",
          cachedComplete.getClass().getSimpleName(), epoch, presentArtifactEtags);
      return cachedComplete;
    }
    BackupHandle newHandle = createHandle(epoch, presentArtifactEtags);
    logger.atInfo().log(
        "Created new BackupHandle (%s) for epoch %d with ETags: %s",
        newHandle.getClass().getSimpleName(), epoch, presentArtifactEtags);
    return newHandle;
  }

  private BackupHandle createHandle(int epoch, EnumMap<ArtifactType, String> presentArtifactEtags) {
    Set<ArtifactType> presentArtifacts = presentArtifactEtags.keySet();
    if (presentArtifacts.size() == ArtifactType.values().length) {
      return new S3CompleteBackupHandle(epoch, reader, presentArtifactEtags);
    }
    List<String> missingFileNames =
        EnumSet.complementOf(EnumSet.copyOf(presentArtifacts)).stream()
            .map(S3BackupPaths::getFileName)
            .toList();
    // The certificate is written last, so treat a backup lacking it as never completed.
    return presentArtifacts.contains(ArtifactType.CERT)
        ? new BackupHandle.Incomplete(epoch, missingFileNames)
        : new BackupHandle.PartiallyWritten(epoch, missingFileNames);
  }
}
