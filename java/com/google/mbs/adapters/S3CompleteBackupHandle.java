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

import com.google.common.collect.ImmutableMap;
import com.google.mbs.domain.ArtifactType;
import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupStorageException;
import java.util.Map;
import org.jspecify.annotations.NonNull;

/**
 * S3 implementation of {@link BackupHandle.Complete} that lazily reads backup artifacts from S3 on
 * the first {@link #read()} and memoizes the result.
 */
final class S3CompleteBackupHandle implements BackupHandle.Complete {

  private final int epoch;
  private final S3BackupReader reader;
  private final ImmutableMap<ArtifactType, String> artifactEtags;
  private KeyBackup cachedBackup;

  S3CompleteBackupHandle(
      int epoch, S3BackupReader reader, Map<ArtifactType, String> artifactEtags) {
    this.epoch = epoch;
    this.reader = reader;
    this.artifactEtags = ImmutableMap.copyOf(artifactEtags);
  }

  @Override
  public int epoch() {
    return epoch;
  }

  ImmutableMap<ArtifactType, String> artifactEtags() {
    return artifactEtags;
  }

  @Override
  public synchronized @NonNull KeyBackup read() throws KeyBackupStorageException {
    if (cachedBackup == null) {
      cachedBackup = reader.read(epoch);
    }
    return cachedBackup;
  }
}
