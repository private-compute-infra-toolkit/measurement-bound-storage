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
import com.google.mbs.domain.BackupStorageException;
import com.google.mbs.domain.SelfSignedBundleBackup;
import com.google.mbs.domain.SelfSignedBundleBackupHandle;
import java.util.Map;
import java.util.Objects;

/**
 * S3 implementation of {@link SelfSignedBundleBackupHandle.Complete} that lazily reads backup
 * artifacts from S3 on the first {@link #read()} and memoizes the result.
 */
final class S3CompleteSelfSignedBundleBackupHandle
    implements SelfSignedBundleBackupHandle.Complete {

  private final int epoch;
  private final S3BackupReader reader;
  private final ImmutableMap<SelfSignedBundleBackupElement, String> elementETags;
  private SelfSignedBundleBackup cachedBackup;

  S3CompleteSelfSignedBundleBackupHandle(
      int epoch, S3BackupReader reader, Map<SelfSignedBundleBackupElement, String> elementETags) {
    this.epoch = epoch;
    this.reader = Objects.requireNonNull(reader);
    this.elementETags = ImmutableMap.copyOf(elementETags);
  }

  @Override
  public int epoch() {
    return epoch;
  }

  ImmutableMap<SelfSignedBundleBackupElement, String> elementETags() {
    return elementETags;
  }

  @Override
  public synchronized SelfSignedBundleBackup read() throws BackupStorageException {
    if (cachedBackup == null) {
      cachedBackup = reader.readSelfSignedBundleBackup(epoch);
    }
    return cachedBackup;
  }
}
