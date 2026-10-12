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

import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupStorageException;

/**
 * S3 implementation of {@link BackupHandle.Empty} that delegates writing a new backup to {@link
 * S3BackupWriter}.
 */
final class S3EmptyBackupHandle implements BackupHandle.Empty {

  private final int epoch;
  private final S3BackupWriter writer;

  S3EmptyBackupHandle(int epoch, S3BackupWriter writer) {
    this.epoch = epoch;
    this.writer = writer;
  }

  @Override
  public int epoch() {
    return epoch;
  }

  @Override
  public void write(KeyBackup keyBackup) throws KeyBackupStorageException {
    writer.write(epoch, keyBackup);
  }
}
