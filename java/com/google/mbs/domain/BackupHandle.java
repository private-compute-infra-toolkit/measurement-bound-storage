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

package com.google.mbs.domain;

import java.util.List;

/**
 * Observed state of the backup of a single epoch, and the operations that state permits.
 *
 * <p>The state is derived from object existence alone, so it says nothing about the integrity of
 * the stored bytes. It may also be stale: storage can change between the listing that produced the
 * handle and the operation invoked on it.
 */
public sealed interface BackupHandle
    permits BackupHandle.Complete,
        BackupHandle.Empty,
        BackupHandle.PartiallyWritten,
        BackupHandle.Incomplete {

  /** Returns the epoch this handle describes. */
  int epoch();

  /**
   * Narrows this handle to {@code expected}, the state the caller needs in order to proceed.
   *
   * @throws KeyBackupStorageException reporting the state actually observed, if it is not {@code
   *     expected}
   */
  default <T extends BackupHandle> T expect(Class<T> expected) throws KeyBackupStorageException {
    if (expected.isInstance(this)) {
      return expected.cast(this);
    }
    throw asException();
  }

  /** Returns the exception reporting this state to a caller that needed a different one. */
  KeyBackupStorageException asException();

  /** All backup artifacts exist for {@link #epoch()}, so the backup can be read. */
  non-sealed interface Complete extends BackupHandle {

    /**
     * Reads the backup artifacts for {@link #epoch()}.
     *
     * @throws KeyBackupStorageException if the artifacts could not be read or no longer form a
     *     complete backup
     */
    KeyBackup read() throws KeyBackupStorageException;

    @Override
    default KeyBackupAlreadyExistsException asException() {
      return new KeyBackupAlreadyExistsException(
          "Key backup already complete for epoch " + epoch());
    }
  }

  /** No backup artifact exists for {@link #epoch()}, so a new backup may be written. */
  non-sealed interface Empty extends BackupHandle {

    /**
     * Writes a new backup for {@link #epoch()}.
     *
     * @throws KeyBackupStorageException if an artifact already exists or could not be written
     */
    void write(KeyBackup keyBackup) throws KeyBackupStorageException;

    @Override
    default KeyBackupStorageException asException() {
      return new KeyBackupNotFoundException("Key backup absent for epoch " + epoch());
    }
  }

  /**
   * Artifacts exist but the certificate, written last as the completion sentinel, does not: the
   * backup was never completed and a write may be in progress.
   */
  record PartiallyWritten(int epoch, List<String> missingKeys) implements BackupHandle {

    public PartiallyWritten {
      missingKeys = List.copyOf(missingKeys);
    }

    @Override
    public KeyBackupStorageException asException() {
      return new KeyBackupPartiallyWrittenException(
          "Key backup partially written for epoch " + epoch + ", missing " + missingKeys);
    }
  }

  /**
   * The certificate exists but other artifacts do not: a completed backup has since lost artifacts.
   */
  record Incomplete(int epoch, List<String> missingKeys) implements BackupHandle {

    public Incomplete {
      missingKeys = List.copyOf(missingKeys);
    }

    @Override
    public KeyBackupStorageException asException() {
      return new KeyBackupIncompleteException(
          "Key backup incomplete for epoch " + epoch + ", missing " + missingKeys);
    }
  }
}
