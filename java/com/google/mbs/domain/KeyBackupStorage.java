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

import org.jspecify.annotations.NonNull;

/** Storage port for storing and retrieving MBS certificate, key, and attestation artifacts. */
public interface KeyBackupStorage {

  /**
   * Acquires an exclusive lock on backup storage for certificate generation.
   *
   * @throws StorageAlreadyLockedException if the lock is already held by another instance
   * @throws KeyBackupAccessFailedException if the lock could not be written
   */
  void acquireLock() throws StorageAlreadyLockedException, KeyBackupAccessFailedException;

  /**
   * Releases the certificate generation lock upon successful artifact creation.
   *
   * @throws KeyBackupAccessFailedException if the lock could not be removed
   */
  void releaseLock() throws KeyBackupAccessFailedException;

  /**
   * Retrieves the complete key backup.
   *
   * @throws KeyBackupNotFoundException if no artifact exists at all
   * @throws KeyBackupPartiallyWrittenException if artifacts are missing and the certificate is one
   *     of them, proving the backup was never completed
   * @throws KeyBackupIncompleteException if a completed backup is missing artifacts
   * @throws KeyBackupAccessFailedException if the artifacts could not be read
   */
  @NonNull KeyBackup getKeyBackup()
      throws KeyBackupNotFoundException,
          KeyBackupPartiallyWrittenException,
          KeyBackupIncompleteException,
          KeyBackupAccessFailedException;

  /**
   * Stores the complete key backup.
   *
   * <p>Implementations must write the certificate last, so that it acts as a completion sentinel
   * for concurrent readers.
   *
   * @throws KeyBackupAccessFailedException if any artifact could not be written
   */
  void putKeyBackup(KeyBackup keyBackup) throws KeyBackupAccessFailedException;
}
