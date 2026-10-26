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

/**
 * Observed state of a cross-signed certificate backup in storage, and the operations that state
 * permits.
 *
 * <p>The state is derived from object existence alone, so it says nothing about the integrity of
 * the stored bytes. It may also be stale: storage can change between the listing that produced the
 * handle and the operation invoked on it.
 */
public sealed interface CrossSignedCertificateBackupHandle
    permits CrossSignedCertificateBackupHandle.Complete, CrossSignedCertificateBackupHandle.Empty {

  /** Returns the cross-signed certificate identifier this handle describes. */
  CrossSignedCertificateId id();

  /**
   * Narrows this handle to {@code expected}, the state the caller needs in order to proceed.
   *
   * @throws BackupStorageException reporting the state actually observed, if it is not {@code
   *     expected}
   */
  default <T extends CrossSignedCertificateBackupHandle> T expect(Class<T> expected)
      throws BackupStorageException {
    if (expected.isInstance(this)) {
      return expected.cast(this);
    }
    throw asException();
  }

  /** Returns the exception reporting this state to a caller that needed a different one. */
  BackupStorageException asException();

  /** The cross-signed certificate backup exists for {@link #id()}, so it can be read. */
  non-sealed interface Complete extends CrossSignedCertificateBackupHandle {

    /**
     * Reads the cross-signed certificate backup for {@link #id()}.
     *
     * @throws BackupStorageException if the certificate could not be read or is no longer present
     */
    CrossSignedCertificateBackup read() throws BackupStorageException;

    @Override
    default BackupAlreadyExistsException asException() {
      return new BackupAlreadyExistsException(
          "Cross-signed certificate already exists for " + id().toKeyString());
    }
  }

  /** No cross-signed certificate backup exists for {@link #id()}, so a new one may be written. */
  non-sealed interface Empty extends CrossSignedCertificateBackupHandle {

    /**
     * Writes a new cross-signed certificate backup for {@link #id()}.
     *
     * @throws BackupStorageException if the certificate already exists or could not be written
     */
    void write(CrossSignedCertificateBackup backup) throws BackupStorageException;

    @Override
    default BackupStorageException asException() {
      return new BackupNotFoundException(
          "Cross-signed certificate absent for " + id().toKeyString());
    }
  }
}
