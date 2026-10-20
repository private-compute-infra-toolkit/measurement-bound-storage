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
 * Observed state of a cross-signed certificate in storage, and the operations that state permits.
 *
 * <p>The state is derived from object existence alone, so it says nothing about the integrity of
 * the stored bytes. It may also be stale: storage can change between the listing that produced the
 * handle and the operation invoked on it.
 */
public sealed interface CrossSignedCertHandle
    permits CrossSignedCertHandle.Complete, CrossSignedCertHandle.Empty {

  /** Returns the cross-signed certificate identifier this handle describes. */
  CrossSignedCertificateId id();

  /**
   * Narrows this handle to {@code expected}, the state the caller needs in order to proceed.
   *
   * @throws KeyBackupStorageException reporting the state actually observed, if it is not {@code
   *     expected}
   */
  default <T extends CrossSignedCertHandle> T expect(Class<T> expected)
      throws KeyBackupStorageException {
    if (expected.isInstance(this)) {
      return expected.cast(this);
    }
    throw asException();
  }

  /** Returns the exception reporting this state to a caller that needed a different one. */
  KeyBackupStorageException asException();

  /** The cross-signed certificate exists for {@link #id()}, so it can be read. */
  non-sealed interface Complete extends CrossSignedCertHandle {

    /**
     * Reads the cross-signed certificate for {@link #id()}.
     *
     * @throws KeyBackupStorageException if the certificate could not be read or is no longer
     *     present
     */
    CrossSignedCertificateBackup read() throws KeyBackupStorageException;

    @Override
    default KeyBackupAlreadyExistsException asException() {
      return new KeyBackupAlreadyExistsException(
          "Cross-signed certificate already exists for " + id().toKeyString());
    }
  }

  /** No cross-signed certificate exists for {@link #id()}, so a new one may be written. */
  non-sealed interface Empty extends CrossSignedCertHandle {

    /**
     * Writes a new cross-signed certificate for {@link #id()}.
     *
     * @throws KeyBackupStorageException if the certificate already exists or could not be written
     */
    void write(CrossSignedCertificateBackup backup) throws KeyBackupStorageException;

    @Override
    default KeyBackupStorageException asException() {
      return new KeyBackupNotFoundException(
          "Cross-signed certificate absent for " + id().toKeyString());
    }
  }
}
