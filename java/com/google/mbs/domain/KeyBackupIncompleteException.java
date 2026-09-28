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
 * Thrown when private key, data key, or attestation doc is missing while certificate is present in
 * the bucket.
 *
 * <p>When backup is written, the certificate is written last as a sentinel object. Object different
 * than a certificate missing from the backup is a non-transient error.
 */
public class KeyBackupIncompleteException extends KeyBackupStorageException {

  public KeyBackupIncompleteException(String message) {
    super(message);
  }

  public KeyBackupIncompleteException(String message, Throwable cause) {
    super(message, cause);
  }
}
