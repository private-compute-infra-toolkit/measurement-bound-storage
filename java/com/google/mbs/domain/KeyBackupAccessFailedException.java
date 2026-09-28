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
 * Thrown when the backup storage could not be reached, e.g. a transport, permission or availability
 * failure. Says nothing about whether a backup exists or what it contains.
 */
public class KeyBackupAccessFailedException extends KeyBackupStorageException {

  public KeyBackupAccessFailedException(String message) {
    super(message);
  }

  public KeyBackupAccessFailedException(String message, Throwable cause) {
    super(message, cause);
  }
}
