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

package com.google.mbs;

/** Storage port for storing and retrieving MBS certificate, key, and attestation artifacts. */
public interface KeyBackupStorage {

  byte[] getCertBytes() throws KeyBackupNotFoundException;

  byte[] getKmsEncryptedDataKey() throws KeyBackupNotFoundException;

  byte[] getAeadEncryptedPrivateKey() throws KeyBackupNotFoundException;

  byte[] getAttestationDocBytes() throws KeyBackupNotFoundException;

  void putCertBytes(byte[] content);

  void putKmsEncryptedDataKey(byte[] content);

  void putAeadEncryptedPrivateKey(byte[] content);

  void putAttestationDocBytes(byte[] content);
}
