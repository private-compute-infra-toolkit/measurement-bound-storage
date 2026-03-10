/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.kmsclient;

/** Interface for Key Management Service operations. */
public interface KmsClientInterface {

  /**
   * Generates a data key.
   *
   * @param keyId The ID or ARN of the master key.
   * @return KmsGeneratedKey containing the plaintext and ciphertext key.
   * @throws KmsException if an error occurs during key generation.
   */
  KmsGeneratedKey generateDataKey(String keyId) throws KmsException;

  /**
   * Decrypts the given ciphertext.
   *
   * @param ciphertext The encrypted data.
   * @param keyId The ID or ARN of the key used for encryption.
   * @return The decrypted plaintext.
   * @throws KmsException if an error occurs during decryption.
   */
  byte[] decrypt(byte[] ciphertext, String keyId) throws KmsException;
}
