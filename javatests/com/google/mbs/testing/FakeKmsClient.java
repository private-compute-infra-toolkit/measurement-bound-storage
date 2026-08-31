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

package com.google.mbs.testing;

import com.google.common.io.BaseEncoding;
import com.google.kmsclient.KmsClientInterface;
import com.google.kmsclient.KmsException;
import com.google.kmsclient.KmsGeneratedKey;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** In-memory fake KMS client for local tests. */
public final class FakeKmsClient implements KmsClientInterface {

  private final ConcurrentMap<String, byte[]> keys = new ConcurrentHashMap<>();
  private final SecureRandom random = new SecureRandom();

  @Override
  public byte[] decrypt(byte[] ciphertext, String kmsKeyArn) throws KmsException {
    String keyHex = BaseEncoding.base16().encode(ciphertext);
    byte[] plaintext = keys.get(keyHex);
    if (plaintext == null) {
      throw new KmsException("Unknown ciphertext");
    }
    return plaintext.clone();
  }

  @Override
  public KmsGeneratedKey generateDataKey(String kmsKeyArn) throws KmsException {
    byte[] plaintext = new byte[32];
    random.nextBytes(plaintext);

    byte[] ciphertext = new byte[32];
    random.nextBytes(ciphertext);

    String keyHex = BaseEncoding.base16().encode(ciphertext);
    keys.put(keyHex, plaintext.clone());

    return KmsGeneratedKey.builder().setPlaintext(plaintext).setCiphertext(ciphertext).build();
  }
}
