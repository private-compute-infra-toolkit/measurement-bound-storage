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
 * Identifier of a cross-signed certificate, pairing the signing {@code privateKeyEpochId} with the
 * signed {@code publicKeyEpochId}.
 */
public record CrossSignedCertificateId(int privateKeyEpochId, int publicKeyEpochId) {

  public CrossSignedCertificateId {
    if (privateKeyEpochId == publicKeyEpochId) {
      throw new IllegalArgumentException(
          String.format(
              "privateKeyEpochId (%d) must not equal publicKeyEpochId (%d)",
              privateKeyEpochId, publicKeyEpochId));
    }
  }

  /** Returns the canonical {@code "<privateKeyEpochId>_<publicKeyEpochId>"} key representation. */
  public String toKeyString() {
    return privateKeyEpochId + "_" + publicKeyEpochId;
  }

  /**
   * Parses a canonical {@code "<privateKeyEpochId>_<publicKeyEpochId>"} string into a {@link
   * CrossSignedCertificateId}.
   *
   * @throws IllegalArgumentException if {@code keyString} is not a canonical pair of distinct
   *     integers separated by {@code '_'}
   */
  public static CrossSignedCertificateId fromKeyString(String keyString) {
    String[] parts = keyString.split("_", -1);
    if (parts.length != 2) {
      throw new IllegalArgumentException(
          "Invalid CrossSignedCertificateId key string: " + keyString);
    }
    int privateKeyEpochId;
    int publicKeyEpochId;
    try {
      privateKeyEpochId = Integer.parseInt(parts[0]);
      publicKeyEpochId = Integer.parseInt(parts[1]);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          String.format("Non-integer epoch in cross-signed key '%s'", keyString), e);
    }
    CrossSignedCertificateId id = new CrossSignedCertificateId(privateKeyEpochId, publicKeyEpochId);
    if (!id.toKeyString().equals(keyString)) {
      throw new IllegalArgumentException(
          String.format(
              "Non-canonical cross-signed key '%s': expected '%s'", keyString, id.toKeyString()));
    }
    return id;
  }
}
