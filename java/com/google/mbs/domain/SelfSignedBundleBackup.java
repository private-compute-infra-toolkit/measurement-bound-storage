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

import java.util.Arrays;
import java.util.Objects;

/**
 * Raw byte representation of a self-signed bundle backup stored in backup storage.
 *
 * @param certBytes PEM-encoded X.509 certificate bytes
 * @param kmsEncryptedDataKey KMS-encrypted AES data key bytes
 * @param aeadEncryptedPrivateKey AEAD-encrypted PKCS#8 private key bytes
 * @param attestationDocBytes raw attestation document bytes bound to the public key
 */
public record SelfSignedBundleBackup(
    byte[] certBytes,
    byte[] kmsEncryptedDataKey,
    byte[] aeadEncryptedPrivateKey,
    byte[] attestationDocBytes) {

  public SelfSignedBundleBackup {
    Objects.requireNonNull(certBytes);
    Objects.requireNonNull(kmsEncryptedDataKey);
    Objects.requireNonNull(aeadEncryptedPrivateKey);
    Objects.requireNonNull(attestationDocBytes);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof SelfSignedBundleBackup that)) {
      return false;
    }
    return Arrays.equals(certBytes, that.certBytes)
        && Arrays.equals(kmsEncryptedDataKey, that.kmsEncryptedDataKey)
        && Arrays.equals(aeadEncryptedPrivateKey, that.aeadEncryptedPrivateKey)
        && Arrays.equals(attestationDocBytes, that.attestationDocBytes);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        Arrays.hashCode(certBytes),
        Arrays.hashCode(kmsEncryptedDataKey),
        Arrays.hashCode(aeadEncryptedPrivateKey),
        Arrays.hashCode(attestationDocBytes));
  }

  @Override
  public String toString() {
    return "SelfSignedBundleBackup[certBytes="
        + Arrays.toString(certBytes)
        + ", kmsEncryptedDataKey="
        + Arrays.toString(kmsEncryptedDataKey)
        + ", aeadEncryptedPrivateKey="
        + Arrays.toString(aeadEncryptedPrivateKey)
        + ", attestationDocBytes="
        + Arrays.toString(attestationDocBytes)
        + "]";
  }
}
