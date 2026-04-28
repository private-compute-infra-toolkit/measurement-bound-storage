/*
 * Copyright 2025 Google LLC
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

package com.google.mbs.attestationcollection.aws;

import com.google.mbs.attestationcollection.AttestationCollector;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.platform.aws.nsm.NitroSecurityModule;
import com.google.platform.aws.nsm.NitroSecurityModuleFactory;
import jakarta.inject.Inject;
import java.security.PublicKey;
import java.util.Optional;

/** AWS Nitro Enclave implementation of {@link AttestationCollector}. */
public class AwsAttestationCollector implements AttestationCollector {

  private final NitroSecurityModuleFactory nsmFactory;

  @Inject
  public AwsAttestationCollector(NitroSecurityModuleFactory nsmFactory) {
    this.nsmFactory = nsmFactory;
  }

  /**
   * Collects an attestation token bound to the provided public key.
   *
   * @throws IllegalArgumentException if the public key is too large.
   */
  @Override
  public AttestationToken collectBoundToPubkey(PublicKey publicKey) {
    byte[] pubkey = publicKey.getEncoded();
    validateSize(pubkey, "Public key");

    try (NitroSecurityModule nsm = nsmFactory.create()) {
      var doc = nsm.getAttestationDocument(Optional.empty(), Optional.empty(), Optional.of(pubkey));
      return AttestationToken.fromBytes(doc);
    }
  }

  /**
   * Collects an attestation token bound to the provided public key and user data.
   *
   * @throws IllegalArgumentException if the public key or user data is too large.
   */
  @Override
  public AttestationToken collectBoundToPubkey(PublicKey publicKey, byte[] userData) {
    byte[] pubkey = publicKey.getEncoded();
    validateSize(pubkey, "Public key");
    validateSize(userData, "User data");

    try (NitroSecurityModule nsm = nsmFactory.create()) {
      var doc =
          nsm.getAttestationDocument(Optional.of(userData), Optional.empty(), Optional.of(pubkey));
      return AttestationToken.fromBytes(doc);
    }
  }

  private void validateSize(byte[] data, String description) {
    final int MAX_USER_DATA_SIZE = 1024;
    if (data.length > MAX_USER_DATA_SIZE) {
      throw new IllegalArgumentException(
          String.format("%s exceeds maximum size of %d bytes", description, MAX_USER_DATA_SIZE));
    }
  }
}
