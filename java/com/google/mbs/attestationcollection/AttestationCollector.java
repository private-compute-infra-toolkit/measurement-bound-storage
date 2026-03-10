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

package com.google.mbs.attestationcollection;

import java.security.PublicKey;

public interface AttestationCollector {
  /**
   * Collects an attestation token from the TEE.
   *
   * @param publicKey {@link PublicKey} to bind the attestation to.
   * @return the {@link AttestationToken}.
   */
  AttestationToken collectBoundToPubkey(PublicKey publicKey);

  /**
   * Collects an attestation token from the TEE.
   *
   * @param publicKey {@link PublicKey} to bind the attestation to.
   * @param userData User data to bind to the attestation.
   * @return the {@link AttestationToken}.
   */
  AttestationToken collectBoundToPubkey(PublicKey publicKey, byte[] userData);
}
