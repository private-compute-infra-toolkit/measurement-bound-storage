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

package com.google.mbs.domain;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * A container for an {@link X509Certificate}, corresponding {@link PrivateKey} and {@link
 * AttestationToken}.
 */
public record MeasurementBoundBundle(
    X509Certificate certificate, PrivateKey privateKey, AttestationToken attestationToken) {

  public MeasurementBoundBundle {
    Objects.requireNonNull(certificate);
    Objects.requireNonNull(privateKey);
    Objects.requireNonNull(attestationToken);
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public AttestationToken getAttestationToken() {
    return attestationToken;
  }
}
