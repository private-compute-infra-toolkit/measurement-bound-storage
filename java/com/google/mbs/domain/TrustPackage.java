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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * Container holding lists of active measurement-bound bundles and cross-certificates.
 *
 * @param bundles list of active measurement-bound bundles
 * @param crossSignedCertificates list of cross-signed X.509 certificates
 */
public record TrustPackage(
    List<MeasurementBoundCertificate> bundles, List<X509Certificate> crossSignedCertificates) {

  public TrustPackage {
    Objects.requireNonNull(bundles, "bundles must not be null");
    Objects.requireNonNull(crossSignedCertificates, "crossSignedCertificates must not be null");
  }
}
