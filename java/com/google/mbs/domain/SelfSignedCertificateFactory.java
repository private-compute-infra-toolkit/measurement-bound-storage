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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

/** Strategy for generating self-signed X.509 certificates and KeyPairs. */
@FunctionalInterface
public interface SelfSignedCertificateFactory {

  record X509CertificateAndPrivateKey(X509Certificate certificate, PrivateKey privateKey) {
    public X509CertificateAndPrivateKey {
      Objects.requireNonNull(certificate);
      Objects.requireNonNull(privateKey);
    }
  }

  class SelfSignedCertificateFactoryException extends RuntimeException {
    public SelfSignedCertificateFactoryException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Generates a certificate and private key.
   *
   * @param params parameters for the self-signed certificate.
   * @return A bundle containing the certificate and private key.
   * @throws RuntimeException if generation fails.
   */
  X509CertificateAndPrivateKey generate(SelfSignedCertificate params);
}
