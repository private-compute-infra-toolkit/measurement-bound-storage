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

package com.google.tlog;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

/** Interface for interacting with a transparency log. */
public interface TransparencyLogClient {

  /**
   * Records the given certificate in the transparency log.
   *
   * @param certificate The X.509 certificate to record.
   * @param privateKey The private key used to sign the certificate.
   * @return TlogEntry containing the signature and the log entry details.
   * @throws Exception if an error occurs during the process.
   */
  TlogEntry recordCertificate(X509Certificate certificate, PrivateKey privateKey) throws Exception;

  /**
   * Retrieves a transparency log entry by the certificate.
   *
   * @param certificate The X.509 certificate to search for.
   * @return Optional containing the TlogEntry if found, empty otherwise.
   * @throws Exception if an error occurs during the process.
   */
  Optional<TlogEntry> getTlogEntryByCertificate(X509Certificate certificate) throws Exception;
}
