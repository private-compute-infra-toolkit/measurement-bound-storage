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

/** Interface for generating MBS certificates and storing their backups in backing storage. */
public interface CertificateGenerator {

  /**
   * Synchronously generates new certificates and stores their backups in backing storage if none
   * exist yet.
   *
   * @param config certificates configuration describing the certificates to generate
   * @throws RuntimeException if generating or storing the certificate backup fails
   */
  void generateCertificates(CertificatesConfig config);
}
