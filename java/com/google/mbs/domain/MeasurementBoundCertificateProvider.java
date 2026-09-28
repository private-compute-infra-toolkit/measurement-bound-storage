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

package com.google.mbs.domain;

/**
 * Thread-safe provider for active {@link TrustPackage}. Enforces atomic retrieval of matching root
 * keys, certificates, and cross-certificates.
 */
public interface MeasurementBoundCertificateProvider {

  /**
   * Returns the current active trust package containing measurement-bound certificates and
   * cross-certificates.
   *
   * <p>This method is lock-free and non-blocking. It returns the current in-memory active trust
   * package.
   *
   * @throws IllegalStateException if the certificates have not been loaded or initialized yet.
   */
  TrustPackage getActiveTrustPackage();
}
