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
 * Interface for reloading the measurement-bound certificate from backing storage.
 *
 * <p>Separates control-plane refresh operations from the read-only data plane exposed by {@link
 * MeasurementBoundCertificateProvider}.
 */
public interface MeasurementBoundCertificateReloader {

  /**
   * Synchronously reloads or generates the certificate from backing storage, updating the active
   * certificate in place.
   *
   * @throws RuntimeException if loading or generating the certificate fails
   */
  void reloadCertificate();
}
