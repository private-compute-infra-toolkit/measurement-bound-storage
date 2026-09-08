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
 * Lifecycle interface for the host service (e.g., TCA) to control background certificate
 * monitoring.
 */
public interface CertificateMonitor {

  /** Starts the background certificate monitor service. */
  void start();

  /** Stops the background certificate monitor service. */
  void stop();

  /** Returns whether the certificate monitor service is currently running. */
  boolean isRunning();
}
