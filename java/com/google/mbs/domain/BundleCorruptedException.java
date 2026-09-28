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
 * Thrown when a complete key backup was retrieved but its contents cannot be used: an artifact does
 * not parse, cannot be decrypted, or the private key does not belong to the certificate.
 */
public class BundleCorruptedException extends Exception {

  public BundleCorruptedException(String message) {
    super(message);
  }

  public BundleCorruptedException(String message, Throwable cause) {
    super(message, cause);
  }
}
