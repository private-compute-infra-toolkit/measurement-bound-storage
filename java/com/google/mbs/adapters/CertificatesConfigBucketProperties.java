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

package com.google.mbs.adapters;

import java.util.Objects;

/**
 * Configuration properties for the certificates configuration bucket.
 *
 * @param bucketName Name of the bucket hosting the rotations configuration.
 * @param configFileName File key / name of the rotations textproto within the bucket.
 */
public record CertificatesConfigBucketProperties(String bucketName, String configFileName) {
  public CertificatesConfigBucketProperties {
    Objects.requireNonNull(bucketName);
    Objects.requireNonNull(configFileName);
  }
}
