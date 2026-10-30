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

package com.google.mbs.adapters;

import com.google.auto.value.AutoValue;

/** Configuration properties for the S3 backup buckets. */
@AutoValue
public abstract class BackupBucketProperties {

  public static BackupBucketProperties.Builder builder() {
    return new AutoValue_BackupBucketProperties.Builder();
  }

  public abstract String getPublicBucketName();

  public abstract String getPrivateBucketName();

  public abstract String getCacheControl();

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract BackupBucketProperties.Builder setPublicBucketName(String value);

    public abstract BackupBucketProperties.Builder setPrivateBucketName(String value);

    public abstract BackupBucketProperties.Builder setCacheControl(String value);

    public abstract BackupBucketProperties build();
  }
}
