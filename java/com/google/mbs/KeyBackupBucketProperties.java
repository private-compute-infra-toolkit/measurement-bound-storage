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

package com.google.mbs;

import com.google.auto.value.AutoValue;

@AutoValue
public abstract class KeyBackupBucketProperties {

  public static KeyBackupBucketProperties.Builder builder() {
    return new AutoValue_KeyBackupBucketProperties.Builder();
  }

  public abstract String getPublicBucketName();

  public abstract String getPrivateBucketName();

  public abstract String getKmsEncryptedDataKeyPath();

  public abstract String getAesEncryptedPrivateKeyPath();

  public abstract String getCertPath();

  public abstract String getAttestationDocPath();

  public abstract String getTlogEntryPath();

  public abstract String getCacheControl();

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract KeyBackupBucketProperties.Builder setPublicBucketName(String value);

    public abstract KeyBackupBucketProperties.Builder setPrivateBucketName(String value);

    public abstract KeyBackupBucketProperties.Builder setKmsEncryptedDataKeyPath(String value);

    public abstract KeyBackupBucketProperties.Builder setAesEncryptedPrivateKeyPath(String value);

    public abstract KeyBackupBucketProperties.Builder setCertPath(String value);

    public abstract KeyBackupBucketProperties.Builder setAttestationDocPath(String value);

    public abstract KeyBackupBucketProperties.Builder setTlogEntryPath(String value);

    public abstract KeyBackupBucketProperties.Builder setCacheControl(String value);

    public abstract KeyBackupBucketProperties build();
  }
}
