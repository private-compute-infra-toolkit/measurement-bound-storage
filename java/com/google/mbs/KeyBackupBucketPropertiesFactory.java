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

public class KeyBackupBucketPropertiesFactory {

  private static final String S3_KMS_ENCRYPTED_DATA_KEY_NAME = "private/0/root_data_key.kms";
  private static final String S3_AES_ENCRYPTED_PRIVATE_KEY_NAME = "private/0/root_private_key.aes";
  private static final String S3_CERT_NAME = "public/0/root_certificate.pem";
  private static final String S3_ATTESTATION_DOC_NAME = "public/0/attestation_doc.base64";
  private static final String S3_TLOG_ENTRY_NAME = "public/0/cert_tlog_entry.json";
  private static final String DEFAULT_CACHE_CONTROL = "public, max-age=120";

  private final String publicBucketName;
  private final String privateBucketName;

  public KeyBackupBucketPropertiesFactory(String publicBucketName, String privateBucketName) {
    this.publicBucketName = publicBucketName;
    this.privateBucketName = privateBucketName;
  }

  /**
   * @deprecated Use {@link #KeyBackupBucketPropertiesFactory(String, String)} instead. This
   *     constructor is kept for backward compatibility and uses the same bucket for both public and
   *     private data.
   */
  @Deprecated
  public KeyBackupBucketPropertiesFactory(String bucketName) {
    this(bucketName, bucketName);
  }

  public KeyBackupBucketProperties create() {
    return KeyBackupBucketProperties.builder()
        .setPublicBucketName(publicBucketName)
        .setPrivateBucketName(privateBucketName)
        .setKmsEncryptedDataKeyPath(S3_KMS_ENCRYPTED_DATA_KEY_NAME)
        .setAesEncryptedPrivateKeyPath(S3_AES_ENCRYPTED_PRIVATE_KEY_NAME)
        .setCertPath(S3_CERT_NAME)
        .setAttestationDocPath(S3_ATTESTATION_DOC_NAME)
        .setTlogEntryPath(S3_TLOG_ENTRY_NAME)
        .setCacheControl(DEFAULT_CACHE_CONTROL)
        .build();
  }
}
