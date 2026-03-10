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

  private static final String S3_KMS_ENCRYPTED_DATA_KEY_NAME = "tca_root_data_key.kms";
  private static final String S3_AES_ENCRYPTED_PRIVATE_KEY_NAME = "tca_root_private_key.aes";
  private static final String S3_CERT_NAME = "tca_root_certificate.pem";
  private static final String S3_ATTESTATION_DOC_NAME = "attestation_doc.base64";
  private static final String S3_TLOG_ENTRY_NAME = "tca_root_tlog_entry.json";

  private final String bucketName;

  public KeyBackupBucketPropertiesFactory(String bucketName) {
    this.bucketName = bucketName;
  }

  public KeyBackupBucketProperties create() {
    return KeyBackupBucketProperties.builder()
        .setBucketName(bucketName)
        .setKmsEncryptedDataKeyPath(S3_KMS_ENCRYPTED_DATA_KEY_NAME)
        .setAesEncryptedPrivateKeyPath(S3_AES_ENCRYPTED_PRIVATE_KEY_NAME)
        .setCertPath(S3_CERT_NAME)
        .setAttestationDocPath(S3_ATTESTATION_DOC_NAME)
        .setTlogEntryPath(S3_TLOG_ENTRY_NAME)
        .build();
  }
}
