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

import com.google.mbs.domain.ArtifactType;

public final class S3BackupPaths {

  public static final String PRIVATE_PREFIX = "private/";
  public static final String PUBLIC_PREFIX = "public/";
  public static final String KMS_ENCRYPTED_DATA_KEY_FILE = "root_data_key.kms";
  public static final String AES_ENCRYPTED_PRIVATE_KEY_FILE = "root_private_key.aes";
  public static final String ROOT_CERT_FILE = "root_certificate.pem";
  public static final String ATTESTATION_DOC_FILE = "attestation_doc.base64";
  public static final String LOCK_PATH = PRIVATE_PREFIX + "root_generation.lock";
  public static final String CERTIFICATES_CONFIG_FILE_PATH = "certificates_config.textproto";

  private S3BackupPaths() {}

  public static String getFileName(ArtifactType artifactType) {
    return switch (artifactType) {
      case CERT -> ROOT_CERT_FILE;
      case ATTESTATION_DOC -> ATTESTATION_DOC_FILE;
      case KMS_DATA_KEY -> KMS_ENCRYPTED_DATA_KEY_FILE;
      case PRIVATE_KEY -> AES_ENCRYPTED_PRIVATE_KEY_FILE;
    };
  }

  public static String getKmsEncryptedDataKeyPath(int epoch) {
    return PRIVATE_PREFIX + epoch + "/" + KMS_ENCRYPTED_DATA_KEY_FILE;
  }

  public static String getAesEncryptedPrivateKeyPath(int epoch) {
    return PRIVATE_PREFIX + epoch + "/" + AES_ENCRYPTED_PRIVATE_KEY_FILE;
  }

  public static String getRootCertPath(int epoch) {
    return PUBLIC_PREFIX + epoch + "/" + ROOT_CERT_FILE;
  }

  public static String getAttestationDocPath(int epoch) {
    return PUBLIC_PREFIX + epoch + "/" + ATTESTATION_DOC_FILE;
  }

  public static String getLockPath() {
    return LOCK_PATH;
  }
}
