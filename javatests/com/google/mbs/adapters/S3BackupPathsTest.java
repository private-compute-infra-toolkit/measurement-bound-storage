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

import static com.google.common.truth.Truth.assertThat;

import com.google.mbs.domain.CrossSignedCertificateId;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class S3BackupPathsTest {

  @Test
  public void returnsExpectedEpochPathsAndLockPath() {
    assertThat(S3BackupPaths.getKmsEncryptedDataKeyPath(0))
        .isEqualTo("private/0/root_data_key.kms");
    assertThat(S3BackupPaths.getAesEncryptedPrivateKeyPath(0))
        .isEqualTo("private/0/root_private_key.aes");
    assertThat(S3BackupPaths.getRootCertPath(0)).isEqualTo("public/0/root_certificate.pem");
    assertThat(S3BackupPaths.getAttestationDocPath(0)).isEqualTo("public/0/attestation_doc.base64");
    assertThat(S3BackupPaths.getLockPath()).isEqualTo("private/root_generation.lock");

    assertThat(S3BackupPaths.getKmsEncryptedDataKeyPath(1))
        .isEqualTo("private/1/root_data_key.kms");
    assertThat(S3BackupPaths.getAesEncryptedPrivateKeyPath(1))
        .isEqualTo("private/1/root_private_key.aes");
    assertThat(S3BackupPaths.getRootCertPath(1)).isEqualTo("public/1/root_certificate.pem");
    assertThat(S3BackupPaths.getAttestationDocPath(1)).isEqualTo("public/1/attestation_doc.base64");
  }

  @Test
  public void getCrossSignedCertificatePath_returnsExpectedPath() {
    assertThat(S3BackupPaths.getCrossSignedCertificatePath(new CrossSignedCertificateId(0, 1)))
        .isEqualTo("public/cross-signed/0_1/cross_signed_certificate.pem");
    assertThat(S3BackupPaths.getCrossSignedCertificatePath(new CrossSignedCertificateId(1, 0)))
        .isEqualTo("public/cross-signed/1_0/cross_signed_certificate.pem");
  }

  @Test
  public void getFileName_returnsExpectedFileNameForEachSelfSignedBundleBackupElement() {
    assertThat(S3BackupPaths.getFileName(SelfSignedBundleBackupElement.CERT))
        .isEqualTo("root_certificate.pem");
    assertThat(S3BackupPaths.getFileName(SelfSignedBundleBackupElement.ATTESTATION_DOC))
        .isEqualTo("attestation_doc.base64");
    assertThat(S3BackupPaths.getFileName(SelfSignedBundleBackupElement.KMS_DATA_KEY))
        .isEqualTo("root_data_key.kms");
    assertThat(S3BackupPaths.getFileName(SelfSignedBundleBackupElement.PRIVATE_KEY))
        .isEqualTo("root_private_key.aes");
  }
}
