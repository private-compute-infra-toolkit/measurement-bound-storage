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

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class KeyBackupBucketPropertiesFactoryTest {
  final String publicBucketName = "test_public";
  final String privateBucketName = "test_private";

  @Test
  public void factory_creates_properties_with_defaults() {
    KeyBackupBucketProperties properties =
        new KeyBackupBucketPropertiesFactory(publicBucketName, privateBucketName).create();

    assertEquals(publicBucketName, properties.getPublicBucketName());
    assertEquals(privateBucketName, properties.getPrivateBucketName());
    assertEquals("private/0/root_data_key.kms", properties.getKmsEncryptedDataKeyPath());
    assertEquals("private/0/root_private_key.aes", properties.getAesEncryptedPrivateKeyPath());
    assertEquals("public/0/root_certificate.pem", properties.getCertPath());
    assertEquals("public/0/attestation_doc.base64", properties.getAttestationDocPath());
    assertEquals("public/0/cert_tlog_entry.json", properties.getTlogEntryPath());
    assertEquals("public, max-age=120", properties.getCacheControl());
  }
}
