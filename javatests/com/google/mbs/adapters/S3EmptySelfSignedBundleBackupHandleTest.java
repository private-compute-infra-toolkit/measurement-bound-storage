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

import static org.mockito.Mockito.verify;

import com.google.mbs.domain.SelfSignedBundleBackup;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class S3EmptySelfSignedBundleBackupHandleTest {

  @Mock private S3BackupWriter writer;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void write_delegatesToWriter() throws Exception {
    S3EmptySelfSignedBundleBackupHandle handle = new S3EmptySelfSignedBundleBackupHandle(0, writer);
    SelfSignedBundleBackup backup =
        new SelfSignedBundleBackup(
            "cert".getBytes(StandardCharsets.UTF_8),
            "kmsKey".getBytes(StandardCharsets.UTF_8),
            "privKey".getBytes(StandardCharsets.UTF_8),
            "attestation".getBytes(StandardCharsets.UTF_8));

    handle.write(backup);

    verify(writer).writeSelfSignedBundleBackup(0, backup);
  }
}
