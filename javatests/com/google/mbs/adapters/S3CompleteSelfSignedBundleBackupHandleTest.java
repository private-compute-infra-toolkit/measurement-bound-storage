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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.SelfSignedBundleBackup;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class S3CompleteSelfSignedBundleBackupHandleTest {

  @Mock private S3BackupReader reader;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void read_memoizesUnderlyingReaderCall() throws Exception {
    SelfSignedBundleBackup expected =
        new SelfSignedBundleBackup(
            "cert".getBytes(StandardCharsets.UTF_8),
            "kmsKey".getBytes(StandardCharsets.UTF_8),
            "privKey".getBytes(StandardCharsets.UTF_8),
            "attestation".getBytes(StandardCharsets.UTF_8));
    when(reader.readSelfSignedBundleBackup(0)).thenReturn(expected);
    S3CompleteSelfSignedBundleBackupHandle handle =
        new S3CompleteSelfSignedBundleBackupHandle(
            0, reader, new EnumMap<>(SelfSignedBundleBackupElement.class));

    assertThat(handle.read()).isSameInstanceAs(expected);
    assertThat(handle.read()).isSameInstanceAs(expected);
    verify(reader, times(1)).readSelfSignedBundleBackup(0);
  }
}
