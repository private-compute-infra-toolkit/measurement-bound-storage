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

package com.google.mbs;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.mbs.domain.BackupAlreadyExistsException;
import com.google.mbs.domain.BackupNotFoundException;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateBackupHandle;
import com.google.mbs.domain.CrossSignedCertificateId;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CrossSignedCertificateBackupHandleTest {

  private static final CrossSignedCertificateId TEST_ID = new CrossSignedCertificateId(0, 1);
  private static final CrossSignedCertificateBackup SAMPLE_BACKUP =
      new CrossSignedCertificateBackup("cross-signed-cert".getBytes(StandardCharsets.UTF_8));

  private record FakeComplete(CrossSignedCertificateId id)
      implements CrossSignedCertificateBackupHandle.Complete {
    @Override
    public CrossSignedCertificateBackup read() {
      throw new UnsupportedOperationException();
    }
  }

  private record FakeEmpty(CrossSignedCertificateId id)
      implements CrossSignedCertificateBackupHandle.Empty {
    @Override
    public void write(CrossSignedCertificateBackup backup) {
      throw new UnsupportedOperationException();
    }
  }

  @Test
  public void complete_expectComplete_returnsSelf() throws Exception {
    CrossSignedCertificateBackupHandle.Complete complete = new FakeComplete(TEST_ID);

    CrossSignedCertificateBackupHandle.Complete narrowed =
        complete.expect(CrossSignedCertificateBackupHandle.Complete.class);

    assertThat(narrowed).isSameInstanceAs(complete);
    assertThat(narrowed.id()).isEqualTo(TEST_ID);
  }

  @Test
  public void complete_expectOther_throwsAlreadyExistsException() {
    CrossSignedCertificateBackupHandle handle = new FakeComplete(TEST_ID);

    assertThrows(
        BackupAlreadyExistsException.class,
        () -> handle.expect(CrossSignedCertificateBackupHandle.Empty.class));
  }

  @Test
  public void empty_expectEmpty_returnsSelf() throws Exception {
    CrossSignedCertificateBackupHandle.Empty empty = new FakeEmpty(TEST_ID);

    CrossSignedCertificateBackupHandle.Empty narrowed =
        empty.expect(CrossSignedCertificateBackupHandle.Empty.class);

    assertThat(narrowed).isSameInstanceAs(empty);
    assertThat(narrowed.id()).isEqualTo(TEST_ID);
  }

  @Test
  public void empty_expectOther_throwsNotFoundException() {
    CrossSignedCertificateBackupHandle handle = new FakeEmpty(TEST_ID);

    assertThrows(
        BackupNotFoundException.class,
        () -> handle.expect(CrossSignedCertificateBackupHandle.Complete.class));
  }

  @Test
  public void
      crossSignedCertificateBackup_equalsHashCodeAndToString_comparesByReferenceAndContent() {
    CrossSignedCertificateBackup sameReference = SAMPLE_BACKUP;
    CrossSignedCertificateBackup clonedContent =
        new CrossSignedCertificateBackup(SAMPLE_BACKUP.certBytes().clone());

    assertThat(SAMPLE_BACKUP.equals(sameReference)).isTrue();
    assertThat(SAMPLE_BACKUP).isEqualTo(clonedContent);
    assertThat(SAMPLE_BACKUP.hashCode()).isEqualTo(clonedContent.hashCode());
    assertThat(SAMPLE_BACKUP.toString()).isEqualTo(clonedContent.toString());
    assertThat(SAMPLE_BACKUP.equals(null)).isFalse();
    assertThat(SAMPLE_BACKUP.equals("not-a-backup")).isFalse();
  }

  @Test
  public void crossSignedCertificateBackup_equalsHashCodeAndToString_mutatedCertBytes_notEqual() {
    CrossSignedCertificateBackup mutated =
        new CrossSignedCertificateBackup(SAMPLE_BACKUP.certBytes().clone());
    mutated.certBytes()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
    assertThat(SAMPLE_BACKUP.toString()).isNotEqualTo(mutated.toString());
  }
}
