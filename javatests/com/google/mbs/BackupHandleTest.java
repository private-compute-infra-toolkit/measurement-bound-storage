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

import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.KeyBackup;
import com.google.mbs.domain.KeyBackupAlreadyExistsException;
import com.google.mbs.domain.KeyBackupIncompleteException;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupPartiallyWrittenException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class BackupHandleTest {

  private static final int TEST_EPOCH = 42;
  private static final KeyBackup SAMPLE_BACKUP =
      new KeyBackup(
          "cert".getBytes(StandardCharsets.UTF_8),
          "kmsKey".getBytes(StandardCharsets.UTF_8),
          "privKey".getBytes(StandardCharsets.UTF_8),
          "attestation".getBytes(StandardCharsets.UTF_8));

  private record FakeComplete(int epoch) implements BackupHandle.Complete {
    @Override
    public KeyBackup read() {
      throw new UnsupportedOperationException();
    }
  }

  private record FakeEmpty(int epoch) implements BackupHandle.Empty {
    @Override
    public void write(KeyBackup keyBackup) {
      throw new UnsupportedOperationException();
    }
  }

  @Test
  public void complete_expectComplete_returnsSelf() throws Exception {
    BackupHandle.Complete complete = new FakeComplete(TEST_EPOCH);

    BackupHandle.Complete narrowed = complete.expect(BackupHandle.Complete.class);

    assertThat(narrowed).isSameInstanceAs(complete);
    assertThat(narrowed.epoch()).isEqualTo(TEST_EPOCH);
  }

  @Test
  public void complete_expectOther_throwsAlreadyExistsException() {
    BackupHandle handle = new FakeComplete(TEST_EPOCH);

    assertThrows(
        KeyBackupAlreadyExistsException.class, () -> handle.expect(BackupHandle.Empty.class));
  }

  @Test
  public void empty_expectEmpty_returnsSelf() throws Exception {
    BackupHandle.Empty empty = new FakeEmpty(TEST_EPOCH);

    BackupHandle.Empty narrowed = empty.expect(BackupHandle.Empty.class);

    assertThat(narrowed).isSameInstanceAs(empty);
    assertThat(narrowed.epoch()).isEqualTo(TEST_EPOCH);
  }

  @Test
  public void empty_expectOther_throwsNotFoundException() {
    BackupHandle handle = new FakeEmpty(TEST_EPOCH);

    assertThrows(
        KeyBackupNotFoundException.class, () -> handle.expect(BackupHandle.Complete.class));
  }

  @Test
  public void partiallyWritten_expectPartiallyWritten_returnsSelf() throws Exception {
    List<String> missing = List.of("public/42/root_certificate.pem");
    BackupHandle.PartiallyWritten partiallyWritten =
        new BackupHandle.PartiallyWritten(TEST_EPOCH, missing);

    BackupHandle.PartiallyWritten narrowed =
        partiallyWritten.expect(BackupHandle.PartiallyWritten.class);

    assertThat(narrowed).isSameInstanceAs(partiallyWritten);
    assertThat(narrowed.epoch()).isEqualTo(TEST_EPOCH);
    assertThat(narrowed.missingKeys()).isEqualTo(missing);
  }

  @Test
  public void partiallyWritten_expectOther_throwsPartiallyWrittenException() {
    List<String> missing = List.of("public/42/root_certificate.pem");
    BackupHandle handle = new BackupHandle.PartiallyWritten(TEST_EPOCH, missing);

    assertThrows(
        KeyBackupPartiallyWrittenException.class, () -> handle.expect(BackupHandle.Complete.class));
  }

  @Test
  public void incomplete_expectIncomplete_returnsSelf() throws Exception {
    List<String> missing = List.of("private/42/root_data_key.kms");
    BackupHandle.Incomplete incomplete = new BackupHandle.Incomplete(TEST_EPOCH, missing);

    BackupHandle.Incomplete narrowed = incomplete.expect(BackupHandle.Incomplete.class);

    assertThat(narrowed).isSameInstanceAs(incomplete);
    assertThat(narrowed.epoch()).isEqualTo(TEST_EPOCH);
    assertThat(narrowed.missingKeys()).isEqualTo(missing);
  }

  @Test
  public void incomplete_expectOther_throwsIncompleteException() {
    List<String> missing = List.of("private/42/root_data_key.kms");
    BackupHandle handle = new BackupHandle.Incomplete(TEST_EPOCH, missing);

    assertThrows(
        KeyBackupIncompleteException.class, () -> handle.expect(BackupHandle.Complete.class));
  }

  private static KeyBackup clone(KeyBackup source) {
    return new KeyBackup(
        source.certBytes().clone(),
        source.kmsEncryptedDataKey().clone(),
        source.aeadEncryptedPrivateKey().clone(),
        source.attestationDocBytes().clone());
  }

  @Test
  public void keyBackup_equalsAndHashCode_comparesByReferenceAndContent() {
    KeyBackup sameReference = SAMPLE_BACKUP;
    KeyBackup clonedContent = clone(SAMPLE_BACKUP);

    assertThat(SAMPLE_BACKUP.equals(sameReference)).isTrue();
    assertThat(SAMPLE_BACKUP).isEqualTo(clonedContent);
    assertThat(SAMPLE_BACKUP.hashCode()).isEqualTo(clonedContent.hashCode());
    assertThat(SAMPLE_BACKUP.equals(null)).isFalse();
    assertThat(SAMPLE_BACKUP.equals("not-a-backup")).isFalse();
  }

  @Test
  public void keyBackup_equalsAndHashCode_mutatedCertBytes_notEqual() {
    KeyBackup mutated = clone(SAMPLE_BACKUP);
    mutated.certBytes()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
  }

  @Test
  public void keyBackup_equalsAndHashCode_mutatedKmsEncryptedDataKey_notEqual() {
    KeyBackup mutated = clone(SAMPLE_BACKUP);
    mutated.kmsEncryptedDataKey()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
  }

  @Test
  public void keyBackup_equalsAndHashCode_mutatedAeadEncryptedPrivateKey_notEqual() {
    KeyBackup mutated = clone(SAMPLE_BACKUP);
    mutated.aeadEncryptedPrivateKey()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
  }

  @Test
  public void keyBackup_equalsAndHashCode_mutatedAttestationDocBytes_notEqual() {
    KeyBackup mutated = clone(SAMPLE_BACKUP);
    mutated.attestationDocBytes()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
  }
}
