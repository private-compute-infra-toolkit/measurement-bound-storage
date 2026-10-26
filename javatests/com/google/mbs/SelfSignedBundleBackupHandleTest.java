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
import com.google.mbs.domain.BackupIncompleteException;
import com.google.mbs.domain.BackupNotFoundException;
import com.google.mbs.domain.BackupPartiallyWrittenException;
import com.google.mbs.domain.SelfSignedBundleBackup;
import com.google.mbs.domain.SelfSignedBundleBackupHandle;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SelfSignedBundleBackupHandleTest {

  private static final int TEST_EPOCH = 42;
  private static final SelfSignedBundleBackup SAMPLE_BACKUP =
      new SelfSignedBundleBackup(
          "cert".getBytes(StandardCharsets.UTF_8),
          "kmsKey".getBytes(StandardCharsets.UTF_8),
          "privKey".getBytes(StandardCharsets.UTF_8),
          "attestation".getBytes(StandardCharsets.UTF_8));

  private record FakeComplete(int epoch) implements SelfSignedBundleBackupHandle.Complete {
    @Override
    public SelfSignedBundleBackup read() {
      throw new UnsupportedOperationException();
    }
  }

  private record FakeEmpty(int epoch) implements SelfSignedBundleBackupHandle.Empty {
    @Override
    public void write(SelfSignedBundleBackup backup) {
      throw new UnsupportedOperationException();
    }
  }

  @Test
  public void complete_expectComplete_returnsSelf() throws Exception {
    SelfSignedBundleBackupHandle.Complete complete = new FakeComplete(TEST_EPOCH);

    SelfSignedBundleBackupHandle.Complete narrowed =
        complete.expect(SelfSignedBundleBackupHandle.Complete.class);

    assertThat(narrowed).isSameInstanceAs(complete);
    assertThat(narrowed.epoch()).isEqualTo(TEST_EPOCH);
  }

  @Test
  public void complete_expectOther_throwsAlreadyExistsException() {
    SelfSignedBundleBackupHandle handle = new FakeComplete(TEST_EPOCH);

    assertThrows(
        BackupAlreadyExistsException.class,
        () -> handle.expect(SelfSignedBundleBackupHandle.Empty.class));
  }

  @Test
  public void empty_expectEmpty_returnsSelf() throws Exception {
    SelfSignedBundleBackupHandle.Empty empty = new FakeEmpty(TEST_EPOCH);

    SelfSignedBundleBackupHandle.Empty narrowed =
        empty.expect(SelfSignedBundleBackupHandle.Empty.class);

    assertThat(narrowed).isSameInstanceAs(empty);
    assertThat(narrowed.epoch()).isEqualTo(TEST_EPOCH);
  }

  @Test
  public void empty_expectOther_throwsNotFoundException() {
    SelfSignedBundleBackupHandle handle = new FakeEmpty(TEST_EPOCH);

    assertThrows(
        BackupNotFoundException.class,
        () -> handle.expect(SelfSignedBundleBackupHandle.Complete.class));
  }

  @Test
  public void partiallyWritten_expectPartiallyWritten_returnsSelf() throws Exception {
    List<String> missing = List.of("public/42/root_certificate.pem");
    SelfSignedBundleBackupHandle.PartiallyWritten partiallyWritten =
        new SelfSignedBundleBackupHandle.PartiallyWritten(TEST_EPOCH, missing);

    SelfSignedBundleBackupHandle.PartiallyWritten narrowed =
        partiallyWritten.expect(SelfSignedBundleBackupHandle.PartiallyWritten.class);

    assertThat(narrowed).isSameInstanceAs(partiallyWritten);
    assertThat(narrowed.epoch()).isEqualTo(TEST_EPOCH);
    assertThat(narrowed.missingKeys()).isEqualTo(missing);
  }

  @Test
  public void partiallyWritten_expectOther_throwsPartiallyWrittenException() {
    List<String> missing = List.of("public/42/root_certificate.pem");
    SelfSignedBundleBackupHandle handle =
        new SelfSignedBundleBackupHandle.PartiallyWritten(TEST_EPOCH, missing);

    assertThrows(
        BackupPartiallyWrittenException.class,
        () -> handle.expect(SelfSignedBundleBackupHandle.Complete.class));
  }

  @Test
  public void incomplete_expectIncomplete_returnsSelf() throws Exception {
    List<String> missing = List.of("private/42/root_data_key.kms");
    SelfSignedBundleBackupHandle.Incomplete incomplete =
        new SelfSignedBundleBackupHandle.Incomplete(TEST_EPOCH, missing);

    SelfSignedBundleBackupHandle.Incomplete narrowed =
        incomplete.expect(SelfSignedBundleBackupHandle.Incomplete.class);

    assertThat(narrowed).isSameInstanceAs(incomplete);
    assertThat(narrowed.epoch()).isEqualTo(TEST_EPOCH);
    assertThat(narrowed.missingKeys()).isEqualTo(missing);
  }

  @Test
  public void incomplete_expectOther_throwsIncompleteException() {
    List<String> missing = List.of("private/42/root_data_key.kms");
    SelfSignedBundleBackupHandle handle =
        new SelfSignedBundleBackupHandle.Incomplete(TEST_EPOCH, missing);

    assertThrows(
        BackupIncompleteException.class,
        () -> handle.expect(SelfSignedBundleBackupHandle.Complete.class));
  }

  private static SelfSignedBundleBackup clone(SelfSignedBundleBackup source) {
    return new SelfSignedBundleBackup(
        source.certBytes().clone(),
        source.kmsEncryptedDataKey().clone(),
        source.aeadEncryptedPrivateKey().clone(),
        source.attestationDocBytes().clone());
  }

  @Test
  public void selfSignedBundleBackup_equalsHashCodeAndToString_comparesByReferenceAndContent() {
    SelfSignedBundleBackup sameReference = SAMPLE_BACKUP;
    SelfSignedBundleBackup clonedContent = clone(SAMPLE_BACKUP);

    assertThat(SAMPLE_BACKUP.equals(sameReference)).isTrue();
    assertThat(SAMPLE_BACKUP).isEqualTo(clonedContent);
    assertThat(SAMPLE_BACKUP.hashCode()).isEqualTo(clonedContent.hashCode());
    assertThat(SAMPLE_BACKUP.toString()).isEqualTo(clonedContent.toString());
    assertThat(SAMPLE_BACKUP.equals(null)).isFalse();
    assertThat(SAMPLE_BACKUP.equals("not-a-backup")).isFalse();
  }

  @Test
  public void selfSignedBundleBackup_equalsHashCodeAndToString_mutatedCertBytes_notEqual() {
    SelfSignedBundleBackup mutated = clone(SAMPLE_BACKUP);
    mutated.certBytes()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
    assertThat(SAMPLE_BACKUP.toString()).isNotEqualTo(mutated.toString());
  }

  @Test
  public void
      selfSignedBundleBackup_equalsHashCodeAndToString_mutatedKmsEncryptedDataKey_notEqual() {
    SelfSignedBundleBackup mutated = clone(SAMPLE_BACKUP);
    mutated.kmsEncryptedDataKey()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
    assertThat(SAMPLE_BACKUP.toString()).isNotEqualTo(mutated.toString());
  }

  @Test
  public void
      selfSignedBundleBackup_equalsHashCodeAndToString_mutatedAeadEncryptedPrivateKey_notEqual() {
    SelfSignedBundleBackup mutated = clone(SAMPLE_BACKUP);
    mutated.aeadEncryptedPrivateKey()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
    assertThat(SAMPLE_BACKUP.toString()).isNotEqualTo(mutated.toString());
  }

  @Test
  public void
      selfSignedBundleBackup_equalsHashCodeAndToString_mutatedAttestationDocBytes_notEqual() {
    SelfSignedBundleBackup mutated = clone(SAMPLE_BACKUP);
    mutated.attestationDocBytes()[0]++;

    assertThat(SAMPLE_BACKUP).isNotEqualTo(mutated);
    assertThat(SAMPLE_BACKUP.hashCode()).isNotEqualTo(mutated.hashCode());
    assertThat(SAMPLE_BACKUP.toString()).isNotEqualTo(mutated.toString());
  }
}
