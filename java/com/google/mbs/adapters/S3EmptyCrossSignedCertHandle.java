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

import com.google.mbs.domain.CrossSignedCertHandle;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KeyBackupStorageException;
import java.util.Objects;

/**
 * S3 implementation of {@link CrossSignedCertHandle.Empty} that delegates writing a new
 * cross-signed certificate to {@link S3BackupWriter}.
 */
record S3EmptyCrossSignedCertHandle(CrossSignedCertificateId id, S3BackupWriter writer)
    implements CrossSignedCertHandle.Empty {

  S3EmptyCrossSignedCertHandle {
    Objects.requireNonNull(id);
    Objects.requireNonNull(writer);
  }

  @Override
  public void write(CrossSignedCertificateBackup backup) throws KeyBackupStorageException {
    writer.writeCrossSignedCert(id, backup);
  }
}
