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
 * S3 implementation of {@link CrossSignedCertHandle.Complete} that lazily reads the cross-signed
 * certificate from S3 on the first {@link #read()} and memoizes the result.
 */
final class S3CompleteCrossSignedCertHandle implements CrossSignedCertHandle.Complete {

  private final CrossSignedCertificateId id;
  private final S3BackupReader reader;
  private final String eTag;
  private CrossSignedCertificateBackup cachedBackup;

  S3CompleteCrossSignedCertHandle(CrossSignedCertificateId id, S3BackupReader reader, String eTag) {
    this.id = Objects.requireNonNull(id);
    this.reader = Objects.requireNonNull(reader);
    this.eTag = Objects.requireNonNull(eTag);
  }

  @Override
  public CrossSignedCertificateId id() {
    return id;
  }

  String eTag() {
    return eTag;
  }

  @Override
  public synchronized CrossSignedCertificateBackup read() throws KeyBackupStorageException {
    if (cachedBackup == null) {
      cachedBackup = reader.readCrossSignedCert(id);
    }
    return cachedBackup;
  }
}
