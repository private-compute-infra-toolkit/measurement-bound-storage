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

import com.google.mbs.domain.BackupHandle;
import com.google.mbs.domain.CrossSignedCertHandle;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.StorageSnapshot;
import java.util.Map;
import java.util.Objects;

record S3StorageSnapshot(
    Map<Integer, BackupHandle> bundleHandles,
    Map<CrossSignedCertificateId, CrossSignedCertHandle> crossSignedCertHandles,
    S3BackupWriter writer)
    implements StorageSnapshot {

  S3StorageSnapshot {
    Objects.requireNonNull(bundleHandles);
    Objects.requireNonNull(crossSignedCertHandles);
    Objects.requireNonNull(writer);
  }

  @Override
  public BackupHandle getBundleHandle(int epoch) {
    BackupHandle handle = bundleHandles.get(epoch);
    return handle != null ? handle : new S3EmptyBackupHandle(epoch, writer);
  }

  @Override
  public CrossSignedCertHandle getCrossSignedCertHandle(CrossSignedCertificateId id) {
    CrossSignedCertHandle handle = crossSignedCertHandles.get(id);
    return handle != null ? handle : new S3EmptyCrossSignedCertHandle(id, writer);
  }
}
