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

package com.google.mbs.domain;

import java.util.Map;

/**
 * Point-in-time view of backup storage, keyed by epoch for self-signed key backups and by {@link
 * CrossSignedCertificateId} for cross-signed certificates.
 *
 * <p>A snapshot is not refreshed by operations performed on the handles it returns; obtain a new
 * snapshot from {@link KeyBackupStorage#getSnapshot()} to observe later changes.
 */
public interface StorageSnapshot {

  /**
   * Returns the handle for {@code epoch}, or a {@link BackupHandle.Empty} if nothing was stored for
   * it when the snapshot was taken.
   */
  BackupHandle getBundleHandle(int epoch);

  /** Returns the handles of the epochs present in storage when the snapshot was taken. */
  Map<Integer, BackupHandle> bundleHandles();

  /**
   * Returns the handle for the cross-signed certificate {@code id}, or a {@link
   * CrossSignedCertHandle.Empty} if nothing was stored for it when the snapshot was taken.
   */
  CrossSignedCertHandle getCrossSignedCertHandle(CrossSignedCertificateId id);

  /**
   * Returns the handles of the cross-signed certificates present in storage when the snapshot was
   * taken.
   */
  Map<CrossSignedCertificateId, CrossSignedCertHandle> crossSignedCertHandles();
}
