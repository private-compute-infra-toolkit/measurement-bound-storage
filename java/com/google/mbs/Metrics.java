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

/** Port for reporting metrics from MBS library. */
public interface Metrics {
  /** Events that can be reported by MBS. */
  enum MbsEvent {
    SUCCESS,
    S3_FETCH_FAILED,
    S3_WRITE_FAILED,
    KMS_OPERATION_FAILED,
  }

  /** Records the occurrence of an MBS event. */
  void recordEvent(MbsEvent event);
}
