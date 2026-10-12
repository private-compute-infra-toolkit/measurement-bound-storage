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

/** Port for reporting metrics from MBS library. */
public interface Metrics {
  enum MbsEvent {
    SUCCESS,
    FAILURE,
  }

  void recordEvent(MbsEvent event);

  enum GenerationEvent {
    SUCCESS,
    WAITING_FOR_MBS_LOCK,
    S3_OPERATION_FAILED,
    KMS_OPERATION_FAILED,
    GENERAL_FAILURE,
  }

  void recordGenerationEvent(GenerationEvent event);

  enum LoadEvent {
    SUCCESS,
    KEY_BACKUP_NOT_FOUND,
    S3_OPERATION_FAILED,
    KMS_OPERATION_FAILED,
    STORED_BACKUP_CORRUPTED,
    GENERAL_FAILURE,
  }

  void recordLoadEvent(LoadEvent event);

  enum ConfigEvent {
    SUCCESS,
    COULD_NOT_FETCH_CONFIGURATION_FILE,
    INVALID_CONFIGURATION_FILE,
    GENERAL_FAILURE,
  }

  void recordConfigEvent(ConfigEvent event);
}
