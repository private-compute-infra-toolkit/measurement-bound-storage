/*
 * Copyright 2025 Google LLC
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

package com.google.tlog;

/** Data class to hold the transparency log entry details as a JSON string. */
public class TlogEntry {
  private final String entryJson; // Raw JSON from the TLog

  public TlogEntry(String entryJson) {
    this.entryJson = entryJson;
  }

  public String getEntryJson() {
    return entryJson;
  }
}
