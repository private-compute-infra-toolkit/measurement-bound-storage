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

package com.google.platform.aws.nsm;

public class NsmJniResult {
  public static final int SUCCESS = 0;
  public static final int NSM_INIT_FAILURE = -1;
  public static final int JNI_OBJECT_ALLOCATION_ERROR = -2;
  // Keep the positive error codes range reserved
  // for error codes reported from libnsm.

  public final byte[] attestationDoc;
  public final int statusCode;

  @SuppressWarnings("unused") // used from the nsm_jni.c
  public NsmJniResult(byte[] attestationDoc) {
    this.attestationDoc = attestationDoc;
    this.statusCode = 0;
  }

  @SuppressWarnings("unused") // used from the nsm_jni.c
  public NsmJniResult(int errorCode) {
    this.attestationDoc = null;
    this.statusCode = errorCode;
  }
}
