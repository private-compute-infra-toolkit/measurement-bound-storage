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

package com.google.mbs.attestationcollection;

import java.util.Base64;

public class AttestationToken {
  private final String tokenBase64;

  private AttestationToken(String tokenBase64) {
    this.tokenBase64 = tokenBase64;
  }

  public static AttestationToken fromBytes(byte[] bytes) {
    return new AttestationToken(Base64.getEncoder().encodeToString(bytes));
  }

  public String getBase64() {
    return tokenBase64;
  }

  public byte[] getBytes() {
    return Base64.getDecoder().decode(tokenBase64);
  }
}
