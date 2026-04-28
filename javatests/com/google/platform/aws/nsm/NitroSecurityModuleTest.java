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

import static com.google.common.truth.Truth.assertThat;

import com.google.platform.aws.nsm.NitroSecurityModule.NitroSecurityModuleException;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class NitroSecurityModuleTest {

  @Test
  public void testWhenNsmJniIsUsed_hasNoLinkIssues() {
    try (NitroSecurityModule nsm = new NitroSecurityModule()) {
      // getting attestation doc will fail outside of AWS Nitro Enclave
      // this test checks Nsm is not failing due to JNI issues.
      nsm.getAttestationDocument(Optional.empty(), Optional.empty(), Optional.empty());
    } catch (NitroSecurityModuleException e) {
      // Expected if run outside of AWS Nitro Enclave
      assertThat(e.error_code).isEqualTo(NsmJniResult.NSM_INIT_FAILURE);
    }
  }
}
