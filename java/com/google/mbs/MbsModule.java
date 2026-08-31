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

import com.google.common.base.Preconditions;
import com.google.inject.AbstractModule;
import com.google.kmsclient.aws.AwsKmsClientModule;
import com.google.mbs.attestationcollection.aws.AwsAttestationModule;

/** Guice module encapsulating AWS KMS and Nitro Attestation-backed Measurement Bound Storage. */
public final class MbsModule extends AbstractModule {
  private final String awsRegion;

  /** Creates an MBS module configured for remote execution backed by AWS KMS and S3 storage. */
  public MbsModule(String awsRegion) {
    this.awsRegion = Preconditions.checkNotNull(awsRegion, "awsRegion cannot be null");
  }

  @Override
  protected void configure() {
    install(new AwsKmsClientModule(awsRegion));
    install(new AwsAttestationModule());
    install(new MbsCoreModule());
  }
}
