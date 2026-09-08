/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
import com.google.inject.Provides;
import com.google.inject.Singleton;
import com.google.mbs.adapters.AwsAttestationCollector;
import com.google.mbs.adapters.AwsKmsClient;
import com.google.mbs.adapters.nsm.DefaultNitroSecurityModuleFactory;
import com.google.mbs.adapters.nsm.NitroSecurityModuleFactory;
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.KmsClientInterface;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

/** Guice module for AWS-specific adapter bindings (NSM, KMS, Attestation). */
public class AwsMbsModule extends AbstractModule {

  private final String awsRegion;

  public AwsMbsModule(String awsRegion) {
    this.awsRegion = Preconditions.checkNotNull(awsRegion, "awsRegion cannot be null");
  }

  @Override
  protected void configure() {
    bind(NitroSecurityModuleFactory.class).to(DefaultNitroSecurityModuleFactory.class);
    bind(KmsClientInterface.class).to(AwsKmsClient.class);
    bind(AttestationCollector.class).to(AwsAttestationCollector.class);
  }

  @Provides
  @Singleton
  public KmsClient provideKmsClient() {
    return KmsClient.builder()
        .region(Region.of(awsRegion))
        .credentialsProvider(DefaultCredentialsProvider.create())
        .build();
  }
}
