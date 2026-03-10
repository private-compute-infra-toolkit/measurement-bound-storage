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

package com.google.kmsclient.aws;

import jakarta.inject.Inject;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;

/** A provider for AWS session credentials that uses the default AWS credentials provider chain. */
public class TcaAwsCredentialsProvider {

  private final DefaultCredentialsProvider credentialsProvider;

  @Inject
  public TcaAwsCredentialsProvider() {
    this.credentialsProvider = DefaultCredentialsProvider.create();
  }

  /**
   * Resolves the AWS session credentials.
   *
   * @return the AWS session credentials
   */
  public AwsSessionCredentials resolveCredentials() {
    return (AwsSessionCredentials) credentialsProvider.resolveCredentials();
  }
}
