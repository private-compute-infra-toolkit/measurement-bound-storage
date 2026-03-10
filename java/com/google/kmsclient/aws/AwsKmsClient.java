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

import com.google.kmsclient.KmsClientInterface;
import com.google.kmsclient.KmsException;
import com.google.kmsclient.KmsGeneratedKey;
import com.google.kmsclient.aws.KmsToolEnclaveWrapper.KmsToolEnclaveResponse;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.io.IOException;

/** AWS-specific implementation of KmsClientInterface using KmsToolEnclaveWrapper. */
public class AwsKmsClient implements KmsClientInterface {

  private final KmsToolEnclaveWrapper kmsToolEnclaveWrapper;
  private final TcaAwsCredentialsProvider credentialsProvider;
  private final String awsRegion;

  @Inject
  public AwsKmsClient(
      KmsToolEnclaveWrapper kmsToolEnclaveWrapper,
      TcaAwsCredentialsProvider credentialsProvider,
      @Named("awsRegion") String awsRegion) {
    this.kmsToolEnclaveWrapper = kmsToolEnclaveWrapper;
    this.credentialsProvider = credentialsProvider;
    this.awsRegion = awsRegion;
  }

  @Override
  public KmsGeneratedKey generateDataKey(String keyId) throws KmsException {
    try {
      KmsToolEnclaveResponse response =
          kmsToolEnclaveWrapper.generateDataKey(keyId, credentialsProvider, awsRegion);
      return KmsGeneratedKey.builder()
          .setPlaintext(response.getPlaintext())
          .setCiphertext(response.getCiphertext())
          .build();
    } catch (IOException | InterruptedException e) {
      throw new KmsException("Failed to generate data key from AWS KMS", e);
    }
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, String keyId) throws KmsException {
    try {
      // The keyId is not strictly needed for the decrypt operation with the enclave tool,
      // as the ciphertext blob contains the key ARN. However, it's good practice to pass it.
      return kmsToolEnclaveWrapper.decrypt(ciphertext, credentialsProvider, awsRegion);
    } catch (IOException | InterruptedException e) {
      throw new KmsException("Failed to decrypt ciphertext using AWS KMS", e);
    }
  }
}
