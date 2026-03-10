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

import com.google.common.io.CharStreams;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

/** A wrapper for the AWS Nitro Enclaves KMS Tool CLI. */
/* TODO: Migrate from Enclave CLI tool to direct SDK invocation via JNI. */
public class KmsToolEnclaveWrapper {

  private static final String KMS_TOOL_ENCLAVE_CLI_PATH = "/kmstool_enclave_cli";

  @Inject
  public KmsToolEnclaveWrapper() {}

  /**
   * Calls the kmstool_enclave_cli to generate a data key.
   *
   * @param keyId the ID of the KMS key to use
   * @param credentialsProvider the AWS credentials provider
   * @param region the AWS region
   * @return a KmsToolEnclaveResponse containing the plaintext and ciphertext of the data key
   * @throws IOException if an I/O error occurs
   * @throws InterruptedException if the current thread is interrupted while waiting for the process
   *     to complete
   */
  public KmsToolEnclaveResponse generateDataKey(
      String keyId, TcaAwsCredentialsProvider credentialsProvider, String region)
      throws IOException, InterruptedException {
    AwsSessionCredentials credentials = credentialsProvider.resolveCredentials();
    ProcessBuilder processBuilder =
        new ProcessBuilder(
            KMS_TOOL_ENCLAVE_CLI_PATH,
            "genkey",
            "--key-id",
            keyId,
            "--key-spec",
            "AES-256",
            "--aws-access-key-id",
            credentials.accessKeyId(),
            "--aws-secret-access-key",
            credentials.secretAccessKey(),
            "--aws-session-token",
            credentials.sessionToken(),
            "--region",
            region);
    Process process = processBuilder.start();
    int exitCode = process.waitFor();

    if (exitCode != 0) {
      String error =
          CharStreams.toString(
              new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8));
      throw new IOException(
          "kmstool_enclave_cli genkey failed with exit code " + exitCode + ": " + error);
    }

    String response =
        CharStreams.toString(
            new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));

    String[] lines = response.split("\n");
    String ciphertext = null;
    String plaintext = null;

    for (String line : lines) {
      if (line.startsWith("CIPHERTEXT: ")) {
        ciphertext = line.substring("CIPHERTEXT: ".length()).trim();
      } else if (line.startsWith("PLAINTEXT: ")) {
        plaintext = line.substring("PLAINTEXT: ".length()).trim();
      }
    }

    if (ciphertext == null || plaintext == null) {
      throw new IOException("Could not parse output from kmstool_enclave_cli");
    }

    return new KmsToolEnclaveResponse(plaintext, ciphertext);
  }

  /**
   * Calls the kmstool_enclave_cli to decrypt a ciphertext.
   *
   * @param ciphertext the ciphertext to decrypt
   * @param credentialsProvider the AWS credentials provider
   * @param region the AWS region
   * @return the decrypted plaintext
   * @throws IOException if an I/O error occurs
   * @throws InterruptedException if the current thread is interrupted while waiting for the process
   *     to complete
   */
  public byte[] decrypt(
      byte[] ciphertext, TcaAwsCredentialsProvider credentialsProvider, String region)
      throws IOException, InterruptedException {
    AwsSessionCredentials credentials = credentialsProvider.resolveCredentials();
    ProcessBuilder processBuilder =
        new ProcessBuilder(
            KMS_TOOL_ENCLAVE_CLI_PATH,
            "decrypt",
            "--ciphertext",
            Base64.getEncoder().encodeToString(ciphertext),
            "--aws-access-key-id",
            credentials.accessKeyId(),
            "--aws-secret-access-key",
            credentials.secretAccessKey(),
            "--aws-session-token",
            credentials.sessionToken(),
            "--region",
            region);
    Process process = processBuilder.start();
    int exitCode = process.waitFor();

    if (exitCode != 0) {
      String error =
          CharStreams.toString(
              new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8));
      throw new IOException(
          "kmstool_enclave_cli decrypt failed with exit code " + exitCode + ": " + error);
    }

    String response =
        CharStreams.toString(
            new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));

    // Output format is 'PLAINTEXT: <decrypted_content>\n'
    if (response.startsWith("PLAINTEXT: ")) {
      response = response.substring("PLAINTEXT: ".length()).trim();
    }

    return Base64.getDecoder().decode(response);
  }

  /** A class to hold the response from the kmstool_enclave_cli. */
  public static class KmsToolEnclaveResponse {
    private final String plaintext;
    private final String ciphertext;

    public KmsToolEnclaveResponse(String plaintext, String ciphertext) {
      this.plaintext = plaintext;
      this.ciphertext = ciphertext;
    }

    public byte[] getPlaintext() {
      return Base64.getDecoder().decode(plaintext);
    }

    public byte[] getCiphertext() {
      return Base64.getDecoder().decode(ciphertext);
    }
  }
}
