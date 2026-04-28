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

import java.util.Optional;

/**
 * Java wrapper for the AWS Nitro Security Module (NSM) library, which interfaces with the
 * underlying NSM driver at {@code /dev/nsm}.
 *
 * <p>This class implements {@link AutoCloseable} to manage the file descriptor to the NSM device.
 * The file descriptor is acquired when an instance is created and released when the {@link
 * #close()} method is called, typically via a try-with-resources statement.
 */
public class NitroSecurityModule implements AutoCloseable {

  static {
    System.loadLibrary("nsm_jni");
  }

  private final int fd;

  public static class NitroSecurityModuleException extends RuntimeException {
    public final int error_code;

    public NitroSecurityModuleException(String message, int error) {
      super(message);
      error_code = error;
    }
  }

  /**
   * Constructor initializes the NSM library and obtains a file descriptor.
   *
   * @throws NsmException if initialization fails.
   */
  public NitroSecurityModule() {
    this.fd = init();
    if (this.fd < 0) {
      throw new NitroSecurityModuleException(
          String.format("Failed to initialize NSM library, fd: %d", this.fd),
          NsmJniResult.NSM_INIT_FAILURE);
    }
  }

  /**
   * Retrieves an attestation document from the NSM device.
   *
   * @param userData Optional user-provided data to be included in the attestation document.
   * @param nonce Optional nonce to be included in the attestation document.
   * @param publicKey Optional public key to be included in the attestation document.
   * @return The attestation document as a byte array on success.
   * @throws NsmException if the native call fails or returns an invalid attestation doc size.
   */
  public byte[] getAttestationDocument(
      Optional<byte[]> userData, Optional<byte[]> nonce, Optional<byte[]> publicKey) {
    byte[] userDataIn = userData.orElse(null);
    byte[] nonceIn = nonce.orElse(null);
    byte[] publicKeyIn = publicKey.orElse(null);

    NsmJniResult attestationResult = getAttestationDoc(this.fd, userDataIn, nonceIn, publicKeyIn);
    if (attestationResult.statusCode == NsmJniResult.SUCCESS) {
      return attestationResult.attestationDoc;
    } else {
      throw new NitroSecurityModuleException(
          String.format(
              "Failed to get attestation document, status_code: %d", attestationResult.statusCode),
          attestationResult.statusCode);
    }
  }

  @Override
  public void close() {
    if (fd > 0) {
      exit(this.fd);
    }
  }

  private static native int init();

  private static native void exit(int fd);

  private static native NsmJniResult getAttestationDoc(
      int fd, byte[] userDataIn, byte[] nonceIn, byte[] publicKeyIn);
}
