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

package com.google.mbs.tools;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.FluentLogger;
import com.google.mbs.adapters.CertificatesConfigMapper;
import com.google.mbs.adapters.PemCertificateCodec;
import com.google.mbs.domain.InvalidCertificatesConfigException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

/**
 * Prints the acceptable root certificates that MBS publishes for a service.
 *
 * <p>Usage: {@code root_certificates_tool HOST_URL}, where {@code HOST_URL} is the base URL that
 * serves the service's published certificates, e.g. {@code https://certs.example.com}.
 *
 * <p>Reads {@code HOST_URL/certificates_config.textproto}, downloads {@code
 * HOST_URL/public/<epoch>/root_certificate.pem} of each acceptable epoch, and prints their
 * concatenation in ascending epoch order to stdout.
 */
public final class RootCertificatesTool {

  /** Downloads a URL. Returns empty if it doesn't exist. */
  interface Fetcher {
    Optional<byte[]> fetch(String url) throws IOException, InterruptedException;
  }

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static final PemCertificateCodec CODEC = new PemCertificateCodec();
  private static final int MAX_ATTEMPTS = 3;
  private static final Duration RETRY_DELAY = Duration.ofSeconds(5);
  private static final Duration TIMEOUT = Duration.ofSeconds(30);

  private RootCertificatesTool() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      System.err.println("Usage: root_certificates_tool HOST_URL");
      System.exit(2);
    }
    HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    System.out.writeBytes(run(url -> fetchWithRetry(client, url), args[0]));
    System.out.flush();
  }

  /**
   * Returns the concatenation of the acceptable root certificates of {@code host} in ascending
   * epoch order.
   */
  static byte[] run(Fetcher fetcher, String host)
      throws IOException, InterruptedException, InvalidCertificatesConfigException {
    ByteArrayOutputStream bundle = new ByteArrayOutputStream();
    for (int epoch : parseAcceptableEpochs(fetchConfig(fetcher, host))) {
      bundle.writeBytes(fetchCertificate(fetcher, host, epoch));
    }
    return bundle.toByteArray();
  }

  /** Returns the certificates config of {@code host}. */
  private static byte[] fetchConfig(Fetcher fetcher, String host)
      throws IOException, InterruptedException {
    String url = host + "/certificates_config.textproto";
    return fetcher.fetch(url).orElseThrow(() -> new IOException(url + " doesn't exist"));
  }

  /** Returns the acceptable epochs in {@code config} in ascending order. */
  static ImmutableList<Integer> parseAcceptableEpochs(byte[] config)
      throws InvalidCertificatesConfigException {
    Set<Integer> epochs =
        CertificatesConfigMapper.fromTextProto(new String(config, UTF_8))
            .acceptableSelfSignedCertificateIds();
    if (epochs.isEmpty()) {
      throw new InvalidCertificatesConfigException("No acceptable self-signed certificates");
    }
    return ImmutableList.sortedCopyOf(epochs);
  }

  /** Returns the root certificate of {@code epoch}, which must be one canonical PEM certificate. */
  private static byte[] fetchCertificate(Fetcher fetcher, String host, int epoch)
      throws IOException, InterruptedException {
    String url = host + "/public/" + epoch + "/root_certificate.pem";
    byte[] pem = fetcher.fetch(url).orElseThrow(() -> new IOException(url + " doesn't exist"));
    if (!isCanonicalPem(pem)) {
      throw new IllegalArgumentException(url + " is not a single canonical PEM certificate");
    }
    return pem;
  }

  /**
   * Fetches {@code url}, retrying failures, so that a transient error never drops an acceptable
   * root.
   */
  private static Optional<byte[]> fetchWithRetry(HttpClient client, String url)
      throws IOException, InterruptedException {
    for (int attempt = 1; ; attempt++) {
      try {
        return fetch(client, url);
      } catch (IOException e) {
        if (attempt == MAX_ATTEMPTS) {
          throw e;
        }
        logger.atWarning().withCause(e).log("Failed to fetch %s, retrying in %s", url, RETRY_DELAY);
        Thread.sleep(RETRY_DELAY.toMillis());
      }
    }
  }

  /** Fetches {@code url} once. Returns empty if it doesn't exist (HTTP 403 or 404). */
  private static Optional<byte[]> fetch(HttpClient client, String url)
      throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT).build();
    HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
    int status = response.statusCode();
    if (status == 200) {
      return Optional.of(response.body());
    }
    if (status == 403 || status == 404) {
      return Optional.empty();
    }
    throw new IOException(url + " returned HTTP " + status);
  }

  private static boolean isCanonicalPem(byte[] pem) {
    try {
      return Arrays.equals(pem, CODEC.toBytes(CODEC.toCertificate(pem)));
    } catch (IllegalArgumentException e) {
      return false;
    }
  }
}
