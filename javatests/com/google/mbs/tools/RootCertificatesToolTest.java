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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.common.primitives.Bytes;
import com.google.mbs.adapters.PemCertificateCodec;
import com.google.mbs.domain.InvalidCertificatesConfigException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class RootCertificatesToolTest {

  private static final String HOST = "https://certs.example.com";

  /** Files that the fake host serves, by URL. */
  private final Map<String, byte[]> served = new HashMap<>();

  private final RootCertificatesTool.Fetcher fetcher = url -> Optional.ofNullable(served.get(url));

  @Test
  public void run_singleEpoch_returnsIdenticalBundle() throws Exception {
    serveConfig(0);
    byte[] certificate = serveCertificate(0);

    byte[] bundle = RootCertificatesTool.run(fetcher, HOST);

    assertThat(bundle).isEqualTo(certificate);
  }

  @Test
  public void run_unsortedEpochs_returnsBundleInAscendingOrder() throws Exception {
    serveConfig(2, 0, 1);
    byte[] certificate0 = serveCertificate(0);
    byte[] certificate1 = serveCertificate(1);
    byte[] certificate2 = serveCertificate(2);

    byte[] bundle = RootCertificatesTool.run(fetcher, HOST);

    assertThat(bundle).isEqualTo(Bytes.concat(certificate0, certificate1, certificate2));
  }

  @Test
  public void run_missingConfig_throws() throws Exception {
    serveCertificate(0);

    assertThrows(IOException.class, () -> RootCertificatesTool.run(fetcher, HOST));
  }

  @Test
  public void run_configFetchFails_throws() throws Exception {
    serveCertificate(0);
    RootCertificatesTool.Fetcher failing =
        url -> {
          if (url.endsWith("/certificates_config.textproto")) {
            throw new IOException("HTTP 503");
          }
          return fetcher.fetch(url);
        };

    assertThrows(IOException.class, () -> RootCertificatesTool.run(failing, HOST));
  }

  @Test
  public void run_missingCertificate_throws() throws Exception {
    serveConfig(0, 1);
    serveCertificate(0);

    assertThrows(IOException.class, () -> RootCertificatesTool.run(fetcher, HOST));
  }

  @Test
  public void run_malformedCertificate_throws() throws Exception {
    serveConfig(0);
    byte[] certificate = serveCertificate(0);
    byte[] crlf = new String(certificate, UTF_8).replace("\n", "\r\n").getBytes(UTF_8);

    for (byte[] malformed :
        List.of("garbage".getBytes(UTF_8), Bytes.concat(certificate, certificate), crlf)) {
      served.put(HOST + "/public/0/root_certificate.pem", malformed);
      assertThrows(IllegalArgumentException.class, () -> RootCertificatesTool.run(fetcher, HOST));
    }
  }

  @Test
  public void parseAcceptableEpochs_malformedConfig_throws() {
    byte[] config = "acceptable_self_signed_certificate_ids".getBytes(UTF_8);

    assertThrows(
        InvalidCertificatesConfigException.class,
        () -> RootCertificatesTool.parseAcceptableEpochs(config));
  }

  @Test
  public void parseAcceptableEpochs_noAcceptableEpochs_throws() {
    byte[] config =
        (selfSignedCertificate(0) + "active_self_signed_certificate_ids: 0").getBytes(UTF_8);

    assertThrows(
        InvalidCertificatesConfigException.class,
        () -> RootCertificatesTool.parseAcceptableEpochs(config));
  }

  /** Serves a config with the given acceptable epochs, in the given order. */
  private void serveConfig(int... acceptableEpochs) {
    StringBuilder config = new StringBuilder();
    for (int epoch : acceptableEpochs) {
      config.append(selfSignedCertificate(epoch));
      config.append("acceptable_self_signed_certificate_ids: ").append(epoch).append('\n');
    }
    config.append("active_self_signed_certificate_ids: ").append(acceptableEpochs[0]);
    served.put(HOST + "/certificates_config.textproto", config.toString().getBytes(UTF_8));
  }

  private static String selfSignedCertificate(int epoch) {
    return String.format(
        """
        self_signed_certificates {
          key: %1$d
          value {
            epoch_id: %1$d
            validity_period { not_before { seconds: 0 } not_after { seconds: 1 } }
          }
        }
        """,
        epoch);
  }

  /** Serves a new self-signed certificate for {@code epoch} as MBS publishes it. */
  private byte[] serveCertificate(int epoch) throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
    X500Name name = new X500Name("CN=Root G" + epoch);
    byte[] pem =
        new PemCertificateCodec()
            .toBytes(
                new JcaX509CertificateConverter()
                    .getCertificate(
                        new JcaX509v3CertificateBuilder(
                                name,
                                BigInteger.ONE,
                                new Date(0),
                                new Date(1000),
                                name,
                                keyPair.getPublic())
                            .build(
                                new JcaContentSignerBuilder("SHA256withECDSA")
                                    .build(keyPair.getPrivate()))));
    served.put(HOST + "/public/" + epoch + "/root_certificate.pem", pem);
    return pem;
  }
}
