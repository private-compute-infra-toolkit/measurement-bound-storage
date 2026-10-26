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

package com.google.mbs.adapters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class PemCertificateCodecTest {

  private final PemCertificateCodec codec = new PemCertificateCodec();

  @Test
  public void toBytes_andToCertificate_roundTripsCertificate() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
    X500Name subject = new X500Name("CN=Test");
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
    X509Certificate certificate =
        new JcaX509CertificateConverter()
            .getCertificate(
                new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.ONE,
                        new Date(0),
                        new Date(1000),
                        subject,
                        keyPair.getPublic())
                    .build(signer));

    byte[] pemBytes = codec.toBytes(certificate);
    String pemString = new String(pemBytes, StandardCharsets.UTF_8);

    assertTrue(pemString.startsWith("-----BEGIN CERTIFICATE-----"));
    assertTrue(pemString.trim().endsWith("-----END CERTIFICATE-----"));
    assertEquals(certificate, codec.toCertificate(pemBytes));
  }

  @Test
  public void toCertificate_corruptedBytes_throwsIllegalArgumentException() {
    byte[] corrupted = "not-a-valid-certificate".getBytes(StandardCharsets.UTF_8);

    assertThrows(IllegalArgumentException.class, () -> codec.toCertificate(corrupted));
  }
}
