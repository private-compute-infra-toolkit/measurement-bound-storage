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

import com.google.mbs.attestationcollection.AttestationToken;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** In-memory, placeholder implementation of MeasurementBoundCertificateProfider. */
public class DummyMeasurementBoundCertificateProvider
    implements MeasurementBoundCertificateProvider {
  // RFC 5280 limits the serial number to 20 bytes (160 bits).
  // A positive BigInteger requires 1 bit for the sign, leaving 159 bits for entropy.
  private static final int SERIAL_NUMBER_ENTROPY_BITS = 159;

  private static final SecureRandom secureRandom = new SecureRandom();
  private MeasurementBoundCertificate mbc = null;

  @Override
  public MeasurementBoundCertificate loadOrGenerateCertificate() {
    if (mbc != null) {
      return mbc;
    }
    try {
      return generateNewCertificate();
    } catch (Exception e) {
      throw new RuntimeException("Failed to generate certificate", e);
    }
  }

  private MeasurementBoundCertificate generateNewCertificate() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048, secureRandom);
    KeyPair keyPair = keyGen.generateKeyPair();

    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    Instant now = Instant.now();
    BigInteger serial = new BigInteger(SERIAL_NUMBER_ENTROPY_BITS, secureRandom);
    Instant notBefore = now.minus(Duration.ofDays(1));
    Instant notAfter = now.plus(Duration.ofDays(30));
    X500Name issuerAndSubject = new X500Name("CN=Standalone CA");

    X509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            issuerAndSubject,
            serial,
            Date.from(notBefore),
            Date.from(notAfter),
            issuerAndSubject,
            publicKey);

    JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    ContentSigner signer = signerBuilder.build(privateKey);

    X509Certificate certificate =
        new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

    AttestationToken token = AttestationToken.fromBytes("AttestationToken".getBytes());
    return new MeasurementBoundCertificate(certificate, privateKey, token);
  }
}
