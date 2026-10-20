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

package com.google.mbs.dummy;

import com.google.mbs.domain.AttestationToken;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.MeasurementBoundBundle;
import com.google.mbs.domain.MeasurementBoundCertificateGenerator;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.TrustPackage;
import com.google.mbs.domain.TrustPackageProvider;
import com.google.mbs.domain.TrustPackageReloader;
import com.google.mbs.domain.ValidityPeriod;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** In-memory, placeholder implementation of {@link TrustPackageProvider}. */
public class DummyTrustPackageProvider
    implements TrustPackageProvider,
        TrustPackageReloader,
        MeasurementBoundCertificateGenerator,
        CertificatesConfigProvider {
  // RFC 5280 limits the serial number to 20 bytes (160 bits).
  // A positive BigInteger requires 1 bit for the sign, leaving 159 bits for entropy.
  private static final int SERIAL_NUMBER_ENTROPY_BITS = 159;

  private static final CertificatesConfig DUMMY_CONFIG =
      new CertificatesConfig(
          Map.of(
              0,
              new SelfSignedCertificate(
                  0,
                  new ValidityPeriod(
                      Instant.parse("2026-01-01T00:00:00Z"),
                      Instant.parse("2100-01-01T00:00:00Z")))),
          Map.of(),
          Set.of(0),
          Set.of(),
          Set.of(0));

  private static final SecureRandom secureRandom = new SecureRandom();
  private volatile TrustPackage trustPackage = null;

  @Override
  public TrustPackage getActiveTrustPackage() {
    TrustPackage current = trustPackage;
    if (current == null) {
      throw new IllegalStateException("Trust package has not been initialized yet");
    }
    return current;
  }

  @Override
  public CertificatesConfig getCertificatesConfig() {
    return DUMMY_CONFIG;
  }

  @Override
  public void generateCertificates(CertificatesConfig unused) {}

  @Override
  public synchronized void reload(CertificatesConfig config) {
    try {
      List<MeasurementBoundBundle> bundles = new ArrayList<>();
      for (SelfSignedCertificate certConfig : config.activeSelfSignedCertificates()) {
        bundles.add(generateNewCertificate(certConfig.validityPeriod()));
      }
      trustPackage = new TrustPackage(bundles, List.of());
    } catch (Exception e) {
      throw new RuntimeException("Failed to reload certificate", e);
    }
  }

  private MeasurementBoundBundle generateNewCertificate(ValidityPeriod validityPeriod)
      throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048, secureRandom);
    KeyPair keyPair = keyGen.generateKeyPair();

    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    BigInteger serial = new BigInteger(SERIAL_NUMBER_ENTROPY_BITS, secureRandom);
    X500Name issuerAndSubject = new X500Name("CN=Standalone CA");

    X509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            issuerAndSubject,
            serial,
            Date.from(validityPeriod.notBefore()),
            Date.from(validityPeriod.notAfter()),
            issuerAndSubject,
            publicKey);

    JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    ContentSigner signer = signerBuilder.build(privateKey);

    X509Certificate certificate =
        new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

    AttestationToken token = AttestationToken.fromBytes("AttestationToken".getBytes());
    return new MeasurementBoundBundle(certificate, privateKey, token);
  }
}
