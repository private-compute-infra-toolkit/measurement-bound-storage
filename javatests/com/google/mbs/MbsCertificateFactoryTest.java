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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MbsCertificateFactoryTest {

  @BeforeClass
  public static void setUpClass() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static KeyUsage getKeyUsageFromCert(X509Certificate cert) {
    byte[] extValue = cert.getExtensionValue(Extension.keyUsage.getId());
    if (extValue == null) {
      return new KeyUsage(0);
    }
    byte[] octets = ASN1OctetString.getInstance(extValue).getOctets();
    return KeyUsage.getInstance(octets);
  }

  @Test
  public void generateSelfSigned_createsValidLeafCert() throws Exception {
    String subjectName = "CN=Test Service";
    Duration validity = Duration.ofDays(30);
    int expectedKeyUsageMask = KeyUsage.digitalSignature;
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory factory =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            spec, new X500Name(subjectName), validity, Optional.empty(), expectedKeyUsageMask);
    X509Certificate cert = factory.generate().certificate();

    assertNotNull(cert);
    assertEquals("CN=Test Service", cert.getSubjectX500Principal().getName());
    assertEquals("CN=Test Service", cert.getIssuerX500Principal().getName());
    cert.verify(cert.getPublicKey());
    assertEquals(-1, cert.getBasicConstraints());
    assertEquals(
        new KeyUsage(expectedKeyUsageMask).toString(), getKeyUsageFromCert(cert).toString());
  }

  @Test
  public void generateSelfSigned_createsValidRootCaCert() throws Exception {
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    int expectedKeyUsageMask = KeyUsage.keyCertSign | KeyUsage.nonRepudiation;
    MbsCertificateFactory factory =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            spec,
            new X500Name("CN=Test CA"),
            Duration.ofDays(30),
            Optional.empty(),
            expectedKeyUsageMask);
    X509Certificate cert = factory.generate().certificate();

    assertNotNull(cert);
    assertEquals(Integer.MAX_VALUE, cert.getBasicConstraints());

    assertEquals(
        new KeyUsage(expectedKeyUsageMask).toString(), getKeyUsageFromCert(cert).toString());
  }

  @Test
  public void generateSelfSigned_addsSubjectAlternativeName() throws Exception {
    String uri = "http://example.com";
    GeneralName san = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
    GeneralNames sans = new GeneralNames(san);

    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory factory =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            spec,
            new X500Name("CN=Test"),
            Duration.ofDays(30),
            Optional.of(sans),
            KeyUsage.digitalSignature);
    X509Certificate cert = factory.generate().certificate();

    assertNotNull(cert);
    var subjectAlternativeNames = cert.getSubjectAlternativeNames();
    assertNotNull(subjectAlternativeNames);
    assertEquals(1, subjectAlternativeNames.size());
    var firstSan = subjectAlternativeNames.iterator().next();
    assertEquals(GeneralName.uniformResourceIdentifier, firstSan.get(0));
    assertEquals(uri, firstSan.get(1));
  }

  private static KeyPair generateKeyPair() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }
}
