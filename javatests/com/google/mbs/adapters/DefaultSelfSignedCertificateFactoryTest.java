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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.mbs.adapters.DefaultSelfSignedCertificateFactory.CertSignatureSpec;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.SelfSignedCertificateFactory;
import com.google.mbs.domain.ValidityPeriod;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class DefaultSelfSignedCertificateFactoryTest {

  private static final CertSignatureSpec RSA_2048 =
      new CertSignatureSpec("RSA", 2048, "SHA256withRSA");

  @BeforeClass
  public static void setUpClass() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static SelfSignedCertificate defaultParams() {
    return new SelfSignedCertificate(
        0,
        new ValidityPeriod(
            Instant.parse("1930-01-01T00:00:00Z"), Instant.parse("1930-02-01T00:00:00Z")));
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
    int expectedKeyUsageMask = KeyUsage.digitalSignature;
    SelfSignedCertificateFactory factory =
        new DefaultSelfSignedCertificateFactory(
            RSA_2048, new X500Name("CN=Test Service"), Optional.empty(), expectedKeyUsageMask);
    SelfSignedCertificate params = defaultParams();
    X509Certificate cert = factory.generate(params).certificate();

    assertNotNull(cert);
    assertEquals("CN=Test Service G0", cert.getSubjectX500Principal().getName());
    assertEquals("CN=Test Service G0", cert.getIssuerX500Principal().getName());
    assertEquals(params.validityPeriod().notBefore(), cert.getNotBefore().toInstant());
    assertEquals(params.validityPeriod().notAfter(), cert.getNotAfter().toInstant());
    cert.verify(cert.getPublicKey());
    assertEquals(-1, cert.getBasicConstraints());
    assertEquals(
        new KeyUsage(expectedKeyUsageMask).toString(), getKeyUsageFromCert(cert).toString());
    byte[] leafSkiBytes = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    assertNotNull(leafSkiBytes);
    SubjectKeyIdentifier actualLeafSki =
        SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(leafSkiBytes).getOctets());
    SubjectKeyIdentifier expectedLeafSki =
        new JcaX509ExtensionUtils().createSubjectKeyIdentifier(cert.getPublicKey());
    assertEquals(expectedLeafSki, actualLeafSki);
    assertNull(cert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
  }

  @Test
  public void generateSelfSigned_createsValidRootCaCert() throws Exception {
    int expectedKeyUsageMask = KeyUsage.keyCertSign | KeyUsage.nonRepudiation;
    SelfSignedCertificateFactory factory =
        new DefaultSelfSignedCertificateFactory(
            RSA_2048, new X500Name("CN=Test CA"), Optional.empty(), expectedKeyUsageMask);
    X509Certificate cert = factory.generate(defaultParams()).certificate();

    assertNotNull(cert);
    assertEquals(Integer.MAX_VALUE, cert.getBasicConstraints());

    assertEquals(
        new KeyUsage(expectedKeyUsageMask).toString(), getKeyUsageFromCert(cert).toString());
    byte[] rootSkiBytes = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    assertNotNull(rootSkiBytes);
    SubjectKeyIdentifier actualRootSki =
        SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(rootSkiBytes).getOctets());
    SubjectKeyIdentifier expectedRootSki =
        new JcaX509ExtensionUtils().createSubjectKeyIdentifier(cert.getPublicKey());
    assertEquals(expectedRootSki, actualRootSki);
    assertNull(cert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
  }

  @Test
  public void generateSelfSigned_addsSubjectAlternativeName() throws Exception {
    String uri = "http://example.com";
    GeneralName san = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
    GeneralNames sans = new GeneralNames(san);

    SelfSignedCertificateFactory factory =
        new DefaultSelfSignedCertificateFactory(
            RSA_2048, new X500Name("CN=Test"), Optional.of(sans), KeyUsage.digitalSignature);
    X509Certificate cert = factory.generate(defaultParams()).certificate();

    assertNotNull(cert);
    assertTrue(
        cert.getNonCriticalExtensionOIDs().contains(Extension.subjectAlternativeName.getId()));
    var subjectAlternativeNames = cert.getSubjectAlternativeNames();
    assertNotNull(subjectAlternativeNames);
    assertEquals(1, subjectAlternativeNames.size());
    var firstSan = subjectAlternativeNames.iterator().next();
    assertEquals(GeneralName.uniformResourceIdentifier, firstSan.get(0));
    assertEquals(uri, firstSan.get(1));
  }

  @Test
  public void constructor_invalidSubjectName_throwsIllegalArgumentException() {
    List<X500Name> invalidSubjects =
        List.of(
            new X500Name(""),
            new X500Name("C=US, O=Google LLC"),
            new X500Name("CN=Root 1, CN=Root 2"),
            new X500Name("CN=Root+OU=Unit"));

    for (X500Name invalidSubject : invalidSubjects) {
      assertThrows(
          "Expected IllegalArgumentException for subjectName: " + invalidSubject,
          IllegalArgumentException.class,
          () ->
              new DefaultSelfSignedCertificateFactory(
                  RSA_2048, invalidSubject, Optional.empty(), KeyUsage.keyCertSign));
    }
  }

  @Test
  public void generateSelfSigned_multiRdnSubject_preservesRdnOrderAndSuffixesCnWithEpoch()
      throws Exception {
    SelfSignedCertificate params = new SelfSignedCertificate(777, defaultParams().validityPeriod());
    for (String cn : List.of("MBS Root", "\\#MBS\\, Root\\+CA\\\\\\ ")) {
      SelfSignedCertificateFactory factory =
          new DefaultSelfSignedCertificateFactory(
              RSA_2048,
              new X500Name("C=US, O=Google LLC, CN=" + cn + ", OU=PCIT"),
              Optional.empty(),
              KeyUsage.keyCertSign);

      X509Certificate cert = factory.generate(params).certificate();

      X500Name expectedDn = new X500Name("C=US, O=Google LLC, CN=" + cn + " G777, OU=PCIT");
      JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
      assertEquals(expectedDn, holder.getSubject());
      assertEquals(expectedDn, holder.getIssuer());
    }
  }
}
