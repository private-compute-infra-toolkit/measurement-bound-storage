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

package com.google.mbs;

import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CertificateGeneratorTest {

  @BeforeClass
  public static void setUpClass() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void signCsr_signsSuccessfully() throws Exception {
    CertificateGenerator.CertificateAndKey root =
        CertificateGenerator.generateSelfSignedCertificate();

    KeyPair subjectKeyPair = createKeyPair();
    PKCS10CertificationRequest csr = createCsr(subjectKeyPair);
    byte[] csrBytes = csr.getEncoded();

    Instant now = Instant.now();
    X509Certificate signedCert =
        CertificateGenerator.signCsr(
            csrBytes,
            root.certificate,
            root.privateKey,
            "test.example.com",
            now,
            now.plus(Duration.ofMinutes(1)));

    assertNotNull(signedCert);
    signedCert.verify(root.certificate.getPublicKey());
    signedCert.checkValidity(java.util.Date.from(now.plusSeconds(30)));
  }

  private static PKCS10CertificationRequest createCsr(KeyPair subjectKeyPair)
      throws OperatorCreationException {
    X500Name subject = new X500Name("CN=Test Subject");
    PKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(subject, subjectKeyPair.getPublic());
    JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    ContentSigner signer = csBuilder.build(subjectKeyPair.getPrivate());
    PKCS10CertificationRequest csr = p10Builder.build(signer);
    return csr;
  }

  private static KeyPair createKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }
}
