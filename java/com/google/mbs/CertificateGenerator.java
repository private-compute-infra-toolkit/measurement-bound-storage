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

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/** A utility for generating self-signed certificates. */
public class CertificateGenerator {

  // RFC 5280 limits the serial number to 20 bytes (160 bits).
  // A positive BigInteger requires 1 bit for the sign, leaving 159 bits for entropy.
  private static final int SERIAL_NUMBER_ENTROPY_BITS = 159;

  // By default, the generated certificate is valid for 30 days.
  private static final Duration THIRTY_DAYS = Duration.ofDays(30);

  private static final SecureRandom secureRandom = new SecureRandom();

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static class CertificateAndKey {
    public final X509Certificate certificate;
    public final PrivateKey privateKey;

    public CertificateAndKey(X509Certificate certificate, PrivateKey privateKey) {
      this.certificate = certificate;
      this.privateKey = privateKey;
    }
  }

  public static CertificateAndKey generateSelfSignedCertificate()
      throws CertificateException, IOException {
    KeyPair keyPair = generateKeyPair();
    X509Certificate cert = generateCertificate(keyPair);
    return new CertificateAndKey(cert, keyPair.getPrivate());
  }

  public static X509Certificate signCsr(
      byte[] csrBytes,
      X509Certificate issuerCert,
      PrivateKey issuerPrivateKey,
      String san,
      Instant notBefore,
      Instant notAfter)
      throws CertificateException, IOException {
    try {
      PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

      BigInteger serial = new BigInteger(SERIAL_NUMBER_ENTROPY_BITS, secureRandom);

      X509v3CertificateBuilder certBuilder =
          new JcaX509v3CertificateBuilder(
              new X500Name(issuerCert.getSubjectX500Principal().getName()),
              serial,
              Date.from(notBefore),
              Date.from(notAfter),
              csr.getSubject(),
              new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo()));

      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
      AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(issuerCert.getPublicKey());
      SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo());

      certBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
      certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
      certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
      certBuilder.addExtension(
          Extension.keyUsage,
          true,
          new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

      if (san != null && !san.isEmpty()) {
        certBuilder.addExtension(
            Extension.subjectAlternativeName,
            false,
            new GeneralNames(new GeneralName(GeneralName.dNSName, san)));
      }

      ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);

      return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    } catch (OperatorCreationException | GeneralSecurityException e) {
      throw new CertificateException(e);
    }
  }

  public static CertificateAndKey generateSelfSignedCertificate(KeyPair keyPair)
      throws CertificateException, IOException {
    X509Certificate cert = generateCertificate(keyPair);
    return new CertificateAndKey(cert, keyPair.getPrivate());
  }

  private static KeyPair generateKeyPair() throws CertificateException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
      keyPairGenerator.initialize(4096, secureRandom);
      return keyPairGenerator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new CertificateException(e);
    }
  }

  private static X509Certificate generateCertificate(KeyPair keyPair)
      throws CertificateException, IOException {
    // By default, the issuer and subject are the same, since this is a self-signed certificate.
    X500Name issuerAndSubject = new X500Name("CN=Standalone CA");
    Instant now = Instant.now();
    BigInteger serial = new BigInteger(SERIAL_NUMBER_ENTROPY_BITS, secureRandom);
    // Set the start date to 24 hours in the past to avoid clock skew issues.
    Instant notBefore = now.minus(Duration.ofDays(1));
    Instant notAfter = now.plus(THIRTY_DAYS);

    X509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            issuerAndSubject,
            serial,
            Date.from(notBefore),
            Date.from(notAfter),
            issuerAndSubject,
            keyPair.getPublic());

    // Mark the certificate as a CA certificate.
    certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    // Mark the certificate for signing other certificates.
    certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
    try {
      ContentSigner signer =
          new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

      return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    } catch (OperatorCreationException | GeneralSecurityException e) {
      throw new CertificateException(e);
    }
  }
}
