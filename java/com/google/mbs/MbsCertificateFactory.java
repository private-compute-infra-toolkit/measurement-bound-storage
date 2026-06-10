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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Strategy for generating X.509 certificates and KeyPairs. */
@FunctionalInterface
public interface MbsCertificateFactory {

  record X509CertificateAndPrivateKey(X509Certificate certificate, PrivateKey privateKey) {}

  record CertSignatureSpec(String keyAlgorithm, int keySize, String signatureAlgorithm) {}

  class MbsCertificateFactoryException extends RuntimeException {
    public MbsCertificateFactoryException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Generates a certificate and private key.
   *
   * @return A bundle containing the certificate and private key.
   * @throws RuntimeException if generation fails.
   */
  X509CertificateAndPrivateKey generate();

  /** Returns a factory for self-signed certificates with specified parameters. */
  static MbsCertificateFactory createSelfSignedCertificatesFactory(
      CertSignatureSpec certSignatureSpec,
      X500Name subjectName,
      Duration validityDuration,
      Optional<GeneralNames> subjectAlternativeNames,
      int keyUsageMask) {
    return () -> {
      try {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(certSignatureSpec.keyAlgorithm());
        keyGen.initialize(certSignatureSpec.keySize());
        KeyPair keyPair = keyGen.generateKeyPair();

        X509Certificate cert =
            generateCertificate(
                keyPair,
                subjectName,
                validityDuration,
                subjectAlternativeNames,
                keyUsageMask,
                certSignatureSpec.signatureAlgorithm());
        return new X509CertificateAndPrivateKey(cert, keyPair.getPrivate());
      } catch (Exception e) {
        throw new MbsCertificateFactoryException("Failed to generate self-signed certificate", e);
      }
    };
  }

  private static X509Certificate generateCertificate(
      KeyPair keyPair,
      X500Name subjectName,
      Duration validityDuration,
      Optional<GeneralNames> subjectAlternativeNames,
      int keyUsageMask,
      String sigAlg)
      throws CertificateException, CertIOException, OperatorCreationException {
    Instant now = Instant.now();
    SecureRandom secureRandom = new SecureRandom();
    // RFC 5280 limits the serial number to 20 bytes (160 bits).
    // A positive BigInteger requires 1 bit for the sign, leaving 159 bits for entropy.
    BigInteger serial = new BigInteger(159, secureRandom);
    // Set the start date to 24 hours in the past to avoid clock skew issues.
    Instant notBefore = now.minus(Duration.ofDays(1));
    Instant notAfter = now.plus(validityDuration);

    X509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            subjectName,
            serial,
            Date.from(notBefore),
            Date.from(notAfter),
            subjectName,
            keyPair.getPublic());

    boolean isCa = (keyUsageMask & KeyUsage.keyCertSign) != 0;
    certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));

    certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageMask));

    try {
      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
      certBuilder.addExtension(
          Extension.subjectKeyIdentifier,
          false,
          extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
    } catch (NoSuchAlgorithmException e) {
      throw new CertificateException("Failed to add key identifiers", e);
    }

    if (subjectAlternativeNames.isPresent()) {
      // RFC 5280 requires SAN to be critical if subject is empty.
      // Note that RFC 5280 Section 4.1.2.6 strictly forbids empty subjects for CA certificates.
      // Additionally, while RFC 5280 allows empty subjects for non-CA certs (with critical SAN),
      // Java's default provider rejects certificates with empty issuer DNs. Since this factory
      // generates self-signed certificates (issuer == subject), passing an empty subject will
      // fail during parsing in Java regardless of the CA flag.
      boolean critical = subjectName.getRDNs().length == 0;
      certBuilder.addExtension(
          Extension.subjectAlternativeName, critical, subjectAlternativeNames.get());
    }

    ContentSigner signer = new JcaContentSignerBuilder(sigAlg).build(keyPair.getPrivate());

    return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
  }
}
