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

import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.SelfSignedCertificateFactory;
import com.google.mbs.domain.ValidityPeriod;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
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

/**
 * Default BouncyCastle implementation of {@link SelfSignedCertificateFactory}.
 *
 * <p>The configured {@code subjectName} must contain a single, single-valued Common Name ({@code
 * CN}) RDN, which will be suffixed with {@code " G<epochId>"} (e.g., {@code CN=MBS Root G0}) when
 * generating a certificate.
 */
public final class DefaultSelfSignedCertificateFactory implements SelfSignedCertificateFactory {

  /** Specification for the key algorithm, key size, and signature algorithm of generated certs. */
  public record CertSignatureSpec(String keyAlgorithm, int keySize, String signatureAlgorithm) {
    public CertSignatureSpec {
      Objects.requireNonNull(keyAlgorithm);
      Objects.requireNonNull(signatureAlgorithm);
    }
  }

  private final CertSignatureSpec certSignatureSpec;
  private final X500Name subjectName;
  private final Optional<GeneralNames> subjectAlternativeNames;
  private final int keyUsageMask;

  public DefaultSelfSignedCertificateFactory(
      CertSignatureSpec certSignatureSpec,
      X500Name subjectName,
      Optional<GeneralNames> subjectAlternativeNames,
      int keyUsageMask) {
    this.certSignatureSpec = Objects.requireNonNull(certSignatureSpec);
    this.subjectName = validateSubjectName(subjectName);
    this.subjectAlternativeNames = Objects.requireNonNull(subjectAlternativeNames);
    this.keyUsageMask = keyUsageMask;
  }

  @Override
  public X509CertificateAndPrivateKey generate(SelfSignedCertificate params) {
    Objects.requireNonNull(params);
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(certSignatureSpec.keyAlgorithm());
      keyGen.initialize(certSignatureSpec.keySize());
      KeyPair keyPair = keyGen.generateKeyPair();

      X509Certificate cert =
          generateCertificate(
              keyPair,
              withEpochInCn(subjectName, params.epochId()),
              params.validityPeriod(),
              subjectAlternativeNames,
              keyUsageMask,
              certSignatureSpec.signatureAlgorithm());
      return new X509CertificateAndPrivateKey(cert, keyPair.getPrivate());
    } catch (Exception e) {
      throw new SelfSignedCertificateFactoryException(
          "Failed to generate self-signed certificate", e);
    }
  }

  private static X500Name validateSubjectName(X500Name subjectName) {
    RDN[] cnRdns = subjectName.getRDNs(BCStyle.CN);
    if (cnRdns.length != 1
        || cnRdns[0].isMultiValued()
        || !(cnRdns[0].getFirst().getValue() instanceof ASN1String)) {
      throw new IllegalArgumentException(
          "subjectName must contain exactly one single-valued CN RDN: " + subjectName);
    }
    return subjectName;
  }

  private static X500Name withEpochInCn(X500Name baseName, int epochId) {
    X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
    for (RDN rdn : baseName.getRDNs()) {
      AttributeTypeAndValue first = rdn.getFirst();
      if (BCStyle.CN.equals(first.getType())) {
        String commonName = ((ASN1String) first.getValue()).getString();
        builder.addRDN(BCStyle.CN, new DERUTF8String(commonName + " G" + epochId));
      } else {
        builder.addMultiValuedRDN(rdn.getTypesAndValues());
      }
    }
    return builder.build();
  }

  private static X509Certificate generateCertificate(
      KeyPair keyPair,
      X500Name subjectName,
      ValidityPeriod validityPeriod,
      Optional<GeneralNames> subjectAlternativeNames,
      int keyUsageMask,
      String sigAlg)
      throws CertificateException, CertIOException, OperatorCreationException {
    SecureRandom secureRandom = new SecureRandom();
    // RFC 5280 limits the serial number to 20 bytes (160 bits).
    // A positive BigInteger requires 1 bit for the sign, leaving 159 bits for entropy.
    BigInteger serial = new BigInteger(159, secureRandom);

    X509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            subjectName,
            serial,
            Date.from(validityPeriod.notBefore()),
            Date.from(validityPeriod.notAfter()),
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
      // Since CN RDN is present, the DN is not empty. As per RFC 5280 Section 4.2.1.6, the SAN
      // should be non-critical.
      boolean isCritical = false;
      certBuilder.addExtension(
          Extension.subjectAlternativeName, isCritical, subjectAlternativeNames.get());
    }

    ContentSigner signer = new JcaContentSignerBuilder(sigAlg).build(keyPair.getPrivate());

    return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
  }
}
