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

import com.google.common.flogger.FluentLogger;
import com.google.mbs.domain.BackupCorruptedException;
import com.google.mbs.domain.CertificateCodec;
import com.google.mbs.domain.CrossSignedCertificate;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.CrossSignedCertificateBackupGenerator;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.SelfSignedBundle;
import com.google.mbs.domain.SelfSignedBundleBackup;
import com.google.mbs.domain.SelfSignedBundleBackupSealer;
import com.google.mbs.domain.ValidityPeriod;
import jakarta.inject.Inject;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class DefaultCrossSignedCertificateBackupGenerator
    implements CrossSignedCertificateBackupGenerator {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static final int KEY_CERT_SIGN_BIT_INDEX = 5;

  private final SelfSignedBundleBackupSealer backupSealer;
  private final CertificateCodec certificateCodec;

  @Inject
  DefaultCrossSignedCertificateBackupGenerator(
      SelfSignedBundleBackupSealer backupSealer, CertificateCodec certificateCodec) {
    this.backupSealer = Objects.requireNonNull(backupSealer);
    this.certificateCodec = Objects.requireNonNull(certificateCodec);
  }

  @Override
  public CrossSignedCertificateBackup generate(
      CrossSignedCertificate certConfig,
      SelfSignedBundleBackup signerBackup,
      SelfSignedBundleBackup subjectBackup)
      throws KmsException, BackupCorruptedException {
    // Unseal both backups even though the subject's certificate is stored in plaintext PEM.
    // Unsealing verifies via KMS decryption, AEAD associated data binding, and private-key
    // consistency checks that the subject certificate in storage was genuinely generated and
    // sealed by an attested TEE instance with access to our KMS key, preventing us from
    // cross-signing an attacker-injected certificate.
    SelfSignedBundle signer = backupSealer.unseal(signerBackup);
    SelfSignedBundle subject = backupSealer.unseal(subjectBackup);

    X509Certificate crossSignedCert =
        generateCrossSignedCertificate(
            certConfig.validityPeriod(),
            signer.certificate(),
            signer.privateKey(),
            subject.certificate());
    return new CrossSignedCertificateBackup(certificateCodec.toBytes(crossSignedCert));
  }

  private static X509Certificate generateCrossSignedCertificate(
      ValidityPeriod validityPeriod,
      X509Certificate signerCert,
      PrivateKey signerPrivateKey,
      X509Certificate subjectCert) {
    validateCertificatesForCrossSigning(signerCert, subjectCert);

    try {
      X509CertificateHolder signerHolder = new JcaX509CertificateHolder(signerCert);
      X509CertificateHolder subjectHolder = new JcaX509CertificateHolder(subjectCert);

      X509v3CertificateBuilder certBuilder =
          new JcaX509v3CertificateBuilder(
              signerHolder.getSubject(),
              generateSerialNumber(),
              Date.from(validityPeriod.notBefore()),
              Date.from(validityPeriod.notAfter()),
              subjectHolder.getSubject(),
              subjectCert.getPublicKey());

      for (Extension extension : buildExtensions(signerHolder, subjectHolder)) {
        certBuilder.addExtension(extension);
      }

      ContentSigner contentSigner =
          new JcaContentSignerBuilder(signerCert.getSigAlgName()).build(signerPrivateKey);
      return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    } catch (GeneralSecurityException | IOException | OperatorCreationException e) {
      throw new IllegalStateException("Failed to generate cross-signed certificate", e);
    }
  }

  private static void validateCertificatesForCrossSigning(
      X509Certificate signerCert, X509Certificate subjectCert) {
    if (!isCaCertificate(signerCert)) {
      logger.atWarning().log(
          "Signer certificate (subject=%s) is not a CA certificate with keyCertSign key usage."
              + " The resulting certificate may fail RFC 5280 validation.",
          signerCert.getSubjectX500Principal());
    }
    if (signerCert.getPublicKey().equals(subjectCert.getPublicKey())) {
      throw new IllegalArgumentException(
          "Signer and subject certificates must have distinct public keys");
    }
  }

  private static boolean isCaCertificate(X509Certificate cert) {
    boolean[] keyUsage = cert.getKeyUsage();
    return cert.getBasicConstraints() != -1
        && keyUsage != null
        && keyUsage.length > KEY_CERT_SIGN_BIT_INDEX
        && keyUsage[KEY_CERT_SIGN_BIT_INDEX];
  }

  private static BigInteger generateSerialNumber() {
    // RFC 5280 limits the serial number to 20 bytes (160 bits).
    // A positive BigInteger requires 1 bit for the sign, leaving 159 bits for entropy.
    return new BigInteger(159, new SecureRandom());
  }

  private static List<Extension> buildExtensions(
      X509CertificateHolder signerHolder, X509CertificateHolder subjectHolder) throws IOException {
    return Stream.concat(
            omitAuthorityKeyIdentifier(subjectHolder.getExtensions()).stream(),
            createAuthorityKeyIdentifier(signerHolder.getExtensions()).stream())
        .toList();
  }

  private static List<Extension> omitAuthorityKeyIdentifier(Extensions extensions) {
    if (extensions == null) {
      return List.of();
    }
    return Arrays.stream(extensions.getExtensionOIDs())
        .filter(oid -> !Extension.authorityKeyIdentifier.equals(oid))
        .map(extensions::getExtension)
        .toList();
  }

  private static Optional<Extension> createAuthorityKeyIdentifier(Extensions signerExtensions)
      throws IOException {
    SubjectKeyIdentifier signerSki = SubjectKeyIdentifier.fromExtensions(signerExtensions);
    if (signerSki == null) {
      return Optional.empty();
    }
    return Optional.of(
        Extension.create(
            Extension.authorityKeyIdentifier,
            false,
            new AuthorityKeyIdentifier(signerSki.getKeyIdentifier())));
  }
}
