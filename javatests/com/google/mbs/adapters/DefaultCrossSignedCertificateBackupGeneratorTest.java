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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.mbs.adapters.DefaultSelfSignedCertificateFactory.CertSignatureSpec;
import com.google.mbs.domain.AttestationToken;
import com.google.mbs.domain.BackupCorruptedException;
import com.google.mbs.domain.CertificateCodec;
import com.google.mbs.domain.CrossSignedCertificate;
import com.google.mbs.domain.CrossSignedCertificateBackup;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.SelfSignedBundle;
import com.google.mbs.domain.SelfSignedBundleBackup;
import com.google.mbs.domain.SelfSignedBundleBackupSealer;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.SelfSignedCertificateFactory.X509CertificateAndPrivateKey;
import com.google.mbs.domain.ValidityPeriod;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Enclosed.class)
public class DefaultCrossSignedCertificateBackupGeneratorTest {

  private static final ValidityPeriod ROOT_VALIDITY =
      new ValidityPeriod(
          Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-06-01T00:00:00Z"));
  private static final ValidityPeriod CROSS_VALIDITY =
      new ValidityPeriod(
          Instant.parse("2026-02-01T00:00:00Z"), Instant.parse("2026-05-01T00:00:00Z"));
  private static final CrossSignedCertificate CROSS_CERT_CONFIG =
      new CrossSignedCertificate(0, 1, CROSS_VALIDITY);
  private static final AttestationToken ATTESTATION_TOKEN =
      AttestationToken.fromBytes("attestation-doc".getBytes(StandardCharsets.UTF_8));
  private static final SelfSignedBundleBackup SIGNER_BACKUP =
      new SelfSignedBundleBackup(
          "signer-cert".getBytes(StandardCharsets.UTF_8),
          "signer-kms".getBytes(StandardCharsets.UTF_8),
          "signer-priv".getBytes(StandardCharsets.UTF_8),
          "signer-att".getBytes(StandardCharsets.UTF_8));
  private static final SelfSignedBundleBackup SUBJECT_BACKUP =
      new SelfSignedBundleBackup(
          "subject-cert".getBytes(StandardCharsets.UTF_8),
          "subject-kms".getBytes(StandardCharsets.UTF_8),
          "subject-priv".getBytes(StandardCharsets.UTF_8),
          "subject-att".getBytes(StandardCharsets.UTF_8));
  private static final CertificateCodec CERTIFICATE_CODEC = new PemCertificateCodec();

  private static final CertSignatureSpec RSA_4096 =
      new CertSignatureSpec("RSA", 4096, "SHA256withRSA");
  private static final CertSignatureSpec EC_P256 =
      new CertSignatureSpec("EC", 256, "SHA256withECDSA");
  private static final CertSignatureSpec EC_P384 =
      new CertSignatureSpec("EC", 384, "SHA384withECDSA");

  private enum UseSkiAkiExtensions {
    INCLUDE,
    OMIT
  }

  private static SelfSignedBundle createRootBundle(
      CertSignatureSpec spec, int keyUsageMask, UseSkiAkiExtensions useSkiAkiExtensions)
      throws Exception {
    GeneralNames sans =
        new GeneralNames(
            new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://example.org/ca"));
    X509CertificateAndPrivateKey certAndKey =
        new DefaultSelfSignedCertificateFactory(
                spec,
                new X500Name("C=US, O=Google LLC, CN=MBS Root"),
                Optional.of(sans),
                keyUsageMask)
            .generate(new SelfSignedCertificate(0, ROOT_VALIDITY));
    X509Certificate cert = certAndKey.certificate();
    if (useSkiAkiExtensions == UseSkiAkiExtensions.OMIT) {
      ContentSigner signer =
          new JcaContentSignerBuilder(spec.signatureAlgorithm()).build(certAndKey.privateKey());
      cert =
          new JcaX509CertificateConverter()
              .getCertificate(
                  new JcaX509v3CertificateBuilder(cert)
                      .removeExtension(Extension.subjectKeyIdentifier)
                      .build(signer));
    }
    return new SelfSignedBundle(cert, certAndKey.privateKey(), ATTESTATION_TOKEN);
  }

  private static List<Extension> omitKeyIdentifiers(Extensions extensions) {
    return Arrays.stream(extensions.getExtensionOIDs())
        .filter(
            oid ->
                !Extension.subjectKeyIdentifier.equals(oid)
                    && !Extension.authorityKeyIdentifier.equals(oid))
        .map(extensions::getExtension)
        .toList();
  }

  @RunWith(Parameterized.class)
  public static class ValidCrossSignedGenerationTest {

    @Parameters(name = "{index}: signer={0}, subject={1}, skiAki={2}")
    public static Object[][] parameters() {
      return new Object[][] {
        {RSA_4096, RSA_4096, UseSkiAkiExtensions.INCLUDE},
        {EC_P256, EC_P384, UseSkiAkiExtensions.INCLUDE},
        {RSA_4096, EC_P256, UseSkiAkiExtensions.INCLUDE},
        {EC_P256, RSA_4096, UseSkiAkiExtensions.INCLUDE},
        {EC_P256, EC_P384, UseSkiAkiExtensions.OMIT},
      };
    }

    @Parameter(0)
    public CertSignatureSpec signerSpec;

    @Parameter(1)
    public CertSignatureSpec subjectSpec;

    @Parameter(2)
    public UseSkiAkiExtensions useSkiAkiExtensions;

    @Test
    public void generate_producesValidCrossSignedCertificate() throws Exception {
      SelfSignedBundle signerBundle =
          createRootBundle(
              signerSpec, KeyUsage.keyCertSign | KeyUsage.cRLSign, useSkiAkiExtensions);
      SelfSignedBundle subjectBundle =
          createRootBundle(
              subjectSpec, KeyUsage.keyCertSign | KeyUsage.digitalSignature, useSkiAkiExtensions);

      SelfSignedBundleBackupSealer backupSealer = mock(SelfSignedBundleBackupSealer.class);
      when(backupSealer.unseal(SIGNER_BACKUP)).thenReturn(signerBundle);
      when(backupSealer.unseal(SUBJECT_BACKUP)).thenReturn(subjectBundle);

      DefaultCrossSignedCertificateBackupGenerator generator =
          new DefaultCrossSignedCertificateBackupGenerator(backupSealer, CERTIFICATE_CODEC);
      CrossSignedCertificateBackup result =
          generator.generate(CROSS_CERT_CONFIG, SIGNER_BACKUP, SUBJECT_BACKUP);

      // Unseal both backups to verify authenticity before cross-signing.
      verify(backupSealer).unseal(SIGNER_BACKUP);
      verify(backupSealer).unseal(SUBJECT_BACKUP);

      X509Certificate crossCert = CERTIFICATE_CODEC.toCertificate(result.certBytes());
      X509Certificate signerCert = signerBundle.certificate();
      X509Certificate subjectCert = subjectBundle.certificate();
      JcaX509CertificateHolder signerHolder = new JcaX509CertificateHolder(signerCert);
      JcaX509CertificateHolder subjectHolder = new JcaX509CertificateHolder(subjectCert);
      JcaX509CertificateHolder crossHolder = new JcaX509CertificateHolder(crossCert);

      // Signed by signer's key and signature algorithm.
      crossCert.verify(signerCert.getPublicKey());
      assertEquals(signerCert.getSigAlgName(), crossCert.getSigAlgName());

      // Chaining: issuer from signer, subject & public key from subject, AKI linked to signer's
      // SKI (when present).
      assertEquals(signerCert.getSubjectX500Principal(), crossCert.getIssuerX500Principal());
      assertEquals(subjectCert.getSubjectX500Principal(), crossCert.getSubjectX500Principal());
      assertEquals(subjectCert.getPublicKey(), crossCert.getPublicKey());
      assertEquals(
          subjectHolder.getExtension(Extension.subjectKeyIdentifier),
          crossHolder.getExtension(Extension.subjectKeyIdentifier));
      if (useSkiAkiExtensions == UseSkiAkiExtensions.INCLUDE) {
        assertFalse(crossHolder.getExtension(Extension.authorityKeyIdentifier).isCritical());
        AuthorityKeyIdentifier aki =
            AuthorityKeyIdentifier.fromExtensions(crossHolder.getExtensions());
        assertArrayEquals(
            SubjectKeyIdentifier.fromExtensions(signerHolder.getExtensions()).getKeyIdentifier(),
            aki.getKeyIdentifier());
        assertNull(aki.getAuthorityCertIssuer());
        assertNull(aki.getAuthorityCertSerialNumber());
      } else {
        assertNull(crossHolder.getExtension(Extension.authorityKeyIdentifier));
      }

      // Validity period from config.
      assertEquals(CROSS_VALIDITY.notBefore(), crossCert.getNotBefore().toInstant());
      assertEquals(CROSS_VALIDITY.notAfter(), crossCert.getNotAfter().toInstant());

      // RFC 5280 serial number (positive, <= 159 bits).
      assertTrue(crossCert.getSerialNumber().signum() > 0);
      assertTrue(crossCert.getSerialNumber().bitLength() <= 159);

      // All other extensions copied unchanged from subject.
      assertEquals(
          omitKeyIdentifiers(subjectHolder.getExtensions()),
          omitKeyIdentifiers(crossHolder.getExtensions()));
    }
  }

  @RunWith(JUnit4.class)
  public static class ErrorHandlingAndPreconditionsTest {

    @Test
    public void generate_whenUnsealFailsOnSignerOrSubject_propagatesException() throws Exception {
      SelfSignedBundle signerBundle =
          createRootBundle(RSA_4096, KeyUsage.keyCertSign, UseSkiAkiExtensions.INCLUDE);
      SelfSignedBundleBackupSealer backupSealer = mock(SelfSignedBundleBackupSealer.class);
      DefaultCrossSignedCertificateBackupGenerator generator =
          new DefaultCrossSignedCertificateBackupGenerator(backupSealer, CERTIFICATE_CODEC);

      when(backupSealer.unseal(SIGNER_BACKUP))
          .thenThrow(new KmsException("KMS error"))
          .thenReturn(signerBundle);
      when(backupSealer.unseal(SUBJECT_BACKUP))
          .thenThrow(new BackupCorruptedException("Subject AEAD verification failed"));

      assertThrows(
          KmsException.class,
          () -> generator.generate(CROSS_CERT_CONFIG, SIGNER_BACKUP, SUBJECT_BACKUP));
      assertThrows(
          BackupCorruptedException.class,
          () -> generator.generate(CROSS_CERT_CONFIG, SIGNER_BACKUP, SUBJECT_BACKUP));
    }

    @Test
    public void generate_whenPublicKeysAreIdentical_throwsIllegalArgumentException()
        throws Exception {
      SelfSignedBundle bundle =
          createRootBundle(RSA_4096, KeyUsage.keyCertSign, UseSkiAkiExtensions.INCLUDE);

      SelfSignedBundleBackupSealer backupSealer = mock(SelfSignedBundleBackupSealer.class);
      DefaultCrossSignedCertificateBackupGenerator generator =
          new DefaultCrossSignedCertificateBackupGenerator(backupSealer, CERTIFICATE_CODEC);

      when(backupSealer.unseal(SIGNER_BACKUP)).thenReturn(bundle);
      when(backupSealer.unseal(SUBJECT_BACKUP)).thenReturn(bundle);
      assertThrows(
          IllegalArgumentException.class,
          () -> generator.generate(CROSS_CERT_CONFIG, SIGNER_BACKUP, SUBJECT_BACKUP));
    }
  }
}
