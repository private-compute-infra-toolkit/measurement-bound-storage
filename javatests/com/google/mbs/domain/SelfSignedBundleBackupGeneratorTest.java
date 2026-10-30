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

package com.google.mbs.domain;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.SelfSignedCertificateFactory.SelfSignedCertificateFactoryException;
import com.google.mbs.domain.SelfSignedCertificateFactory.X509CertificateAndPrivateKey;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class SelfSignedBundleBackupGeneratorTest {

  private static final byte[] TEST_USER_DATA = "test_userdata".getBytes(StandardCharsets.UTF_8);
  private static final ValidityPeriod VALIDITY_PERIOD =
      new ValidityPeriod(
          Instant.parse("1930-01-01T00:00:00Z"), Instant.parse("1930-02-01T00:00:00Z"));
  private static final SelfSignedCertificate CERT_CONFIG =
      new SelfSignedCertificate(0, VALIDITY_PERIOD);
  private static final AttestationToken ATTESTATION_TOKEN =
      AttestationToken.fromBytes("attestation-doc".getBytes(StandardCharsets.UTF_8));
  private static final SelfSignedBundleBackup SEALED_BACKUP =
      new SelfSignedBundleBackup(
          "cert".getBytes(StandardCharsets.UTF_8),
          "kms-key".getBytes(StandardCharsets.UTF_8),
          "priv-key".getBytes(StandardCharsets.UTF_8),
          "attestation-doc".getBytes(StandardCharsets.UTF_8));

  @Mock private SelfSignedCertificateFactory certificateFactory;
  @Mock private AttestationCollector attestationCollector;
  @Mock private SelfSignedBundleBackupSealer backupSealer;
  @Mock private X509Certificate certificate;
  @Mock private PublicKey publicKey;
  @Mock private PrivateKey privateKey;

  private SelfSignedBundle expectedBundle;
  private SelfSignedBundleBackupGenerator generator;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    expectedBundle = new SelfSignedBundle(certificate, privateKey, ATTESTATION_TOKEN);

    when(certificate.getPublicKey()).thenReturn(publicKey);
    when(certificateFactory.generate(CERT_CONFIG))
        .thenReturn(new X509CertificateAndPrivateKey(certificate, privateKey));
    when(attestationCollector.collectBoundToPubkey(publicKey, TEST_USER_DATA))
        .thenReturn(ATTESTATION_TOKEN);
    when(backupSealer.seal(expectedBundle)).thenReturn(SEALED_BACKUP);

    generator =
        new SelfSignedBundleBackupGenerator(
            certificateFactory, attestationCollector, TEST_USER_DATA, backupSealer);
  }

  @Test
  public void generate_createsCertificateCollectsAttestationAndSealsBundle() throws Exception {
    SelfSignedBundleBackup result = generator.generate(CERT_CONFIG);

    assertSame(SEALED_BACKUP, result);
    InOrder inOrder = inOrder(certificateFactory, attestationCollector, backupSealer);
    inOrder.verify(certificateFactory).generate(CERT_CONFIG);
    inOrder.verify(attestationCollector).collectBoundToPubkey(publicKey, TEST_USER_DATA);
    inOrder.verify(backupSealer).seal(expectedBundle);
  }

  @Test
  public void generate_certificateGenerationFails_propagatesException() {
    when(certificateFactory.generate(CERT_CONFIG))
        .thenThrow(
            new SelfSignedCertificateFactoryException("Keygen failed", new RuntimeException()));

    assertThrows(
        SelfSignedCertificateFactoryException.class, () -> generator.generate(CERT_CONFIG));
    verifyNoInteractions(attestationCollector, backupSealer);
  }

  @Test
  public void generate_attestationFails_propagatesException() {
    when(attestationCollector.collectBoundToPubkey(publicKey, TEST_USER_DATA))
        .thenThrow(new IllegalStateException("Attestation failed"));

    assertThrows(IllegalStateException.class, () -> generator.generate(CERT_CONFIG));
    verifyNoInteractions(backupSealer);
  }

  @Test
  public void generate_sealFails_propagatesKmsException() throws Exception {
    when(backupSealer.seal(expectedBundle)).thenThrow(new KmsException("KMS error"));

    assertThrows(KmsException.class, () -> generator.generate(CERT_CONFIG));
  }
}
