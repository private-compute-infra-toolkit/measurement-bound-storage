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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertificate;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.ValidityPeriod;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CertificatesConfigTest {

  @Test
  public void validityPeriod_constructionAndGetters() {
    Instant notBefore = Instant.ofEpochSecond(100);
    Instant notAfter = Instant.ofEpochSecond(200);
    ValidityPeriod vp = new ValidityPeriod(notBefore, notAfter);

    assertThat(vp.notBefore()).isEqualTo(notBefore);
    assertThat(vp.notAfter()).isEqualTo(notAfter);
  }

  @Test
  public void validityPeriod_notAfterBeforeNotBefore_throwsIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new ValidityPeriod(Instant.ofEpochSecond(200), Instant.ofEpochSecond(100)));
  }

  @Test
  public void validityPeriod_zeroDuration_throwsIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(100)));
  }

  @Test
  public void validityPeriod_isValidAt_validatesBoundaries() {
    Instant notBefore = Instant.ofEpochSecond(1000);
    Instant notAfter = Instant.ofEpochSecond(2000);
    ValidityPeriod vp = new ValidityPeriod(notBefore, notAfter);

    assertThat(vp.isValidAt(notBefore)).isTrue();
    assertThat(vp.isValidAt(notAfter)).isTrue();
    assertThat(vp.isValidAt(Instant.ofEpochSecond(1500))).isTrue();
    assertThat(vp.isValidAt(Instant.ofEpochSecond(999))).isFalse();
    assertThat(vp.isValidAt(Instant.ofEpochSecond(2001))).isFalse();
  }

  @Test
  public void selfSignedCertificate_keyIdZero_succeeds() {
    ValidityPeriod vp = new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(200));
    SelfSignedCertificate cert = new SelfSignedCertificate(0, vp);
    assertThat(cert.epochId()).isEqualTo(0);
    assertThat(cert.validityPeriod()).isEqualTo(vp);
  }

  @Test
  public void crossSignedCertificate_keyIdZero_succeeds() {
    ValidityPeriod vp = new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(200));
    CrossSignedCertificate cert = new CrossSignedCertificate(0, 1, vp);
    assertThat(cert.privateKeyEpochId()).isEqualTo(0);
    assertThat(cert.publicKeyEpochId()).isEqualTo(1);
    assertThat(cert.certificateId()).isEqualTo("0_1");
  }

  @Test
  public void crossSignedCertificate_signedByEqualsPublicKey_throwsIllegalArgumentException() {
    ValidityPeriod vp = new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(200));
    assertThrows(IllegalArgumentException.class, () -> new CrossSignedCertificate(1, 1, vp));
  }

  @Test
  public void crossSignedCertificateId_privateKeyEqualsPublicKey_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new CrossSignedCertificateId(1, 1));
  }

  @Test
  public void crossSignedCertificateId_fromKeyString_validString_returnsId() {
    CrossSignedCertificateId id01 = CrossSignedCertificateId.fromKeyString("0_1");
    assertThat(id01).isEqualTo(new CrossSignedCertificateId(0, 1));
    assertThat(CrossSignedCertificateId.fromKeyString(id01.toKeyString())).isEqualTo(id01);

    CrossSignedCertificateId id102 = CrossSignedCertificateId.fromKeyString("10_2");
    assertThat(id102).isEqualTo(new CrossSignedCertificateId(10, 2));
  }

  @Test
  public void
      crossSignedCertificateId_fromKeyString_invalidFormat_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString(""));
    assertThrows(IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("0"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("0_1_2"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("a_1"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("0_b"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("_1"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("0_"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("1_1"));

    // Non-canonical integer representations must be rejected so distinct strings cannot map to the
    // same CrossSignedCertificateId.
    IllegalArgumentException nonCanonical =
        assertThrows(
            IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("00_1"));
    assertThat(nonCanonical).hasMessageThat().contains("Non-canonical cross-signed key");

    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("0_01"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("+0_1"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("0_+1"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("-0_1"));
    assertThrows(
        IllegalArgumentException.class, () -> CrossSignedCertificateId.fromKeyString("-01_2"));
  }

  @Test
  public void certificatesConfig_emptyActiveSelfSignedCertificateIds_throwsException() {
    ValidityPeriod vp = new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(200));
    SelfSignedCertificate self1 = new SelfSignedCertificate(1, vp);

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new CertificatesConfig(Map.of(1, self1), Map.of(), Set.of(), Set.of(), Set.of(1)));
    assertThat(e).hasMessageThat().contains("activeSelfSignedCertificateIds must not be empty");
  }

  @Test
  public void certificatesConfig_activeSelfSignedCertificates_returnsActiveCertificates() {
    ValidityPeriod vp = new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(200));
    SelfSignedCertificate self0 = new SelfSignedCertificate(0, vp);
    SelfSignedCertificate self1 = new SelfSignedCertificate(1, vp);
    SelfSignedCertificate self2 = new SelfSignedCertificate(2, vp);

    CertificatesConfig config =
        new CertificatesConfig(
            Map.of(0, self0, 1, self1, 2, self2),
            Map.of(),
            Set.of(2, 0),
            Set.of(),
            Set.of(0, 1, 2));

    assertThat(config.activeSelfSignedCertificates()).containsExactly(self0, self2);
  }

  @Test
  public void certificatesConfig_activeCrossSignedCertificates_returnsActiveCertificates() {
    ValidityPeriod vp = new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(200));
    SelfSignedCertificate self0 = new SelfSignedCertificate(0, vp);
    SelfSignedCertificate self1 = new SelfSignedCertificate(1, vp);
    SelfSignedCertificate self2 = new SelfSignedCertificate(2, vp);
    CrossSignedCertificate cross01 = new CrossSignedCertificate(0, 1, vp);
    CrossSignedCertificate cross10 = new CrossSignedCertificate(1, 0, vp);
    CrossSignedCertificate cross12 = new CrossSignedCertificate(1, 2, vp);

    CertificatesConfig config =
        CertificatesConfig.builder()
            .setSelfSignedCertificates(Map.of(0, self0, 1, self1, 2, self2))
            .setCrossSignedCertificates(
                Map.of(cross01.id(), cross01, cross10.id(), cross10, cross12.id(), cross12))
            .setActiveSelfSignedCertificateIds(Set.of(0, 1))
            .setActiveCrossSignedCertificateIds(Set.of(cross12.id(), cross01.id()))
            .build();

    assertThat(config.activeCrossSignedCertificates()).containsExactly(cross01, cross12);
  }

  @Test
  public void certificatesConfig_domainConstructor_validatesCrossSignedKeys() {
    ValidityPeriod vp = new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(200));
    SelfSignedCertificate self1 = new SelfSignedCertificate(1, vp);
    SelfSignedCertificate self2 = new SelfSignedCertificate(2, vp);
    CrossSignedCertificate cross12 = new CrossSignedCertificate(1, 2, vp);

    // Map key mismatch for self-signed
    assertThrows(
        IllegalArgumentException.class,
        () -> new CertificatesConfig(Map.of(2, self1), Map.of(), Set.of(2), Set.of(), Set.of()));

    // Map key mismatch for cross-signed
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new CertificatesConfig(
                Map.of(1, self1, 2, self2),
                Map.of(new CrossSignedCertificateId(99, 100), cross12),
                Set.of(1),
                Set.of(),
                Set.of()));

    // Cross-cert referencing missing private key in inventory
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new CertificatesConfig(
                Map.of(2, self2), Map.of(cross12.id(), cross12), Set.of(2), Set.of(), Set.of()));

    // Cross-cert referencing missing public key in inventory
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new CertificatesConfig(
                Map.of(1, self1), Map.of(cross12.id(), cross12), Set.of(1), Set.of(), Set.of()));
  }

  @Test
  public void certificatesConfig_inventoryContainmentValidation_throwsIllegalArgumentException() {
    ValidityPeriod vp = new ValidityPeriod(Instant.ofEpochSecond(100), Instant.ofEpochSecond(200));
    SelfSignedCertificate self1 = new SelfSignedCertificate(1, vp);

    IllegalArgumentException eActive =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new CertificatesConfig(Map.of(1, self1), Map.of(), Set.of(99), Set.of(), Set.of()));
    assertThat(eActive).hasMessageThat().contains("key 99");

    IllegalArgumentException eAcceptable =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new CertificatesConfig(
                    Map.of(1, self1), Map.of(), Set.of(1), Set.of(), Set.of(99)));
    assertThat(eAcceptable).hasMessageThat().contains("key 99");

    IllegalArgumentException eCross =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new CertificatesConfig(
                    Map.of(1, self1),
                    Map.of(),
                    Set.of(1),
                    Set.of(new CrossSignedCertificateId(1, 2)),
                    Set.of()));
    assertThat(eCross).hasMessageThat().contains("certificate ID '1_2'");
  }
}
