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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.common.io.Resources;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertificate;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.InvalidCertificatesConfigException;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.protobuf.TextFormat;
import com.google.protobuf.Timestamp;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CertificatesConfigMapperTest {

  private static final String TEST_RESOURCE =
      "com/google/mbs/adapters/res/valid_certificates_config.textproto";

  private static String getTestResourceContent() throws Exception {
    return Resources.toString(Resources.getResource(TEST_RESOURCE), StandardCharsets.UTF_8);
  }

  @Test
  public void toDomain_fromTextProtoResource_mapsCorrectly() throws Exception {
    String textProto = getTestResourceContent();
    com.google.mbs.v1.CertificatesConfig.Builder builder =
        com.google.mbs.v1.CertificatesConfig.newBuilder();
    TextFormat.getParser().merge(textProto, builder);

    CertificatesConfig config = CertificatesConfigMapper.toDomain(builder.build());

    assertThat(config.selfSignedCertificates()).hasSize(2);
    assertThat(config.crossSignedCertificates()).hasSize(1);
    assertThat(config.activeSelfSignedCertificateIds()).containsExactly(0);
    assertThat(config.activeCrossSignedCertificateIds())
        .containsExactly(new CrossSignedCertificateId(0, 2));
    assertThat(config.acceptableSelfSignedCertificateIds()).containsExactly(0, 2);

    SelfSignedCertificate cert0 = config.selfSignedCertificates().get(0);
    assertThat(cert0).isNotNull();
    assertThat(cert0.epochId()).isEqualTo(0);
    assertThat(cert0.validityPeriod().notBefore()).isEqualTo(Instant.ofEpochSecond(1700000000));
    assertThat(cert0.validityPeriod().notAfter()).isEqualTo(Instant.ofEpochSecond(1710000000));

    CrossSignedCertificate crossCert =
        config.crossSignedCertificates().get(new CrossSignedCertificateId(0, 2));
    assertThat(crossCert).isNotNull();
    assertThat(crossCert.privateKeyEpochId()).isEqualTo(0);
    assertThat(crossCert.publicKeyEpochId()).isEqualTo(2);
    assertThat(crossCert.certificateId()).isEqualTo("0_2");
  }

  @Test
  public void fromTextProto_string_parsesAndMaps() throws Exception {
    String textProto = getTestResourceContent();

    CertificatesConfig config = CertificatesConfigMapper.fromTextProto(textProto);

    assertThat(config.selfSignedCertificates()).hasSize(2);
    assertThat(config.activeSelfSignedCertificateIds()).containsExactly(0);
  }

  @Test
  public void toDomain_invalidCrossSignedKeyFormat_throwsException() {
    com.google.mbs.v1.CertificatesConfig proto =
        com.google.mbs.v1.CertificatesConfig.newBuilder()
            .putCrossSignedCertificates(
                "invalid_key",
                com.google.mbs.v1.CrossSignedCertificate.newBuilder()
                    .setPrivateKeyEpochId(1)
                    .setPublicKeyEpochId(2)
                    .setValidityPeriod(
                        com.google.mbs.v1.ValidityPeriod.newBuilder()
                            .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
                            .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
                            .build())
                    .build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class, () -> CertificatesConfigMapper.toDomain(proto));
  }

  @Test
  public void toDomain_missingValidityPeriodSelfSigned_throwsException() {
    com.google.mbs.v1.CertificatesConfig proto =
        com.google.mbs.v1.CertificatesConfig.newBuilder()
            .putSelfSignedCertificates(
                1, com.google.mbs.v1.SelfSignedCertificate.newBuilder().setEpochId(1).build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class, () -> CertificatesConfigMapper.toDomain(proto));
  }

  @Test
  public void toDomain_missingValidityPeriodCrossSigned_throwsException() {
    com.google.mbs.v1.CertificatesConfig proto =
        com.google.mbs.v1.CertificatesConfig.newBuilder()
            .putCrossSignedCertificates(
                "1_2",
                com.google.mbs.v1.CrossSignedCertificate.newBuilder()
                    .setPrivateKeyEpochId(1)
                    .setPublicKeyEpochId(2)
                    .build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class, () -> CertificatesConfigMapper.toDomain(proto));
  }

  @Test
  public void toDomain_missingNotBeforeOrNotAfter_throwsException() {
    com.google.mbs.v1.ValidityPeriod missingNotAfter =
        com.google.mbs.v1.ValidityPeriod.newBuilder()
            .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class,
        () -> CertificatesConfigMapper.toDomain(missingNotAfter));

    com.google.mbs.v1.ValidityPeriod missingNotBefore =
        com.google.mbs.v1.ValidityPeriod.newBuilder()
            .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class,
        () -> CertificatesConfigMapper.toDomain(missingNotBefore));
  }

  @Test
  public void fromTextProto_malformedSyntax_throwsException() {
    assertThrows(
        InvalidCertificatesConfigException.class,
        () -> CertificatesConfigMapper.fromTextProto("invalid { syntax"));
  }

  @Test
  public void toDomain_timestampNanosNonZero_throwsException() {
    com.google.mbs.v1.ValidityPeriod invalid =
        com.google.mbs.v1.ValidityPeriod.newBuilder()
            .setNotBefore(Timestamp.newBuilder().setSeconds(100).setNanos(500).build())
            .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
            .build();

    InvalidCertificatesConfigException e =
        assertThrows(
            InvalidCertificatesConfigException.class,
            () -> CertificatesConfigMapper.toDomain(invalid));
    assertThat(e).hasMessageThat().contains("Timestamp nanos must be 0 for X.509 validity periods");
  }

  @Test
  public void toDomain_selfSignedMissingEpochId_throwsException() {
    com.google.mbs.v1.SelfSignedCertificate cert =
        com.google.mbs.v1.SelfSignedCertificate.newBuilder()
            .setValidityPeriod(
                com.google.mbs.v1.ValidityPeriod.newBuilder()
                    .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
                    .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
                    .build())
            .build();

    InvalidCertificatesConfigException e =
        assertThrows(
            InvalidCertificatesConfigException.class,
            () -> CertificatesConfigMapper.toDomain(cert));
    assertThat(e).hasMessageThat().contains("SelfSignedCertificate is missing epoch_id");
  }

  @Test
  public void toDomain_selfSignedExplicitEpochIdZero_succeeds() throws Exception {
    com.google.mbs.v1.SelfSignedCertificate cert =
        com.google.mbs.v1.SelfSignedCertificate.newBuilder()
            .setEpochId(0)
            .setValidityPeriod(
                com.google.mbs.v1.ValidityPeriod.newBuilder()
                    .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
                    .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
                    .build())
            .build();

    SelfSignedCertificate domain = CertificatesConfigMapper.toDomain(cert);
    assertThat(domain.epochId()).isEqualTo(0);
  }

  @Test
  public void toDomain_crossSignedMissingPrivateKeyEpochId_throwsException() {
    com.google.mbs.v1.CrossSignedCertificate cert =
        com.google.mbs.v1.CrossSignedCertificate.newBuilder()
            .setPublicKeyEpochId(1)
            .setValidityPeriod(
                com.google.mbs.v1.ValidityPeriod.newBuilder()
                    .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
                    .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
                    .build())
            .build();

    InvalidCertificatesConfigException e =
        assertThrows(
            InvalidCertificatesConfigException.class,
            () -> CertificatesConfigMapper.toDomain(cert));
    assertThat(e)
        .hasMessageThat()
        .contains("CrossSignedCertificate is missing private_key_epoch_id");
  }

  @Test
  public void toDomain_crossSignedMissingPublicKeyEpochId_throwsException() {
    com.google.mbs.v1.CrossSignedCertificate cert =
        com.google.mbs.v1.CrossSignedCertificate.newBuilder()
            .setPrivateKeyEpochId(1)
            .setValidityPeriod(
                com.google.mbs.v1.ValidityPeriod.newBuilder()
                    .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
                    .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
                    .build())
            .build();

    InvalidCertificatesConfigException e =
        assertThrows(
            InvalidCertificatesConfigException.class,
            () -> CertificatesConfigMapper.toDomain(cert));
    assertThat(e)
        .hasMessageThat()
        .contains("CrossSignedCertificate is missing public_key_epoch_id");
  }

  @Test
  public void toDomain_crossSignedExplicitEpochIdZero_succeeds() throws Exception {
    com.google.mbs.v1.CrossSignedCertificate cert =
        com.google.mbs.v1.CrossSignedCertificate.newBuilder()
            .setPrivateKeyEpochId(0)
            .setPublicKeyEpochId(1)
            .setValidityPeriod(
                com.google.mbs.v1.ValidityPeriod.newBuilder()
                    .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
                    .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
                    .build())
            .build();

    CrossSignedCertificate domain = CertificatesConfigMapper.toDomain(cert);
    assertThat(domain.privateKeyEpochId()).isEqualTo(0);
    assertThat(domain.publicKeyEpochId()).isEqualTo(1);
  }

  @Test
  public void toDomain_timestampSecondsOutOfBounds_throwsException() {
    com.google.mbs.v1.ValidityPeriod tooLow =
        com.google.mbs.v1.ValidityPeriod.newBuilder()
            .setNotBefore(Timestamp.newBuilder().setSeconds(-62135596801L).build())
            .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class, () -> CertificatesConfigMapper.toDomain(tooLow));

    com.google.mbs.v1.ValidityPeriod tooHigh =
        com.google.mbs.v1.ValidityPeriod.newBuilder()
            .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
            .setNotAfter(Timestamp.newBuilder().setSeconds(253402300800L).build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class, () -> CertificatesConfigMapper.toDomain(tooHigh));
  }

  @Test
  public void toDomain_crossSignedSamePrivateKeyAndPublicKeyEpochId_throwsException() {
    com.google.mbs.v1.CrossSignedCertificate cert =
        com.google.mbs.v1.CrossSignedCertificate.newBuilder()
            .setPrivateKeyEpochId(1)
            .setPublicKeyEpochId(1)
            .setValidityPeriod(
                com.google.mbs.v1.ValidityPeriod.newBuilder()
                    .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
                    .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
                    .build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class, () -> CertificatesConfigMapper.toDomain(cert));
  }

  @Test
  public void toDomain_crossSignedMapKeyMismatch_throwsException() {
    com.google.mbs.v1.ValidityPeriod vp =
        com.google.mbs.v1.ValidityPeriod.newBuilder()
            .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
            .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
            .build();
    com.google.mbs.v1.CertificatesConfig proto =
        com.google.mbs.v1.CertificatesConfig.newBuilder()
            .putSelfSignedCertificates(
                1,
                com.google.mbs.v1.SelfSignedCertificate.newBuilder()
                    .setEpochId(1)
                    .setValidityPeriod(vp)
                    .build())
            .putSelfSignedCertificates(
                2,
                com.google.mbs.v1.SelfSignedCertificate.newBuilder()
                    .setEpochId(2)
                    .setValidityPeriod(vp)
                    .build())
            .putCrossSignedCertificates(
                "1_2",
                com.google.mbs.v1.CrossSignedCertificate.newBuilder()
                    .setPrivateKeyEpochId(2)
                    .setPublicKeyEpochId(1)
                    .setValidityPeriod(vp)
                    .build())
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class, () -> CertificatesConfigMapper.toDomain(proto));
  }

  @Test
  public void
      toDomain_activeCrossSignedCertificateIdNotInCrossSignedCertificates_throwsException() {
    com.google.mbs.v1.ValidityPeriod vp =
        com.google.mbs.v1.ValidityPeriod.newBuilder()
            .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
            .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
            .build();
    com.google.mbs.v1.CertificatesConfig proto =
        com.google.mbs.v1.CertificatesConfig.newBuilder()
            .putSelfSignedCertificates(
                1,
                com.google.mbs.v1.SelfSignedCertificate.newBuilder()
                    .setEpochId(1)
                    .setValidityPeriod(vp)
                    .build())
            .putSelfSignedCertificates(
                2,
                com.google.mbs.v1.SelfSignedCertificate.newBuilder()
                    .setEpochId(2)
                    .setValidityPeriod(vp)
                    .build())
            .putCrossSignedCertificates(
                "1_2",
                com.google.mbs.v1.CrossSignedCertificate.newBuilder()
                    .setPrivateKeyEpochId(1)
                    .setPublicKeyEpochId(2)
                    .setValidityPeriod(vp)
                    .build())
            .addActiveSelfSignedCertificateIds(1)
            .addActiveCrossSignedCertificateIds("2_1")
            .build();

    assertThrows(
        InvalidCertificatesConfigException.class, () -> CertificatesConfigMapper.toDomain(proto));
  }

  @Test
  public void toDomain_emptyActiveSelfSignedCertificateIds_throwsException() {
    com.google.mbs.v1.ValidityPeriod vp =
        com.google.mbs.v1.ValidityPeriod.newBuilder()
            .setNotBefore(Timestamp.newBuilder().setSeconds(100).build())
            .setNotAfter(Timestamp.newBuilder().setSeconds(200).build())
            .build();
    com.google.mbs.v1.CertificatesConfig proto =
        com.google.mbs.v1.CertificatesConfig.newBuilder()
            .putSelfSignedCertificates(
                0,
                com.google.mbs.v1.SelfSignedCertificate.newBuilder()
                    .setEpochId(0)
                    .setValidityPeriod(vp)
                    .build())
            .build();

    InvalidCertificatesConfigException e =
        assertThrows(
            InvalidCertificatesConfigException.class,
            () -> CertificatesConfigMapper.toDomain(proto));
    assertThat(e).hasMessageThat().contains("activeSelfSignedCertificateIds must not be empty");
  }
}
