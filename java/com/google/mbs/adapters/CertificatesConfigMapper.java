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
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertificate;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.InvalidCertificatesConfigException;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.ValidityPeriod;
import com.google.protobuf.TextFormat;
import com.google.protobuf.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Maps {@link com.google.mbs.v1.CertificatesConfig} protobuf messages to domain entities, enforcing
 * validation invariants.
 */
public final class CertificatesConfigMapper {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  // Protobuf Timestamp spec constraints: 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z
  private static final long MIN_TIMESTAMP_SECONDS = -62135596800L;
  private static final long MAX_TIMESTAMP_SECONDS = 253402300799L;

  private CertificatesConfigMapper() {}

  /**
   * Converts a {@link com.google.mbs.v1.CertificatesConfig} protobuf message to a domain {@link
   * CertificatesConfig} entity.
   *
   * @throws InvalidCertificatesConfigException if any field is missing, inconsistent, or invalid.
   */
  public static CertificatesConfig toDomain(com.google.mbs.v1.CertificatesConfig proto)
      throws InvalidCertificatesConfigException {
    Map<Integer, SelfSignedCertificate> selfSignedMap = new HashMap<>();
    for (Map.Entry<Integer, com.google.mbs.v1.SelfSignedCertificate> entry :
        proto.getSelfSignedCertificatesMap().entrySet()) {
      selfSignedMap.put(entry.getKey(), toDomain(entry.getValue()));
    }

    Map<CrossSignedCertificateId, CrossSignedCertificate> crossSignedMap = new HashMap<>();
    for (Map.Entry<String, com.google.mbs.v1.CrossSignedCertificate> entry :
        proto.getCrossSignedCertificatesMap().entrySet()) {
      CrossSignedCertificateId id = parseCrossSignedKey(entry.getKey());
      crossSignedMap.put(id, toDomain(entry.getValue()));
    }

    Set<CrossSignedCertificateId> activeCrossSignedIds = new LinkedHashSet<>();
    for (String keyStr : proto.getActiveCrossSignedCertificateIdsList()) {
      activeCrossSignedIds.add(parseCrossSignedKey(keyStr));
    }

    CertificatesConfig config;
    try {
      config =
          new CertificatesConfig(
              selfSignedMap,
              crossSignedMap,
              new LinkedHashSet<>(proto.getActiveSelfSignedCertificateIdsList()),
              activeCrossSignedIds,
              new LinkedHashSet<>(proto.getAcceptableSelfSignedCertificateIdsList()));
    } catch (IllegalArgumentException e) {
      throw new InvalidCertificatesConfigException(e.getMessage(), e);
    }

    logger.atFine().log(
        "Mapped CertificatesConfig with %d self-signed certs, %d cross-signed certs, %d active"
            + " self-signed, %d active cross-signed, %d acceptable self-signed",
        config.selfSignedCertificates().size(),
        config.crossSignedCertificates().size(),
        config.activeSelfSignedCertificateIds().size(),
        config.activeCrossSignedCertificateIds().size(),
        config.acceptableSelfSignedCertificateIds().size());

    return config;
  }

  /**
   * Converts a {@link com.google.mbs.v1.SelfSignedCertificate} protobuf message to a domain {@link
   * SelfSignedCertificate}.
   */
  static SelfSignedCertificate toDomain(com.google.mbs.v1.SelfSignedCertificate proto)
      throws InvalidCertificatesConfigException {
    if (!proto.hasEpochId()) {
      throw new InvalidCertificatesConfigException("SelfSignedCertificate is missing epoch_id");
    }
    if (!proto.hasValidityPeriod()) {
      throw new InvalidCertificatesConfigException(
          String.format(
              "SelfSignedCertificate epoch_id=%d is missing validity_period", proto.getEpochId()));
    }
    try {
      return new SelfSignedCertificate(proto.getEpochId(), toDomain(proto.getValidityPeriod()));
    } catch (IllegalArgumentException e) {
      throw new InvalidCertificatesConfigException(e.getMessage(), e);
    }
  }

  /**
   * Converts a {@link com.google.mbs.v1.CrossSignedCertificate} protobuf message to a domain {@link
   * CrossSignedCertificate}.
   */
  static CrossSignedCertificate toDomain(com.google.mbs.v1.CrossSignedCertificate proto)
      throws InvalidCertificatesConfigException {
    if (!proto.hasPrivateKeyEpochId()) {
      throw new InvalidCertificatesConfigException(
          "CrossSignedCertificate is missing private_key_epoch_id");
    }
    if (!proto.hasPublicKeyEpochId()) {
      throw new InvalidCertificatesConfigException(
          "CrossSignedCertificate is missing public_key_epoch_id");
    }
    if (!proto.hasValidityPeriod()) {
      throw new InvalidCertificatesConfigException(
          String.format(
              "CrossSignedCertificate (%d_%d) is missing validity_period",
              proto.getPrivateKeyEpochId(), proto.getPublicKeyEpochId()));
    }
    try {
      return new CrossSignedCertificate(
          proto.getPrivateKeyEpochId(),
          proto.getPublicKeyEpochId(),
          toDomain(proto.getValidityPeriod()));
    } catch (IllegalArgumentException e) {
      throw new InvalidCertificatesConfigException(e.getMessage(), e);
    }
  }

  /**
   * Converts a {@link com.google.mbs.v1.ValidityPeriod} protobuf message to a domain {@link
   * ValidityPeriod}.
   */
  static ValidityPeriod toDomain(com.google.mbs.v1.ValidityPeriod proto)
      throws InvalidCertificatesConfigException {
    if (!proto.hasNotBefore() || !proto.hasNotAfter()) {
      throw new InvalidCertificatesConfigException(
          "ValidityPeriod must have both not_before and not_after specified");
    }
    Instant notBefore = toInstant(proto.getNotBefore());
    Instant notAfter = toInstant(proto.getNotAfter());
    try {
      return new ValidityPeriod(notBefore, notAfter);
    } catch (IllegalArgumentException e) {
      throw new InvalidCertificatesConfigException("Invalid validity period: " + e.getMessage(), e);
    }
  }

  /**
   * Parses a textproto representation of {@link com.google.mbs.v1.CertificatesConfig} and maps it
   * to the domain object.
   */
  public static CertificatesConfig fromTextProto(String textProto)
      throws InvalidCertificatesConfigException {
    com.google.mbs.v1.CertificatesConfig.Builder builder =
        com.google.mbs.v1.CertificatesConfig.newBuilder();
    try {
      TextFormat.getParser().merge(textProto, builder);
    } catch (TextFormat.ParseException e) {
      throw new InvalidCertificatesConfigException(
          "Failed to parse CertificatesConfig textproto: " + e.getMessage(), e);
    }
    return toDomain(builder.build());
  }

  private static Instant toInstant(Timestamp timestamp) throws InvalidCertificatesConfigException {
    if (timestamp.getSeconds() < MIN_TIMESTAMP_SECONDS
        || timestamp.getSeconds() > MAX_TIMESTAMP_SECONDS) {
      throw new InvalidCertificatesConfigException(
          String.format(
              "Timestamp seconds must be in [%d, %d], got %d",
              MIN_TIMESTAMP_SECONDS, MAX_TIMESTAMP_SECONDS, timestamp.getSeconds()));
    }
    // RFC 5280 Section 4.1.2.5 mandates whole-second resolution for X.509 validity periods.
    if (timestamp.getNanos() != 0) {
      throw new InvalidCertificatesConfigException(
          String.format(
              "Timestamp nanos must be 0 for X.509 validity periods, got %d",
              timestamp.getNanos()));
    }
    return Instant.ofEpochSecond(timestamp.getSeconds());
  }

  private static CrossSignedCertificateId parseCrossSignedKey(String keyStr)
      throws InvalidCertificatesConfigException {
    try {
      return CrossSignedCertificateId.fromKeyString(keyStr);
    } catch (IllegalArgumentException e) {
      throw new InvalidCertificatesConfigException(e.getMessage(), e);
    }
  }
}
