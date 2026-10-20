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

import com.google.auto.value.AutoBuilder;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public record CertificatesConfig(
    Map<Integer, SelfSignedCertificate> selfSignedCertificates,
    Map<CrossSignedCertificateId, CrossSignedCertificate> crossSignedCertificates,
    Set<Integer> activeSelfSignedCertificateIds,
    Set<CrossSignedCertificateId> activeCrossSignedCertificateIds,
    Set<Integer> acceptableSelfSignedCertificateIds) {

  public CertificatesConfig {
    selfSignedCertificates = Map.copyOf(selfSignedCertificates);
    crossSignedCertificates = Map.copyOf(crossSignedCertificates);
    activeSelfSignedCertificateIds = Set.copyOf(activeSelfSignedCertificateIds);
    activeCrossSignedCertificateIds = Set.copyOf(activeCrossSignedCertificateIds);
    acceptableSelfSignedCertificateIds = Set.copyOf(acceptableSelfSignedCertificateIds);

    selfSignedCertificates.forEach(
        (epochId, cert) -> {
          if (!epochId.equals(cert.epochId())) {
            throw new IllegalArgumentException(
                String.format(
                    "Map key (%d) does not match SelfSignedCertificate.epochId (%d)",
                    epochId, cert.epochId()));
          }
        });
    crossSignedCertificates.forEach(
        (certId, cert) -> {
          if (!certId.equals(cert.id())) {
            throw new IllegalArgumentException(
                String.format(
                    "Map key '%s' does not match CrossSignedCertificate.id '%s'",
                    certId, cert.id()));
          }
        });

    for (CrossSignedCertificate crossCert : crossSignedCertificates.values()) {
      SelfSignedCertificate signingCert = selfSignedCertificates.get(crossCert.privateKeyEpochId());
      if (signingCert == null) {
        throw new IllegalArgumentException(
            String.format(
                "CrossSignedCertificate (%s) references private key epoch %d not present in"
                    + " selfSignedCertificates",
                crossCert.certificateId(), crossCert.privateKeyEpochId()));
      }
      SelfSignedCertificate publicCert = selfSignedCertificates.get(crossCert.publicKeyEpochId());
      if (publicCert == null) {
        throw new IllegalArgumentException(
            String.format(
                "CrossSignedCertificate (%s) references public key epoch %d not present in"
                    + " selfSignedCertificates",
                crossCert.certificateId(), crossCert.publicKeyEpochId()));
      }
    }

    if (activeSelfSignedCertificateIds.isEmpty()) {
      throw new IllegalArgumentException("activeSelfSignedCertificateIds must not be empty");
    }

    validateKeysExist(
        activeSelfSignedCertificateIds,
        selfSignedCertificates,
        "activeSelfSignedCertificateIds",
        "key",
        "selfSignedCertificates");
    validateKeysExist(
        acceptableSelfSignedCertificateIds,
        selfSignedCertificates,
        "acceptableSelfSignedCertificateIds",
        "key",
        "selfSignedCertificates");
    validateKeysExist(
        activeCrossSignedCertificateIds,
        crossSignedCertificates,
        "activeCrossSignedCertificateIds",
        "certificate ID",
        "crossSignedCertificates");
  }

  /** Returns all configured {@link SelfSignedCertificate}s ordered by ascending epoch ID. */
  public List<SelfSignedCertificate> getSelfSignedCertificates() {
    return selfSignedCertificates.values().stream()
        .sorted(Comparator.comparingInt(SelfSignedCertificate::epochId))
        .toList();
  }

  /** Returns active {@link SelfSignedCertificate}s ordered by ascending epoch ID. */
  public List<SelfSignedCertificate> activeSelfSignedCertificates() {
    return activeSelfSignedCertificateIds.stream()
        .sorted()
        .map(selfSignedCertificates::get)
        .toList();
  }

  /**
   * Returns active {@link CrossSignedCertificate}s ordered by ascending {@link
   * CrossSignedCertificateId}.
   */
  public List<CrossSignedCertificate> activeCrossSignedCertificates() {
    return activeCrossSignedCertificateIds.stream()
        .sorted(
            Comparator.comparingInt(CrossSignedCertificateId::privateKeyEpochId)
                .thenComparingInt(CrossSignedCertificateId::publicKeyEpochId))
        .map(crossSignedCertificates::get)
        .toList();
  }

  public static Builder builder() {
    return new AutoBuilder_CertificatesConfig_Builder()
        .setSelfSignedCertificates(Map.of())
        .setCrossSignedCertificates(Map.of())
        .setActiveSelfSignedCertificateIds(Set.of())
        .setActiveCrossSignedCertificateIds(Set.of())
        .setAcceptableSelfSignedCertificateIds(Set.of());
  }

  /** Builder for {@link CertificatesConfig}. */
  @AutoBuilder
  public interface Builder {
    Builder setSelfSignedCertificates(Map<Integer, SelfSignedCertificate> selfSignedCertificates);

    Builder setCrossSignedCertificates(
        Map<CrossSignedCertificateId, CrossSignedCertificate> crossSignedCertificates);

    Builder setActiveSelfSignedCertificateIds(Set<Integer> activeSelfSignedCertificateIds);

    Builder setActiveCrossSignedCertificateIds(
        Set<CrossSignedCertificateId> activeCrossSignedCertificateIds);

    Builder setAcceptableSelfSignedCertificateIds(Set<Integer> acceptableSelfSignedCertificateIds);

    CertificatesConfig build();
  }

  private static <T> void validateKeysExist(
      Set<T> ids, Map<T, ?> inventory, String listName, String itemType, String inventoryName) {
    for (T id : ids) {
      if (!inventory.containsKey(id)) {
        String formattedId =
            (id instanceof CrossSignedCertificateId)
                ? "'" + ((CrossSignedCertificateId) id).toKeyString() + "'"
                : String.valueOf(id);
        throw new IllegalArgumentException(
            String.format(
                "%s contains %s %s not defined in %s",
                listName, itemType, formattedId, inventoryName));
      }
    }
  }
}
