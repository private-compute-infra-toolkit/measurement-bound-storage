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

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

public record CertificatesConfig(
    @NonNull Map<Integer, SelfSignedCertificate> selfSignedCertificates,
    @NonNull Map<CrossSignedCertificateId, CrossSignedCertificate> crossSignedCertificates,
    @NonNull Set<Integer> activeSelfSignedCertificateIds,
    @NonNull Set<CrossSignedCertificateId> activeCrossSignedCertificateIds,
    @NonNull Set<Integer> acceptableSelfSignedCertificateIds) {

  public CertificatesConfig {
    selfSignedCertificates =
        Map.copyOf(
            Objects.requireNonNull(
                selfSignedCertificates, "selfSignedCertificates must not be null"));
    crossSignedCertificates =
        Map.copyOf(
            Objects.requireNonNull(
                crossSignedCertificates, "crossSignedCertificates must not be null"));
    activeSelfSignedCertificateIds =
        Set.copyOf(
            Objects.requireNonNull(
                activeSelfSignedCertificateIds, "activeSelfSignedCertificateIds must not be null"));
    activeCrossSignedCertificateIds =
        Set.copyOf(
            Objects.requireNonNull(
                activeCrossSignedCertificateIds,
                "activeCrossSignedCertificateIds must not be null"));
    acceptableSelfSignedCertificateIds =
        Set.copyOf(
            Objects.requireNonNull(
                acceptableSelfSignedCertificateIds,
                "acceptableSelfSignedCertificateIds must not be null"));

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
