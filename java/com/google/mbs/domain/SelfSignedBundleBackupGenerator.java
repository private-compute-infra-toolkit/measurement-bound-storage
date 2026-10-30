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

import com.google.mbs.qualifier.AttestationUserData;
import jakarta.inject.Inject;
import java.util.Objects;

class SelfSignedBundleBackupGenerator {

  private final SelfSignedCertificateFactory certificateFactory;
  private final AttestationCollector attestationCollector;
  private final byte[] userDataBoundToAttestation;
  private final SelfSignedBundleBackupSealer backupSealer;

  @Inject
  SelfSignedBundleBackupGenerator(
      SelfSignedCertificateFactory certificateFactory,
      AttestationCollector attestationCollector,
      @AttestationUserData byte[] userDataBoundToAttestation,
      SelfSignedBundleBackupSealer backupSealer) {
    this.certificateFactory = Objects.requireNonNull(certificateFactory);
    this.attestationCollector = Objects.requireNonNull(attestationCollector);
    this.userDataBoundToAttestation = Objects.requireNonNull(userDataBoundToAttestation);
    this.backupSealer = Objects.requireNonNull(backupSealer);
  }

  SelfSignedBundleBackup generate(SelfSignedCertificate certConfig) throws KmsException {
    SelfSignedCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        certificateFactory.generate(certConfig);
    AttestationToken token =
        attestationCollector.collectBoundToPubkey(
            certAndKey.certificate().getPublicKey(), userDataBoundToAttestation);
    return backupSealer.seal(
        new SelfSignedBundle(certAndKey.certificate(), certAndKey.privateKey(), token));
  }
}
