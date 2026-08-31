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

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.mbs.qualifier.MbsRoot;
import jakarta.inject.Singleton;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** Guice module for in-memory, self-signed Measurement Bound Storage used in local mode testing. */
public final class DummyMbsModule extends AbstractModule {

  @Override
  protected void configure() {
    bind(MeasurementBoundCertificateProvider.class)
        .to(DummyMeasurementBoundCertificateProvider.class)
        .in(Singleton.class);
  }

  @Provides
  @Singleton
  MeasurementBoundCertificate provideMeasurementBoundCertificate(
      MeasurementBoundCertificateProvider provider) {
    return provider.loadOrGenerateCertificate();
  }

  @Provides
  @Singleton
  @MbsRoot
  X509Certificate provideRootCertificate(MeasurementBoundCertificate cert) {
    return cert.getCertificate();
  }

  @Provides
  @Singleton
  @MbsRoot
  PrivateKey provideRootPrivateKey(MeasurementBoundCertificate cert) {
    return cert.getPrivateKey();
  }
}
