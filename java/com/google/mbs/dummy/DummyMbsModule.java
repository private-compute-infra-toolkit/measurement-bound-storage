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

package com.google.mbs.dummy;

import com.google.inject.AbstractModule;
import com.google.mbs.adapters.MeasurementBoundCertificateMonitor;
import com.google.mbs.domain.CertificateMonitor;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.MeasurementBoundCertificateGenerator;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.TrustPackageProvider;
import com.google.mbs.domain.TrustPackageReloader;
import jakarta.inject.Singleton;

/** Guice module for in-memory, self-signed Measurement Bound Storage used in local mode testing. */
public final class DummyMbsModule extends AbstractModule {

  @Override
  protected void configure() {
    bind(DummyTrustPackageProvider.class).in(Singleton.class);
    bind(TrustPackageProvider.class).to(DummyTrustPackageProvider.class);
    bind(TrustPackageReloader.class).to(DummyTrustPackageProvider.class);
    bind(MeasurementBoundCertificateGenerator.class).to(DummyTrustPackageProvider.class);
    bind(CertificatesConfigProvider.class).to(DummyTrustPackageProvider.class);

    bind(Metrics.class).to(NoOpMetrics.class).in(Singleton.class);

    bind(CertificateMonitor.class).to(MeasurementBoundCertificateMonitor.class).in(Singleton.class);
  }
}
