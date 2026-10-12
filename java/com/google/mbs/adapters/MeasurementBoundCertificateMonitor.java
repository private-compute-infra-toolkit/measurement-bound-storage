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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.flogger.FluentLogger;
import com.google.common.util.concurrent.AbstractScheduledService;
import com.google.mbs.domain.CertificateMonitor;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.MeasurementBoundCertificateGenerator;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.TrustPackageReloader;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.Optional;

/**
 * Background monitor that periodically checks and reloads the root measurement-bound certificate.
 */
@Singleton
public class MeasurementBoundCertificateMonitor extends AbstractScheduledService
    implements CertificateMonitor {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final Duration RELOAD_INTERVAL = Duration.ofMinutes(2);

  private final MeasurementBoundCertificateGenerator generator;
  private final TrustPackageReloader reloader;
  private final CertificatesConfigProvider certificatesConfigProvider;
  private final Metrics metrics;

  @Inject
  public MeasurementBoundCertificateMonitor(
      MeasurementBoundCertificateGenerator generator,
      TrustPackageReloader reloader,
      CertificatesConfigProvider certificatesConfigProvider,
      Metrics metrics) {
    this.generator = generator;
    this.reloader = reloader;
    this.certificatesConfigProvider = certificatesConfigProvider;
    this.metrics = metrics;
  }

  @Override
  public void start() {
    startAsync();
  }

  @Override
  public void stop() {
    stopAsync();
  }

  @VisibleForTesting
  @Override
  public void runOneIteration() {
    Optional<CertificatesConfig> config = fetchConfig();
    boolean generationSucceeded = config.isPresent() && generate(config.get());
    // TODO: make reload depend on config, execute only when fetched
    boolean reloadSucceeded = reload();

    Metrics.MbsEvent result =
        generationSucceeded && reloadSucceeded
            ? Metrics.MbsEvent.SUCCESS
            : Metrics.MbsEvent.FAILURE;
    metrics.recordEvent(result);
    (result == Metrics.MbsEvent.SUCCESS ? logger.atFine() : logger.atSevere())
        .log("Measurement-bound certificate monitor iteration finished with %s", result);
  }

  private Optional<CertificatesConfig> fetchConfig() {
    try {
      return Optional.of(certificatesConfigProvider.getCertificatesConfig());
    } catch (Exception e) {
      logger.atSevere().withCause(e).log("Failed to fetch certificates config");
      return Optional.empty();
    }
  }

  private boolean generate(CertificatesConfig config) {
    try {
      generator.generateCertificates(config);
      return true;
    } catch (Exception e) {
      Thread.interrupted();
      logger.atSevere().withCause(e).log("Failed to generate root measurement-bound certificate");
      return false;
    }
  }

  private boolean reload() {
    try {
      reloader.reload();
      return true;
    } catch (Exception e) {
      Thread.interrupted();
      logger.atSevere().withCause(e).log("Failed to reload root measurement-bound certificate");
      return false;
    }
  }

  @Override
  protected String serviceName() {
    return "mbs-certificate-monitor";
  }

  @Override
  protected Scheduler scheduler() {
    // Run immediately on service start, then periodically every RELOAD_INTERVAL.
    return Scheduler.newFixedRateSchedule(Duration.ZERO, RELOAD_INTERVAL);
  }
}
