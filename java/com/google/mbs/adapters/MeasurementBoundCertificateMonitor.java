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

import static com.google.mbs.domain.Metrics.ReloadStatus.FAILURE;
import static com.google.mbs.domain.Metrics.ReloadStatus.SUCCESS;

import com.google.common.flogger.FluentLogger;
import com.google.common.util.concurrent.AbstractScheduledService;
import com.google.mbs.domain.CertificateMonitor;
import com.google.mbs.domain.MeasurementBoundCertificateReloader;
import com.google.mbs.domain.Metrics;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;

/**
 * Background monitor that periodically checks and reloads the root measurement-bound certificate.
 */
@Singleton
public class MeasurementBoundCertificateMonitor extends AbstractScheduledService
    implements CertificateMonitor {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final Duration RELOAD_INTERVAL = Duration.ofMinutes(10);

  private final MeasurementBoundCertificateReloader reloader;
  private final Metrics metrics;

  @Inject
  public MeasurementBoundCertificateMonitor(
      MeasurementBoundCertificateReloader reloader, Metrics metrics) {
    this.reloader = reloader;
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

  @Override
  protected void runOneIteration() {
    try {
      reloader.reloadCertificate();
      metrics.setReloadStatus(SUCCESS);
      logger.atInfo().log("Successfully reloaded root measurement-bound certificate");
    } catch (Exception e) {
      // Clear interrupted status so the worker thread is not poisoned for subsequent scheduled
      // runs.
      Thread.interrupted();
      metrics.setReloadStatus(FAILURE);
      // Prevent transient storage or network errors from terminating future scheduled runs.
      logger.atSevere().withCause(e).log("Failed to reload root measurement-bound certificate");
    }
  }

  @Override
  protected String serviceName() {
    return "mbs-certificate-reloader";
  }

  @Override
  protected Scheduler scheduler() {
    // Run immediately on service start, then periodically every 10 minutes.
    return Scheduler.newFixedRateSchedule(Duration.ZERO, RELOAD_INTERVAL);
  }
}
