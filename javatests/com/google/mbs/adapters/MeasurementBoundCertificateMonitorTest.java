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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import com.google.mbs.domain.MeasurementBoundCertificateReloader;
import com.google.mbs.domain.Metrics;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(JUnit4.class)
public class MeasurementBoundCertificateMonitorTest {

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  @Mock private MeasurementBoundCertificateReloader mockReloader;
  @Mock private Metrics mockMetrics;

  private MeasurementBoundCertificateMonitor service;

  @Before
  public void setUp() {
    service = new MeasurementBoundCertificateMonitor(mockReloader, mockMetrics);
  }

  @After
  public void tearDown() {
    if (service != null && service.isRunning()) {
      service.stop();
      service.awaitTerminated();
    }
  }

  @Test
  public void runOneIteration_delegatesToCertificateReloaderAndSetsReloadSuccess() {
    service.runOneIteration();

    verify(mockReloader).reloadCertificate();
    verify(mockMetrics).setReloadStatus(SUCCESS);
  }

  @Test
  public void runOneIteration_whenReloaderThrowsException_setsReloadFailureAndSwallowsException() {
    doThrow(new RuntimeException("Simulated KMS failure")).when(mockReloader).reloadCertificate();

    service.runOneIteration();

    verify(mockReloader).reloadCertificate();
    verify(mockMetrics).setReloadStatus(FAILURE);
  }

  @Test
  public void scheduler_returnsNonNullSchedule() {
    assertNotNull(service.scheduler());
  }

  @Test
  public void serviceName_returnsConfiguredThreadName() {
    assertEquals("mbs-certificate-reloader", service.serviceName());
  }

  @Test
  public void startAndStop_managesServiceLifecycle() {
    assertFalse(service.isRunning());

    service.start();
    service.awaitRunning();
    assertTrue(service.isRunning());
    verify(mockReloader, timeout(5000)).reloadCertificate();

    service.stop();
    service.awaitTerminated();
    assertFalse(service.isRunning());
  }
}
