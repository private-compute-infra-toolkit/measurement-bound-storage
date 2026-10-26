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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.CertificateGenerator;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.InvalidCertificatesConfigException;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.TrustPackageReloader;
import com.google.mbs.domain.ValidityPeriod;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(JUnit4.class)
public class ScheduledCertificateMonitorTest {

  private static final CertificatesConfig CONFIG =
      new CertificatesConfig(
          Map.of(
              0,
              new SelfSignedCertificate(
                  0,
                  new ValidityPeriod(
                      Instant.parse("1930-01-01T00:00:00Z"),
                      Instant.parse("1930-02-01T00:00:00Z")))),
          Map.of(),
          Set.of(0),
          Set.of(),
          Set.of(0));

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  @Mock private CertificateGenerator mockGenerator;
  @Mock private TrustPackageReloader mockReloader;
  @Mock private CertificatesConfigProvider mockConfigProvider;
  @Mock private Metrics mockMetrics;

  private ScheduledCertificateMonitor service;

  @Before
  public void setUp() throws Exception {
    when(mockConfigProvider.getCertificatesConfig()).thenReturn(CONFIG);
    service =
        new ScheduledCertificateMonitor(
            mockGenerator, mockReloader, mockConfigProvider, mockMetrics);
  }

  @After
  public void tearDown() {
    if (service != null && service.isRunning()) {
      service.stop();
      service.awaitTerminated();
    }
  }

  @Test
  public void runOneIteration_delegatesToGeneratorThenReloader() throws Exception {
    service.runOneIteration();

    InOrder inOrder = inOrder(mockConfigProvider, mockGenerator, mockReloader, mockMetrics);
    inOrder.verify(mockConfigProvider).getCertificatesConfig();
    inOrder.verify(mockGenerator).generateCertificates(same(CONFIG));
    inOrder.verify(mockReloader).reload(same(CONFIG));
    inOrder.verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void runOneIteration_whenConfigFetchFails_skipsGenerationAndReloadAndRecordsFailure()
      throws Exception {
    when(mockConfigProvider.getCertificatesConfig())
        .thenThrow(new InvalidCertificatesConfigException("Simulated config fetch failure"));

    service.runOneIteration();

    verify(mockGenerator, never()).generateCertificates(any());
    verify(mockReloader, never()).reload(any());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.FAILURE);
  }

  @Test
  public void
      runOneIteration_whenGeneratorThrowsException_stillDelegatesToReloaderAndRecordsFailure() {
    doThrow(new RuntimeException("Simulated generation failure"))
        .when(mockGenerator)
        .generateCertificates(any());

    service.runOneIteration();

    InOrder inOrder = inOrder(mockGenerator, mockReloader, mockMetrics);
    inOrder.verify(mockGenerator).generateCertificates(same(CONFIG));
    inOrder.verify(mockReloader).reload(same(CONFIG));
    inOrder.verify(mockMetrics).recordEvent(Metrics.MbsEvent.FAILURE);
  }

  @Test
  public void runOneIteration_whenReloaderThrowsException_swallowsExceptionAndRecordsFailure() {
    doThrow(new RuntimeException("Simulated KMS failure")).when(mockReloader).reload(any());

    service.runOneIteration();

    verify(mockGenerator).generateCertificates(same(CONFIG));
    verify(mockReloader).reload(same(CONFIG));
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.FAILURE);
  }

  @Test
  public void scheduler_returnsNonNullSchedule() {
    assertNotNull(service.scheduler());
  }

  @Test
  public void serviceName_returnsConfiguredThreadName() {
    assertEquals("mbs-certificate-monitor", service.serviceName());
  }

  @Test
  public void startAndStop_managesServiceLifecycle() {
    assertFalse(service.isRunning());

    service.start();
    service.awaitRunning();
    assertTrue(service.isRunning());
    verify(mockGenerator, timeout(5000)).generateCertificates(any());
    verify(mockReloader, timeout(5000)).reload(any());

    service.stop();
    service.awaitTerminated();
    assertFalse(service.isRunning());
  }
}
