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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.InvalidCertificatesConfigException;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.ValidityPeriod;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(JUnit4.class)
public class DefaultingCertificatesConfigProviderTest {

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  @Mock private CertificatesConfigProvider mockDelegate;

  private DefaultingCertificatesConfigProvider provider;

  @Before
  public void setUp() {
    provider = new DefaultingCertificatesConfigProvider(mockDelegate);
  }

  @Test
  public void getCertificatesConfig_delegateSucceeds_returnsDelegateConfig() throws Exception {
    CertificatesConfig expected =
        new CertificatesConfig(
            Map.of(
                1,
                new SelfSignedCertificate(
                    1,
                    new ValidityPeriod(
                        Instant.parse("1930-01-01T00:00:00Z"),
                        Instant.parse("1930-02-01T00:00:00Z")))),
            Map.of(),
            Set.of(1),
            Set.of(),
            Set.of(1));
    when(mockDelegate.getCertificatesConfig()).thenReturn(expected);

    CertificatesConfig result = provider.getCertificatesConfig();

    assertSame(expected, result);
  }

  @Test
  public void getCertificatesConfig_delegateThrowsCheckedException_returnsDefaultConfig()
      throws Exception {
    when(mockDelegate.getCertificatesConfig())
        .thenThrow(new InvalidCertificatesConfigException("Config missing"));

    CertificatesConfig result = provider.getCertificatesConfig();

    assertEquals(DefaultingCertificatesConfigProvider.DEFAULT_CONFIG, result);
    assertTrue(result.selfSignedCertificates().containsKey(0));
    assertTrue(result.activeSelfSignedCertificateIds().contains(0));
  }

  @Test
  public void getCertificatesConfig_delegateThrowsRuntimeException_returnsDefaultConfig()
      throws Exception {
    when(mockDelegate.getCertificatesConfig()).thenThrow(new RuntimeException("Unexpected error"));

    CertificatesConfig result = provider.getCertificatesConfig();

    assertEquals(DefaultingCertificatesConfigProvider.DEFAULT_CONFIG, result);
    assertTrue(result.selfSignedCertificates().containsKey(0));
    assertTrue(result.activeSelfSignedCertificateIds().contains(0));
  }
}
