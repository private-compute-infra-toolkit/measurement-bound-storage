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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

import com.google.mbs.domain.MeasurementBoundCertificate;
import com.google.mbs.domain.TrustPackage;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class TrustPackageTest {

  @Test
  public void constructor_storesBundlesAndCrossCertificates() {
    MeasurementBoundCertificate mbc = mock(MeasurementBoundCertificate.class);
    X509Certificate x509 = mock(X509Certificate.class);

    TrustPackage result = new TrustPackage(List.of(mbc), List.of(x509));

    assertEquals(1, result.bundles().size());
    assertEquals(mbc, result.bundles().get(0));
    assertEquals(1, result.crossSignedCertificates().size());
    assertEquals(x509, result.crossSignedCertificates().get(0));
  }

  @Test
  public void constructor_nullBundles_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> new TrustPackage(null, List.of(mock(X509Certificate.class))));
  }

  @Test
  public void constructor_nullCrossSignedCertificates_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> new TrustPackage(List.of(mock(MeasurementBoundCertificate.class)), null));
  }
}
