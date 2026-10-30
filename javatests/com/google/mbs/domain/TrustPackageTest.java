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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class TrustPackageTest {

  private static SelfSignedBundle createBundle() {
    return new SelfSignedBundle(
        mock(X509Certificate.class),
        mock(PrivateKey.class),
        AttestationToken.fromBytes(new byte[0]));
  }

  @Test
  public void constructor_storesSelfSignedBundlesAndCrossCertificates() {
    SelfSignedBundle bundle = createBundle();
    X509Certificate x509 = mock(X509Certificate.class);

    TrustPackage result = new TrustPackage(List.of(bundle), List.of(x509));

    assertEquals(1, result.selfSignedBundles().size());
    assertEquals(bundle, result.selfSignedBundles().get(0));
    assertEquals(1, result.crossSignedCertificates().size());
    assertEquals(x509, result.crossSignedCertificates().get(0));
  }

  @Test
  public void constructor_makesDefensiveUnmodifiableCopies() {
    SelfSignedBundle bundle = createBundle();
    X509Certificate x509 = mock(X509Certificate.class);
    List<SelfSignedBundle> mutableBundles = new ArrayList<>(List.of(bundle));
    List<X509Certificate> mutableCerts = new ArrayList<>(List.of(x509));

    TrustPackage result = new TrustPackage(mutableBundles, mutableCerts);
    mutableBundles.clear();
    mutableCerts.clear();

    assertEquals(1, result.selfSignedBundles().size());
    assertEquals(1, result.crossSignedCertificates().size());
    assertThrows(UnsupportedOperationException.class, () -> result.selfSignedBundles().add(bundle));
    assertThrows(
        UnsupportedOperationException.class, () -> result.crossSignedCertificates().add(x509));
  }
}
