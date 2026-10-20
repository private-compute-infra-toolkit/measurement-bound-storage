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

package com.google.mbs.testing;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class CertificateTestHelper {
  private CertificateTestHelper() {}

  public static X509Certificate parseCertificate(byte[] certBytes) throws GeneralSecurityException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
  }
}
