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

import com.google.mbs.domain.CertificateCodec;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public final class PemCertificateCodec implements CertificateCodec {

  private static final String CERTIFICATE_TYPE = "X.509";

  @Inject
  public PemCertificateCodec() {}

  @Override
  public byte[] toBytes(X509Certificate certificate) {
    StringWriter stringWriter = new StringWriter();
    try (PemWriter pemWriter = new PemWriter(stringWriter)) {
      pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
    } catch (CertificateEncodingException e) {
      throw new IllegalArgumentException("Failed to encode certificate", e);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return stringWriter.toString().getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public X509Certificate toCertificate(byte[] certBytes) {
    CertificateFactory x509CertFactory;
    try {
      x509CertFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
    } catch (CertificateException e) {
      throw new IllegalStateException("Failed to initialize X.509 CertificateFactory", e);
    }
    try {
      return (X509Certificate)
          x509CertFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    } catch (CertificateException e) {
      throw new IllegalArgumentException("Failed to parse X.509 certificate", e);
    }
  }
}
