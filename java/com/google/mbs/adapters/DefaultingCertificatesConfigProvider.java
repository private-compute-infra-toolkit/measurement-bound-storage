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
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.ValidityPeriod;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/**
 * Decorates a {@link CertificatesConfigProvider}, falling back to a hardcoded epoch-0 config when
 * the config cannot be obtained.
 *
 * <p>TODO: temporary workaround - remove (and bind {@link S3CertificatesConfigProvider} directly in
 * {@code MbsCoreModule}) once certificates_config.textproto is deployed in all environments.
 */
public class DefaultingCertificatesConfigProvider implements CertificatesConfigProvider {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  @VisibleForTesting
  static final CertificatesConfig DEFAULT_CONFIG =
      new CertificatesConfig(
          Map.of(
              0,
              new SelfSignedCertificate(
                  0,
                  new ValidityPeriod(
                      Instant.parse("2026-10-01T00:00:00Z"),
                      Instant.parse("2027-02-02T13:00:00Z")))),
          Map.of(),
          Set.of(0),
          Set.of(),
          Set.of(0));

  private final CertificatesConfigProvider delegate;

  public DefaultingCertificatesConfigProvider(CertificatesConfigProvider delegate) {
    this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
  }

  @Override
  public @NonNull CertificatesConfig getCertificatesConfig() {
    try {
      return delegate.getCertificatesConfig();
    } catch (Exception e) {
      logger.atWarning().log(
          "Failed to get certificates config, using hardcoded default %s", DEFAULT_CONFIG);
      return DEFAULT_CONFIG;
    }
  }
}
