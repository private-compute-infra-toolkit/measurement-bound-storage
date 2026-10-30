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

package com.google.mbs.dummy;

import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.Metrics;
import java.util.Set;

/** A no-op implementation of {@link Metrics}. */
public final class NoOpMetrics implements Metrics {
  @Override
  public void recordEvent(MbsEvent event) {}

  @Override
  public void recordGenerationEvent(GenerationEvent event) {}

  @Override
  public void recordLoadEvent(LoadEvent event) {}

  @Override
  public void recordConfigEvent(ConfigEvent event) {}

  @Override
  public void recordActiveSelfSignedCertificates(Set<Integer> epochIds) {}

  @Override
  public void recordActiveCrossSignedCertificates(Set<CrossSignedCertificateId> certificateIds) {}
}
