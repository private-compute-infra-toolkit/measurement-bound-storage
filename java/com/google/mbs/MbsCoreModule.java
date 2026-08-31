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

import com.google.inject.AbstractModule;
import com.google.inject.Key;
import com.google.inject.Provides;
import com.google.kmsclient.KmsClientInterface;
import com.google.mbs.adapters.S3KeyBackupStorage;
import com.google.mbs.attestationcollection.AttestationCollector;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.KmsKeyArn;
import com.google.mbs.qualifier.MbsRoot;
import com.google.mbs.qualifier.PrivateBackupBucket;
import com.google.mbs.qualifier.PublicBackupBucket;
import jakarta.inject.Singleton;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import software.amazon.awssdk.services.s3.S3Client;

/** Guice core module configuring MBS certificate provider and storage port. */
final class MbsCoreModule extends AbstractModule {

  @Override
  protected void configure() {
    requireBinding(KmsClientInterface.class);
    requireBinding(AttestationCollector.class);
    requireBinding(S3Client.class);
    requireBinding(Key.get(String.class, PublicBackupBucket.class));
    requireBinding(Key.get(String.class, PrivateBackupBucket.class));
    requireBinding(Key.get(String.class, KmsKeyArn.class));
    requireBinding(Key.get(byte[].class, AttestationUserData.class));
    requireBinding(MbsCertificateFactory.class);
    requireBinding(Metrics.class);

    bind(KeyBackupStorage.class).to(S3KeyBackupStorage.class).in(Singleton.class);

    bind(MeasurementBoundCertificateProvider.class)
        .to(KmsMeasurementBoundCertificateProvider.class)
        .in(Singleton.class);
  }

  @Provides
  @Singleton
  KeyBackupBucketProperties provideKeyBackupBucketProperties(
      @PublicBackupBucket String publicBucketName, @PrivateBackupBucket String privateBucketName) {
    return new KeyBackupBucketPropertiesFactory(publicBucketName, privateBucketName).create();
  }

  @Provides
  @Singleton
  MeasurementBoundCertificate provideMeasurementBoundCertificate(
      MeasurementBoundCertificateProvider provider) {
    return provider.loadOrGenerateCertificate();
  }

  @Provides
  @Singleton
  @MbsRoot
  X509Certificate provideRootCertificate(MeasurementBoundCertificate cert) {
    return cert.getCertificate();
  }

  @Provides
  @Singleton
  @MbsRoot
  PrivateKey provideRootPrivateKey(MeasurementBoundCertificate cert) {
    return cert.getPrivateKey();
  }
}
