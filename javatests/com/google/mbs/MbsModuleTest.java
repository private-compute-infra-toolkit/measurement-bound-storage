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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.mbs.adapters.S3KeyBackupStorage;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.KmsKeyArn;
import com.google.mbs.qualifier.MbsRoot;
import com.google.mbs.qualifier.PrivateBackupBucket;
import com.google.mbs.qualifier.PublicBackupBucket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import software.amazon.awssdk.services.s3.S3Client;

@RunWith(JUnit4.class)
public class MbsModuleTest {

  @Test
  public void testDummyMbsModuleProvidesCertificates() {
    Injector injector = Guice.createInjector(new DummyMbsModule());

    MeasurementBoundCertificateProvider provider =
        injector.getInstance(MeasurementBoundCertificateProvider.class);
    assertNotNull(provider);
    assertTrue(provider instanceof DummyMeasurementBoundCertificateProvider);

    MeasurementBoundCertificate mbc = injector.getInstance(MeasurementBoundCertificate.class);
    assertNotNull(mbc);

    X509Certificate cert =
        injector.getInstance(com.google.inject.Key.get(X509Certificate.class, MbsRoot.class));
    assertNotNull(cert);

    PrivateKey privateKey =
        injector.getInstance(com.google.inject.Key.get(PrivateKey.class, MbsRoot.class));
    assertNotNull(privateKey);
  }

  @Test
  public void testKmsMbsModuleBindsProvider() {
    Injector injector =
        Guice.createInjector(
            new MbsModule("us-east-1"),
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(S3Client.class).toInstance(mock(S3Client.class));
                bind(String.class)
                    .annotatedWith(PublicBackupBucket.class)
                    .toInstance("test-public-bucket");
                bind(String.class)
                    .annotatedWith(PrivateBackupBucket.class)
                    .toInstance("test-private-bucket");
                bind(String.class)
                    .annotatedWith(KmsKeyArn.class)
                    .toInstance("arn:aws:kms:us-east-1:12345:key/abc");
                bind(byte[].class).annotatedWith(AttestationUserData.class).toInstance(new byte[0]);
                bind(MbsCertificateFactory.class).toInstance(mock(MbsCertificateFactory.class));
                bind(Metrics.class).toInstance(mock(Metrics.class));
              }
            });

    MeasurementBoundCertificateProvider provider =
        injector.getInstance(MeasurementBoundCertificateProvider.class);
    assertNotNull(provider);
    assertTrue(provider instanceof KmsMeasurementBoundCertificateProvider);

    KeyBackupBucketProperties bucketProps = injector.getInstance(KeyBackupBucketProperties.class);
    assertNotNull(bucketProps);
    assertEquals("test-public-bucket", bucketProps.getPublicBucketName());
    assertEquals("test-private-bucket", bucketProps.getPrivateBucketName());

    KeyBackupStorage storage1 = injector.getInstance(KeyBackupStorage.class);
    KeyBackupStorage storage2 = injector.getInstance(KeyBackupStorage.class);
    assertNotNull(storage1);
    assertSame(storage1, storage2);
    assertTrue(storage1 instanceof S3KeyBackupStorage);
  }
}
