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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.mbs.adapters.AwsAttestationCollector;
import com.google.mbs.adapters.AwsKmsClient;
import com.google.mbs.adapters.MeasurementBoundCertificateMonitor;
import com.google.mbs.adapters.S3KeyBackupStorage;
import com.google.mbs.adapters.nsm.DefaultNitroSecurityModuleFactory;
import com.google.mbs.adapters.nsm.NitroSecurityModuleFactory;
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.CertificateMonitor;
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.MeasurementBoundCertificate;
import com.google.mbs.domain.MeasurementBoundCertificateProvider;
import com.google.mbs.domain.MeasurementBoundCertificateReloader;
import com.google.mbs.domain.Metrics;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.InstanceId;
import com.google.mbs.qualifier.KmsKeyArn;
import com.google.mbs.qualifier.PrivateBackupBucket;
import com.google.mbs.qualifier.PublicBackupBucket;
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

    MeasurementBoundCertificateReloader reloader =
        injector.getInstance(MeasurementBoundCertificateReloader.class);
    assertNotNull(reloader);
    assertSame(provider, reloader);

    assertThrows(IllegalStateException.class, provider::getCertificate);

    reloader.reloadCertificate();
    MeasurementBoundCertificate mbc1 = provider.getCertificate();
    assertNotNull(mbc1);
    assertNotNull(mbc1.getCertificate());
    assertNotNull(mbc1.getPrivateKey());

    reloader.reloadCertificate();
    MeasurementBoundCertificate mbc2 = provider.getCertificate();
    assertNotNull(mbc2);
    assertNotNull(mbc2.getCertificate());
    assertNotNull(mbc2.getPrivateKey());
    assertNotEquals(
        mbc1.getCertificate().getSerialNumber(), mbc2.getCertificate().getSerialNumber());

    CertificateMonitor scheduler = injector.getInstance(CertificateMonitor.class);
    assertNotNull(scheduler);
    assertTrue(scheduler instanceof MeasurementBoundCertificateMonitor);
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
                bind(String.class)
                    .annotatedWith(InstanceId.class)
                    .toInstance("i-1234567890abcdef0");
                bind(byte[].class).annotatedWith(AttestationUserData.class).toInstance(new byte[0]);
                bind(MbsCertificateFactory.class).toInstance(mock(MbsCertificateFactory.class));
                bind(Metrics.class).toInstance(mock(Metrics.class));
              }
            });

    MeasurementBoundCertificateProvider provider =
        injector.getInstance(MeasurementBoundCertificateProvider.class);
    assertNotNull(provider);
    assertTrue(provider instanceof KmsMeasurementBoundCertificateProvider);

    MeasurementBoundCertificateReloader reloader =
        injector.getInstance(MeasurementBoundCertificateReloader.class);
    assertNotNull(reloader);
    assertSame(provider, reloader);

    KeyBackupBucketProperties bucketProps = injector.getInstance(KeyBackupBucketProperties.class);
    assertNotNull(bucketProps);
    assertEquals("test-public-bucket", bucketProps.getPublicBucketName());
    assertEquals("test-private-bucket", bucketProps.getPrivateBucketName());

    KeyBackupStorage storage1 = injector.getInstance(KeyBackupStorage.class);
    KeyBackupStorage storage2 = injector.getInstance(KeyBackupStorage.class);
    assertNotNull(storage1);
    assertSame(storage1, storage2);
    assertTrue(storage1 instanceof S3KeyBackupStorage);

    NitroSecurityModuleFactory nsmFactory = injector.getInstance(NitroSecurityModuleFactory.class);
    assertNotNull(nsmFactory);
    assertTrue(nsmFactory instanceof DefaultNitroSecurityModuleFactory);

    KmsClientInterface kmsClient = injector.getInstance(KmsClientInterface.class);
    assertNotNull(kmsClient);
    assertTrue(kmsClient instanceof AwsKmsClient);

    CertificateMonitor scheduler = injector.getInstance(CertificateMonitor.class);
    assertNotNull(scheduler);
    assertTrue(scheduler instanceof MeasurementBoundCertificateMonitor);
  }

  @Test
  public void testAwsMbsModuleBindsComponents() {
    Injector injector = Guice.createInjector(new AwsMbsModule("us-east-1"));

    NitroSecurityModuleFactory factory = injector.getInstance(NitroSecurityModuleFactory.class);
    assertNotNull(factory);
    assertTrue(factory instanceof DefaultNitroSecurityModuleFactory);

    KmsClientInterface kmsClient = injector.getInstance(KmsClientInterface.class);
    assertNotNull(kmsClient);
    assertTrue(kmsClient instanceof AwsKmsClient);

    AttestationCollector attestationCollector = injector.getInstance(AttestationCollector.class);
    assertNotNull(attestationCollector);
    assertTrue(attestationCollector instanceof AwsAttestationCollector);
  }
}
