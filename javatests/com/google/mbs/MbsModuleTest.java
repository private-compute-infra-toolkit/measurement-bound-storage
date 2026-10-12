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
import com.google.mbs.adapters.DefaultingCertificatesConfigProvider;
import com.google.mbs.adapters.MeasurementBoundCertificateMonitor;
import com.google.mbs.adapters.S3BackupPaths;
import com.google.mbs.adapters.S3KeyBackupStorage;
import com.google.mbs.adapters.nsm.DefaultNitroSecurityModuleFactory;
import com.google.mbs.adapters.nsm.NitroSecurityModuleFactory;
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.CertificateMonitor;
import com.google.mbs.domain.CertificatesConfigBucketProperties;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.KeyBackupBucketProperties;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.MeasurementBoundBundle;
import com.google.mbs.domain.MeasurementBoundCertificateGenerator;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.TrustPackage;
import com.google.mbs.domain.TrustPackageProvider;
import com.google.mbs.domain.TrustPackageReloader;
import com.google.mbs.dummy.DummyMbsModule;
import com.google.mbs.dummy.DummyTrustPackageProvider;
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
  public void testDummyMbsModuleProvidesCertificates() throws Exception {
    Injector injector = Guice.createInjector(new DummyMbsModule());

    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);
    assertNotNull(provider);
    assertTrue(provider instanceof DummyTrustPackageProvider);

    TrustPackageReloader reloader = injector.getInstance(TrustPackageReloader.class);
    assertNotNull(reloader);
    assertSame(provider, reloader);

    MeasurementBoundCertificateGenerator generator =
        injector.getInstance(MeasurementBoundCertificateGenerator.class);
    assertNotNull(generator);
    assertSame(provider, generator);

    CertificatesConfigProvider configProvider =
        injector.getInstance(CertificatesConfigProvider.class);
    assertNotNull(configProvider);
    assertSame(provider, configProvider);

    assertThrows(IllegalStateException.class, provider::getActiveTrustPackage);

    generator.generateCertificates(configProvider.getCertificatesConfig());
    reloader.reload();
    TrustPackage package1 = provider.getActiveTrustPackage();
    assertNotNull(package1);
    assertEquals(1, package1.bundles().size());
    assertTrue(package1.crossSignedCertificates().isEmpty());
    MeasurementBoundBundle mbc1 = package1.bundles().get(0);
    assertNotNull(mbc1.getCertificate());
    assertNotNull(mbc1.getPrivateKey());
    var expectedValidity =
        configProvider.getCertificatesConfig().selfSignedCertificates().get(0).validityPeriod();
    assertEquals(expectedValidity.notBefore(), mbc1.getCertificate().getNotBefore().toInstant());
    assertEquals(expectedValidity.notAfter(), mbc1.getCertificate().getNotAfter().toInstant());

    reloader.reload();
    TrustPackage package2 = provider.getActiveTrustPackage();
    assertNotNull(package2);
    assertEquals(1, package2.bundles().size());
    assertTrue(package2.crossSignedCertificates().isEmpty());
    MeasurementBoundBundle mbc2 = package2.bundles().get(0);
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

    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);
    assertNotNull(provider);
    assertTrue(provider instanceof KmsMeasurementBoundCertificateProvider);

    TrustPackageReloader reloader = injector.getInstance(TrustPackageReloader.class);
    assertNotNull(reloader);
    assertSame(provider, reloader);

    MeasurementBoundCertificateGenerator generator =
        injector.getInstance(MeasurementBoundCertificateGenerator.class);
    assertNotNull(generator);
    assertTrue(generator instanceof KmsMeasurementBoundCertificateGenerator);

    KeyBackupBucketProperties bucketProps = injector.getInstance(KeyBackupBucketProperties.class);
    assertNotNull(bucketProps);
    assertEquals("test-public-bucket", bucketProps.getPublicBucketName());
    assertEquals("test-private-bucket", bucketProps.getPrivateBucketName());

    CertificatesConfigBucketProperties configBucketProps =
        injector.getInstance(CertificatesConfigBucketProperties.class);
    assertNotNull(configBucketProps);
    assertEquals("test-public-bucket", configBucketProps.bucketName());
    assertEquals(S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH, configBucketProps.configFileName());

    CertificatesConfigProvider configProvider1 =
        injector.getInstance(CertificatesConfigProvider.class);
    CertificatesConfigProvider configProvider2 =
        injector.getInstance(CertificatesConfigProvider.class);
    assertNotNull(configProvider1);
    assertSame(configProvider1, configProvider2);
    assertTrue(configProvider1 instanceof DefaultingCertificatesConfigProvider);

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
