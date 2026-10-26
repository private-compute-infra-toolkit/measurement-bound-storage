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
import com.google.mbs.adapters.AeadSelfSignedBundleBackupSealer;
import com.google.mbs.adapters.AwsAttestationCollector;
import com.google.mbs.adapters.AwsKmsClient;
import com.google.mbs.adapters.DefaultingCertificatesConfigProvider;
import com.google.mbs.adapters.PemCertificateCodec;
import com.google.mbs.adapters.S3BackupPaths;
import com.google.mbs.adapters.S3BackupStorage;
import com.google.mbs.adapters.ScheduledCertificateMonitor;
import com.google.mbs.adapters.nsm.DefaultNitroSecurityModuleFactory;
import com.google.mbs.adapters.nsm.NitroSecurityModuleFactory;
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.BackupBucketProperties;
import com.google.mbs.domain.BackupStorage;
import com.google.mbs.domain.CertificateCodec;
import com.google.mbs.domain.CertificateGenerator;
import com.google.mbs.domain.CertificateMonitor;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CertificatesConfigBucketProperties;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedBundle;
import com.google.mbs.domain.SelfSignedBundleBackupSealer;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.TrustPackage;
import com.google.mbs.domain.TrustPackageProvider;
import com.google.mbs.domain.TrustPackageReloader;
import com.google.mbs.domain.ValidityPeriod;
import com.google.mbs.dummy.DummyMbsModule;
import com.google.mbs.dummy.DummyTrustPackageProvider;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.InstanceId;
import com.google.mbs.qualifier.KmsKeyArn;
import com.google.mbs.qualifier.PrivateBackupBucket;
import com.google.mbs.qualifier.PublicBackupBucket;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
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

    CertificateGenerator generator = injector.getInstance(CertificateGenerator.class);
    assertNotNull(generator);
    assertSame(provider, generator);

    CertificatesConfigProvider configProvider =
        injector.getInstance(CertificatesConfigProvider.class);
    assertNotNull(configProvider);
    assertSame(provider, configProvider);

    assertThrows(IllegalStateException.class, provider::getActiveTrustPackage);

    CertificatesConfig config = configProvider.getCertificatesConfig();
    generator.generateCertificates(config);
    reloader.reload(config);
    TrustPackage package1 = provider.getActiveTrustPackage();
    assertNotNull(package1);
    assertEquals(1, package1.selfSignedBundles().size());
    assertTrue(package1.crossSignedCertificates().isEmpty());
    SelfSignedBundle bundle1 = package1.selfSignedBundles().get(0);
    assertNotNull(bundle1.certificate());
    assertNotNull(bundle1.privateKey());
    var expectedValidity = config.selfSignedCertificates().get(0).validityPeriod();
    assertEquals(expectedValidity.notBefore(), bundle1.certificate().getNotBefore().toInstant());
    assertEquals(expectedValidity.notAfter(), bundle1.certificate().getNotAfter().toInstant());

    reloader.reload(config);
    TrustPackage package2 = provider.getActiveTrustPackage();
    assertNotNull(package2);
    assertEquals(1, package2.selfSignedBundles().size());
    assertTrue(package2.crossSignedCertificates().isEmpty());
    SelfSignedBundle bundle2 = package2.selfSignedBundles().get(0);
    assertNotNull(bundle2.certificate());
    assertNotNull(bundle2.privateKey());
    assertNotEquals(
        bundle1.certificate().getSerialNumber(), bundle2.certificate().getSerialNumber());

    ValidityPeriod validity0 =
        new ValidityPeriod(
            Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-06-01T00:00:00Z"));
    ValidityPeriod validity2 =
        new ValidityPeriod(
            Instant.parse("2026-05-01T00:00:00Z"), Instant.parse("2026-10-01T00:00:00Z"));
    CertificatesConfig multiEpochConfig =
        new CertificatesConfig(
            Map.of(
                0, new SelfSignedCertificate(0, validity0),
                2, new SelfSignedCertificate(2, validity2)),
            Map.of(),
            Set.of(2, 0),
            Set.of(),
            Set.of(0, 2));
    reloader.reload(multiEpochConfig);
    TrustPackage multiPackage = provider.getActiveTrustPackage();
    assertEquals(2, multiPackage.selfSignedBundles().size());
    Set<ValidityPeriod> loadedValidities =
        multiPackage.selfSignedBundles().stream()
            .map(
                b ->
                    new ValidityPeriod(
                        b.certificate().getNotBefore().toInstant(),
                        b.certificate().getNotAfter().toInstant()))
            .collect(Collectors.toSet());
    assertEquals(Set.of(validity0, validity2), loadedValidities);

    CertificateMonitor scheduler = injector.getInstance(CertificateMonitor.class);
    assertNotNull(scheduler);
    assertTrue(scheduler instanceof ScheduledCertificateMonitor);
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
    assertTrue(provider instanceof TrustPackageService);

    TrustPackageReloader reloader = injector.getInstance(TrustPackageReloader.class);
    assertNotNull(reloader);
    assertSame(provider, reloader);

    CertificateGenerator generator = injector.getInstance(CertificateGenerator.class);
    assertNotNull(generator);
    assertTrue(generator instanceof DefaultCertificateGenerator);

    CertificateCodec certificateCodec = injector.getInstance(CertificateCodec.class);
    assertNotNull(certificateCodec);
    assertTrue(certificateCodec instanceof PemCertificateCodec);

    SelfSignedBundleBackupSealer backupSealer =
        injector.getInstance(SelfSignedBundleBackupSealer.class);
    assertNotNull(backupSealer);
    assertTrue(backupSealer instanceof AeadSelfSignedBundleBackupSealer);

    BackupBucketProperties bucketProps = injector.getInstance(BackupBucketProperties.class);
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

    BackupStorage storage1 = injector.getInstance(BackupStorage.class);
    BackupStorage storage2 = injector.getInstance(BackupStorage.class);
    assertNotNull(storage1);
    assertSame(storage1, storage2);
    assertTrue(storage1 instanceof S3BackupStorage);

    NitroSecurityModuleFactory nsmFactory = injector.getInstance(NitroSecurityModuleFactory.class);
    assertNotNull(nsmFactory);
    assertTrue(nsmFactory instanceof DefaultNitroSecurityModuleFactory);

    KmsClientInterface kmsClient = injector.getInstance(KmsClientInterface.class);
    assertNotNull(kmsClient);
    assertTrue(kmsClient instanceof AwsKmsClient);

    CertificateMonitor scheduler = injector.getInstance(CertificateMonitor.class);
    assertNotNull(scheduler);
    assertTrue(scheduler instanceof ScheduledCertificateMonitor);
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
