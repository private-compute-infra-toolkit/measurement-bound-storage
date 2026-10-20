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

import static com.google.mbs.testing.CertificateTestHelper.parseCertificate;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.mbs.adapters.CertificatesConfigMapper;
import com.google.mbs.adapters.MeasurementBoundCertificateMonitor;
import com.google.mbs.adapters.S3BackupPaths;
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.MeasurementBoundBundle;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.SelfSignedCertificate;
import com.google.mbs.domain.TrustPackage;
import com.google.mbs.domain.TrustPackageProvider;
import com.google.mbs.domain.ValidityPeriod;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.InstanceId;
import com.google.mbs.qualifier.KmsKeyArn;
import com.google.mbs.qualifier.PrivateBackupBucket;
import com.google.mbs.qualifier.PublicBackupBucket;
import com.google.mbs.testing.FakeAttestationCollector;
import com.google.mbs.testing.FakeKmsClient;
import com.google.mbs.testing.S3TestClient;
import com.google.protobuf.TextFormat;
import com.google.protobuf.Timestamp;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;

@RunWith(JUnit4.class)
public class MbsIntegrationTest {

  private static final String PUBLIC_BUCKET = "mbs-integration-public-bucket";
  private static final String PRIVATE_BUCKET = "mbs-integration-private-bucket";
  private static final String KMS_KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/test-key";
  private static final byte[] TEST_USER_DATA =
      "mbs-test-user-data".getBytes(StandardCharsets.UTF_8);

  private static final String DEFAULT_CONFIG_TEXTPROTO =
      configTextproto(List.of(0, 1), List.of(0, 1));

  private static final LocalStackContainer localstack =
      new LocalStackContainer(DockerImageName.parse("localstack/localstack:4.14.0"))
          .withServices(LocalStackContainer.Service.S3)
          .withEnv("STRICT_S3_CHECKSUMS", "0")
          .withStartupTimeout(Duration.ofSeconds(120));

  private static S3Client s3Client;
  private static S3TestClient s3TestClient;

  private FakeKmsClient fakeKmsClient;
  private FakeAttestationCollector fakeAttestationCollector;
  private FakeMetrics fakeMetrics;

  @BeforeClass
  public static void setUpClass() {
    localstack.start();
    s3Client =
        S3Client.builder()
            .endpointOverride(localstack.getEndpointOverride(LocalStackContainer.Service.S3))
            .credentialsProvider(
                StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(
                        localstack.getAccessKey(), localstack.getSecretKey())))
            .serviceConfiguration(
                S3Configuration.builder()
                    .pathStyleAccessEnabled(true)
                    .chunkedEncodingEnabled(false)
                    .build())
            .overrideConfiguration(
                software.amazon.awssdk.core.client.config.ClientOverrideConfiguration.builder()
                    .addExecutionInterceptor(new LocalStackChecksumInterceptor())
                    .build())
            .region(Region.of(localstack.getRegion()))
            .build();
    s3TestClient = new S3TestClient(s3Client);
  }

  private static class LocalStackChecksumInterceptor
      implements software.amazon.awssdk.core.interceptor.ExecutionInterceptor {
    @Override
    public software.amazon.awssdk.http.SdkHttpRequest modifyHttpRequest(
        software.amazon.awssdk.core.interceptor.Context.ModifyHttpRequest context,
        software.amazon.awssdk.core.interceptor.ExecutionAttributes executionAttributes) {
      if (context.request() instanceof software.amazon.awssdk.services.s3.model.PutObjectRequest
          && context.requestBody().isPresent()) {
        try {
          software.amazon.awssdk.services.s3.model.PutObjectRequest req =
              (software.amazon.awssdk.services.s3.model.PutObjectRequest) context.request();
          if (req.checksumAlgorithm() != null && req.checksumSHA256() == null) {
            byte[] content;
            try (java.io.InputStream stream =
                context.requestBody().get().contentStreamProvider().newStream()) {
              content = stream.readAllBytes();
            }
            String sha256 =
                java.util.Base64.getEncoder()
                    .encodeToString(
                        java.security.MessageDigest.getInstance("SHA-256").digest(content));
            return context.httpRequest().toBuilder()
                .putHeader("x-amz-checksum-sha256", sha256)
                .build();
          }
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
      return context.httpRequest();
    }
  }

  @AfterClass
  public static void tearDownClass() {
    if (s3Client != null) {
      s3Client.close();
    }
    if (localstack != null) {
      localstack.stop();
    }
  }

  @Before
  public void setUp() {
    fakeKmsClient = new FakeKmsClient();
    fakeAttestationCollector = new FakeAttestationCollector();
    fakeMetrics = new FakeMetrics();

    s3TestClient.createBucket(PUBLIC_BUCKET);
    s3TestClient.createBucket(PRIVATE_BUCKET);
    s3TestClient.clearBucket(PUBLIC_BUCKET);
    s3TestClient.clearBucket(PRIVATE_BUCKET);
    s3TestClient.putFile(
        PUBLIC_BUCKET, S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH, DEFAULT_CONFIG_TEXTPROTO);
  }

  private Injector createTestInjector() {
    return createTestInjector("i-testinstance123", "CN=Test MBS Root");
  }

  private Injector createTestInjector(String instanceId) {
    return createTestInjector(instanceId, "CN=Test MBS Root");
  }

  private static MbsCertificateFactory createCertFactory(String commonName) {
    return MbsCertificateFactory.createSelfSignedCertificatesFactory(
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA"),
        new X500Name(commonName),
        Optional.empty(),
        KeyUsage.keyCertSign);
  }

  private Injector createTestInjector(String instanceId, String commonName) {
    MbsCertificateFactory certFactory = createCertFactory(commonName);

    return Guice.createInjector(
        new MbsCoreModule(),
        new AbstractModule() {
          @Override
          protected void configure() {
            bind(KmsClientInterface.class).toInstance(fakeKmsClient);
            bind(AttestationCollector.class).toInstance(fakeAttestationCollector);
            bind(S3Client.class).toInstance(s3Client);
            bind(Metrics.class).toInstance(fakeMetrics);
            bind(String.class).annotatedWith(PublicBackupBucket.class).toInstance(PUBLIC_BUCKET);
            bind(String.class).annotatedWith(PrivateBackupBucket.class).toInstance(PRIVATE_BUCKET);
            bind(String.class).annotatedWith(KmsKeyArn.class).toInstance(KMS_KEY_ARN);
            bind(String.class).annotatedWith(InstanceId.class).toInstance(instanceId);
            bind(byte[].class).annotatedWith(AttestationUserData.class).toInstance(TEST_USER_DATA);
            bind(MbsCertificateFactory.class).toInstance(certFactory);
          }
        });
  }

  private static void runMonitorIteration(Injector injector) {
    injector.getInstance(MeasurementBoundCertificateMonitor.class).runOneIteration();
  }

  private static MeasurementBoundBundle singleActiveBundle(TrustPackageProvider provider) {
    TrustPackage trustPackage = provider.getActiveTrustPackage();
    assertEquals(1, trustPackage.bundles().size());
    assertTrue(trustPackage.crossSignedCertificates().isEmpty());
    return trustPackage.bundles().get(0);
  }

  // TODO(b/556648211): replace with chaining cross signed certificates once we can generate them
  private static X509Certificate putCrossSignedCert(CrossSignedCertificateId id) throws Exception {
    X509Certificate cert =
        createCertFactory("CN=Cross " + id.toKeyString())
            .generate(
                new SelfSignedCertificate(
                    0, new ValidityPeriod(Instant.EPOCH, Instant.ofEpochSecond(1))))
            .certificate();
    s3TestClient.putFile(
        PUBLIC_BUCKET,
        S3BackupPaths.getCrossSignedCertPath(id),
        KmsMeasurementBoundCertificateGenerator.toPemBytes(cert));
    return cert;
  }

  private static String configTextproto(
      List<Integer> activeEpochs, List<Integer> configuredEpochs) {
    return configTextproto(activeEpochs, configuredEpochs, List.of(), List.of());
  }

  private static String configTextproto(
      List<Integer> activeEpochs,
      List<Integer> configuredEpochs,
      List<CrossSignedCertificateId> activeCrossSigned,
      List<CrossSignedCertificateId> configuredCrossSigned) {
    com.google.mbs.v1.CertificatesConfig.Builder builder =
        com.google.mbs.v1.CertificatesConfig.newBuilder()
            .addAllActiveSelfSignedCertificateIds(activeEpochs)
            .addAllAcceptableSelfSignedCertificateIds(configuredEpochs)
            .addAllActiveCrossSignedCertificateIds(
                activeCrossSigned.stream().map(CrossSignedCertificateId::toKeyString).toList());
    for (int epoch : configuredEpochs) {
      long notBeforeSeconds = 1700000000L + epoch * 20000000L;
      long notAfterSeconds = 1730000000L + epoch * 20000000L;
      builder.putSelfSignedCertificates(
          epoch,
          com.google.mbs.v1.SelfSignedCertificate.newBuilder()
              .setEpochId(epoch)
              .setValidityPeriod(
                  com.google.mbs.v1.ValidityPeriod.newBuilder()
                      .setNotBefore(Timestamp.newBuilder().setSeconds(notBeforeSeconds))
                      .setNotAfter(Timestamp.newBuilder().setSeconds(notAfterSeconds)))
              .build());
    }
    for (CrossSignedCertificateId id : configuredCrossSigned) {
      builder.putCrossSignedCertificates(
          id.toKeyString(),
          com.google.mbs.v1.CrossSignedCertificate.newBuilder()
              .setPrivateKeyEpochId(id.privateKeyEpochId())
              .setPublicKeyEpochId(id.publicKeyEpochId())
              .setValidityPeriod(
                  com.google.mbs.v1.ValidityPeriod.newBuilder()
                      .setNotBefore(Timestamp.newBuilder().setSeconds(1700000000L))
                      .setNotAfter(Timestamp.newBuilder().setSeconds(1730000000L)))
              .build());
    }
    return TextFormat.printer().printToString(builder.build());
  }

  @Test
  public void runOneIteration_emptyStorage_generatesAndLoadsCertificates() throws Exception {
    CertificatesConfig config = CertificatesConfigMapper.fromTextProto(DEFAULT_CONFIG_TEXTPROTO);
    Injector injector = createTestInjector();
    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);

    assertThrows(IllegalStateException.class, provider::getActiveTrustPackage);

    runMonitorIteration(injector);

    TrustPackage trustPackage = provider.getActiveTrustPackage();
    assertEquals(config.selfSignedCertificates().size(), trustPackage.bundles().size());
    assertTrue(trustPackage.crossSignedCertificates().isEmpty());

    for (MeasurementBoundBundle bundle : trustPackage.bundles()) {
      assertNotNull(bundle.getCertificate());
      assertNotNull(bundle.getPrivateKey());
      assertNotNull(bundle.getAttestationToken());
      assertEquals("CN=Test MBS Root", bundle.getCertificate().getSubjectX500Principal().getName());
    }

    for (SelfSignedCertificate expectedCert : config.selfSignedCertificates().values()) {
      ValidityPeriod expectedValidity = expectedCert.validityPeriod();
      assertTrue(
          trustPackage.bundles().stream()
              .map(MeasurementBoundBundle::getCertificate)
              .anyMatch(
                  cert ->
                      cert.getNotBefore().toInstant().equals(expectedValidity.notBefore())
                          && cert.getNotAfter().toInstant().equals(expectedValidity.notAfter())));
    }
  }

  @Test
  public void runOneIteration_existingStorage_loadsExistingCertificatesWithoutRegenerating() {
    // Generate initial certificates and artifacts in S3
    Injector firstInjector = createTestInjector();
    runMonitorIteration(firstInjector);
    TrustPackage initialPackage =
        firstInjector.getInstance(TrustPackageProvider.class).getActiveTrustPackage();

    // Create a second injector simulating a fresh enclave start
    Injector secondInjector = createTestInjector();
    TrustPackageProvider secondProvider = secondInjector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(secondInjector);
    TrustPackage loadedPackage = secondProvider.getActiveTrustPackage();

    assertEquals(initialPackage, loadedPackage);
  }

  @Test
  public void runOneIteration_corruptedActiveEpoch_generatesMissingEpochAndFailsLoad() {
    byte[] corruptedCert = "incomplete set of MBS backup objects".getBytes(StandardCharsets.UTF_8);
    s3TestClient.putFile(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0), corruptedCert);
    Injector injector = createTestInjector();
    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(injector);

    assertEquals(Metrics.ConfigEvent.SUCCESS, fakeMetrics.lastConfigEvent);
    assertEquals(Metrics.GenerationEvent.SUCCESS, fakeMetrics.lastGenerationEvent);
    assertEquals(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED, fakeMetrics.lastLoadEvent);
    assertEquals(Metrics.MbsEvent.FAILURE, fakeMetrics.lastMbsEvent);
    // Missing epoch 1 was generated, while corrupted epoch 0 was not overwritten.
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(1)));
    assertArrayEquals(
        corruptedCert, s3TestClient.getFile(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0)));
    assertThrows(IllegalStateException.class, provider::getActiveTrustPackage);
  }

  // TODO: remove when all envs deploy the config file
  @Test
  public void runOneIteration_missingConfig_fallsBackToHardcodedDefaultConfigAndGenerates() {
    s3TestClient.deleteFile(PUBLIC_BUCKET, S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH);
    Injector injector = createTestInjector();
    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(injector);

    MeasurementBoundBundle bundle = singleActiveBundle(provider);
    assertEquals(
        Instant.parse("2026-10-01T00:00:00Z"), bundle.getCertificate().getNotBefore().toInstant());
    assertEquals(
        Instant.parse("2027-02-02T13:00:00Z"), bundle.getCertificate().getNotAfter().toInstant());
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0)));
    assertFalse(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(1)));
  }

  @Test
  public void runOneIteration_concurrentInstances_mutualExclusionAndSingleWinner()
      throws Exception {
    int numThreads = 20;
    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    try {
      List<Callable<TrustPackage>> tasks = new ArrayList<>();
      for (int i = 0; i < numThreads; i++) {
        final int threadId = i;
        tasks.add(
            () -> {
              Injector injector = createTestInjector("i-worker-" + threadId);
              TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);
              runMonitorIteration(injector);
              TrustPackage trustPackage = provider.getActiveTrustPackage();
              assertEquals(2, trustPackage.bundles().size());
              return trustPackage;
            });
      }

      List<Future<TrustPackage>> futures = executor.invokeAll(tasks);
      List<TrustPackage> results = new ArrayList<>();
      for (Future<TrustPackage> future : futures) {
        results.add(future.get());
      }

      // Verify all instances received the exact same generated certificates for both epochs
      TrustPackage first = results.get(0);
      for (int i = 1; i < results.size(); i++) {
        assertEquals(first, results.get(i));
      }

      // Verify lock file was cleanly released by winner
      assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getLockPath()));
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void
      runOneIteration_certificateRotationLifecycle_preGeneratesActivatesAndDeactivatesEpochs()
          throws Exception {
    // 1. Initial operation with only epoch 0 configured and active
    s3TestClient.putFile(
        PUBLIC_BUCKET,
        S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH,
        configTextproto(List.of(0), List.of(0)));

    Injector runningInjector = createTestInjector("i-running-1", "CN=Initial MBS Root");
    TrustPackageProvider runningProvider = runningInjector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(runningInjector);
    MeasurementBoundBundle epoch0Bundle = singleActiveBundle(runningProvider);
    assertEquals(
        "CN=Initial MBS Root", epoch0Bundle.getCertificate().getSubjectX500Principal().getName());
    assertFalse(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(1)));

    // Normal operation: verify active signing works with Certificate A's keypair
    byte[] testPayload = "test-signature-payload".getBytes(StandardCharsets.UTF_8);
    Signature sigA = Signature.getInstance("SHA256withRSA");
    sigA.initSign(epoch0Bundle.getPrivateKey());
    sigA.update(testPayload);
    byte[] signatureA = sigA.sign();

    sigA.initVerify(epoch0Bundle.getCertificate().getPublicKey());
    sigA.update(testPayload);
    assertTrue(sigA.verify(signatureA));

    // 2. Pre-rotation step: epoch 1 and cross-signed certs are added (inactive) in S3
    CrossSignedCertificateId id01 = new CrossSignedCertificateId(0, 1);
    CrossSignedCertificateId id10 = new CrossSignedCertificateId(1, 0);
    X509Certificate cross01Cert = putCrossSignedCert(id01);
    X509Certificate cross10Cert = putCrossSignedCert(id10);
    s3TestClient.putFile(
        PUBLIC_BUCKET,
        S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH,
        configTextproto(List.of(0), List.of(0, 1), List.of(), List.of(id01, id10)));

    Injector rotationInjector = createTestInjector("i-rotator-1", "CN=Rotated MBS Root");
    TrustPackageProvider rotationProvider =
        rotationInjector.getInstance(TrustPackageProvider.class);
    runMonitorIteration(rotationInjector);
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(1)));
    X509Certificate epoch1Cert =
        parseCertificate(s3TestClient.getFile(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(1)));
    assertEquals("CN=Rotated MBS Root", epoch1Cert.getSubjectX500Principal().getName());
    assertNotEquals(epoch0Bundle.getCertificate().getSerialNumber(), epoch1Cert.getSerialNumber());
    assertEquals(epoch0Bundle, singleActiveBundle(rotationProvider));

    // 3. Rotation step 1 (dual-active): epoch 1 and cross-signed certs are activated
    s3TestClient.putFile(
        PUBLIC_BUCKET,
        S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH,
        configTextproto(List.of(1, 0), List.of(0, 1), List.of(id01, id10), List.of(id01, id10)));

    runMonitorIteration(rotationInjector);
    TrustPackage rotationPackage = rotationProvider.getActiveTrustPackage();
    assertEquals(2, rotationPackage.bundles().size());
    assertEquals(
        Set.of(cross01Cert, cross10Cert), Set.copyOf(rotationPackage.crossSignedCertificates()));

    // Before reload is triggered, running provider still operates on Certificate A only
    assertEquals(epoch0Bundle, singleActiveBundle(runningProvider));

    // 4. Reload is triggered on the running instance during dual-active window
    runMonitorIteration(runningInjector);
    TrustPackage dualActivePackage = runningProvider.getActiveTrustPackage();
    assertEquals(rotationPackage, dualActivePackage);
    assertTrue(dualActivePackage.bundles().contains(epoch0Bundle));
    assertTrue(
        dualActivePackage.bundles().stream().anyMatch(b -> b.getCertificate().equals(epoch1Cert)));

    // 5. Rotation step 2: epoch 0 and cross-signed certs are deactivated, leaving only epoch 1
    s3TestClient.putFile(
        PUBLIC_BUCKET,
        S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH,
        configTextproto(List.of(1), List.of(0, 1), List.of(), List.of(id01, id10)));
    runMonitorIteration(runningInjector);

    MeasurementBoundBundle activeBundle = singleActiveBundle(runningProvider);
    assertEquals(epoch1Cert, activeBundle.getCertificate());

    // Verify normal operation with new keypair: signing and verifying with Certificate B
    Signature sigB = Signature.getInstance("SHA256withRSA");
    sigB.initSign(activeBundle.getPrivateKey());
    sigB.update(testPayload);
    byte[] signatureB = sigB.sign();

    sigB.initVerify(activeBundle.getCertificate().getPublicKey());
    sigB.update(testPayload);
    assertTrue(sigB.verify(signatureB));

    // Verify cross-check: signature from B fails verification against old Certificate A
    sigB.initVerify(epoch0Bundle.getCertificate().getPublicKey());
    sigB.update(testPayload);
    assertFalse(sigB.verify(signatureB));
  }

  @Test
  public void runOneIteration_configUpdateWithMissingEpoch_retainsPreviousTrustPackage() {
    assertConfigUpdateWithMissingCertificateRetainsPreviousTrustPackage(
        configTextproto(List.of(0, 1), List.of(0, 1)));
  }

  @Test
  public void
      runOneIteration_configUpdateWithMissingCrossSignedCertificate_retainsPreviousTrustPackage() {
    CrossSignedCertificateId id01 = new CrossSignedCertificateId(0, 1);
    assertConfigUpdateWithMissingCertificateRetainsPreviousTrustPackage(
        configTextproto(List.of(0), List.of(0, 1), List.of(id01), List.of(id01)));
  }

  private void assertConfigUpdateWithMissingCertificateRetainsPreviousTrustPackage(
      String configWithMissingCert) {
    s3TestClient.putFile(
        PUBLIC_BUCKET,
        S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH,
        configTextproto(List.of(0), List.of(0)));

    Injector injector = createTestInjector("i-running-retain", "CN=Initial MBS Root");
    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(injector);
    TrustPackage initialPackage = provider.getActiveTrustPackage();
    assertEquals(1, initialPackage.bundles().size());
    assertEquals(Metrics.MbsEvent.SUCCESS, fakeMetrics.lastMbsEvent);

    // Hold the generation lock so newly configured certificates cannot be generated.
    s3TestClient.putFile(
        PRIVATE_BUCKET,
        S3BackupPaths.getLockPath(),
        "other-instance".getBytes(StandardCharsets.UTF_8));
    s3TestClient.putFile(
        PUBLIC_BUCKET, S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH, configWithMissingCert);

    runMonitorIteration(injector);

    assertEquals(Metrics.ConfigEvent.SUCCESS, fakeMetrics.lastConfigEvent);
    assertEquals(Metrics.GenerationEvent.WAITING_FOR_MBS_LOCK, fakeMetrics.lastGenerationEvent);
    assertEquals(Metrics.LoadEvent.KEY_BACKUP_NOT_FOUND, fakeMetrics.lastLoadEvent);
    assertEquals(Metrics.MbsEvent.FAILURE, fakeMetrics.lastMbsEvent);
    assertEquals(initialPackage, provider.getActiveTrustPackage());
  }

  @Test
  public void runOneIteration_invalidConfigUpdate_fallsBackToDefaultConfigAndServesDefaultEpoch()
      throws Exception {
    Injector injector = createTestInjector("i-running-invalid-cfg", "CN=Initial MBS Root");
    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(injector);
    assertEquals(2, provider.getActiveTrustPackage().bundles().size());
    assertEquals(Metrics.MbsEvent.SUCCESS, fakeMetrics.lastMbsEvent);
    X509Certificate epoch0Cert =
        parseCertificate(s3TestClient.getFile(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0)));

    // DefaultingCertificatesConfigProvider catches InvalidCertificatesConfigException from
    // S3CertificatesConfigProvider and substitutes DEFAULT_CONFIG (epoch 0), so the monitor
    // iteration still succeeds while serving epoch 0.
    s3TestClient.putFile(
        PUBLIC_BUCKET,
        S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH,
        configTextproto(List.of(), List.of(0, 1)));

    runMonitorIteration(injector);

    assertEquals(Metrics.ConfigEvent.INVALID_CONFIGURATION_FILE, fakeMetrics.lastConfigEvent);
    assertEquals(Metrics.MbsEvent.SUCCESS, fakeMetrics.lastMbsEvent);
    assertEquals(epoch0Cert, singleActiveBundle(provider).getCertificate());
  }

  @Test
  public void s3TestClient_operations_workAsExpected() {
    String testBucket = "s3-test-client-bucket";
    s3TestClient.createBucket(testBucket);

    String key1 = "folder/file1.txt";
    String key2 = "folder/file2.txt";
    byte[] data1 = "hello world".getBytes(StandardCharsets.UTF_8);
    byte[] data2 = "foo bar".getBytes(StandardCharsets.UTF_8);

    assertFalse(s3TestClient.fileExists(testBucket, key1));
    s3TestClient.putFile(testBucket, key1, data1);
    assertTrue(s3TestClient.fileExists(testBucket, key1));
    assertArrayEquals(data1, s3TestClient.getFile(testBucket, key1));
    assertEquals(
        Optional.of(data1).map(b -> new String(b, StandardCharsets.UTF_8)),
        s3TestClient
            .getFileIfExists(testBucket, key1)
            .map(b -> new String(b, StandardCharsets.UTF_8)));

    s3TestClient.putFile(testBucket, key2, data2);
    List<String> files = s3TestClient.listFiles(testBucket, "folder/");
    assertEquals(2, files.size());
    assertTrue(files.contains(key1));
    assertTrue(files.contains(key2));

    s3TestClient.deleteFile(testBucket, key1);
    assertFalse(s3TestClient.fileExists(testBucket, key1));
    assertFalse(s3TestClient.getFileIfExists(testBucket, key1).isPresent());

    s3TestClient.clearBucket(testBucket);
    assertTrue(s3TestClient.listFiles(testBucket).isEmpty());

    s3TestClient.deleteBucket(testBucket);
  }

  private static final class FakeMetrics implements Metrics {
    volatile MbsEvent lastMbsEvent;
    volatile GenerationEvent lastGenerationEvent;
    volatile LoadEvent lastLoadEvent;
    volatile ConfigEvent lastConfigEvent;

    @Override
    public void recordEvent(MbsEvent event) {
      this.lastMbsEvent = event;
    }

    @Override
    public void recordGenerationEvent(GenerationEvent event) {
      this.lastGenerationEvent = event;
    }

    @Override
    public void recordLoadEvent(LoadEvent event) {
      this.lastLoadEvent = event;
    }

    @Override
    public void recordConfigEvent(ConfigEvent event) {
      this.lastConfigEvent = event;
    }
  }
}
