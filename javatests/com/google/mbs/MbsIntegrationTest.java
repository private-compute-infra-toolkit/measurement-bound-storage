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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.mbs.adapters.MeasurementBoundCertificateMonitor;
import com.google.mbs.adapters.S3BackupPaths;
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.MeasurementBoundBundle;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.TrustPackage;
import com.google.mbs.domain.TrustPackageProvider;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.InstanceId;
import com.google.mbs.qualifier.KmsKeyArn;
import com.google.mbs.qualifier.PrivateBackupBucket;
import com.google.mbs.qualifier.PublicBackupBucket;
import com.google.mbs.testing.FakeAttestationCollector;
import com.google.mbs.testing.FakeKmsClient;
import com.google.mbs.testing.S3TestClient;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
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

  private static final Instant DEFAULT_CONFIG_NOT_BEFORE = Instant.ofEpochSecond(1700000000);
  private static final Instant DEFAULT_CONFIG_NOT_AFTER = Instant.ofEpochSecond(1730000000);

  private static final String DEFAULT_CONFIG_TEXTPROTO =
      "self_signed_certificates {\n"
          + "  key: 0\n"
          + "  value {\n"
          + "    epoch_id: 0\n"
          + "    validity_period {\n"
          + "      not_before { seconds: 1700000000 nanos: 0 }\n"
          + "      not_after { seconds: 1730000000 nanos: 0 }\n"
          + "    }\n"
          + "  }\n"
          + "}\n"
          + "active_self_signed_certificate_ids: 0\n"
          + "acceptable_self_signed_certificate_ids: 0\n";

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

    // Verify test tooling cleared the buckets so tests start from a clean state.
    assertFalse(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0)));
    assertFalse(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getAttestationDocPath(0)));
    assertFalse(
        s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getKmsEncryptedDataKeyPath(0)));
    assertFalse(
        s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getAesEncryptedPrivateKeyPath(0)));
    assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getLockPath()));
  }

  private Injector createTestInjector() {
    return createTestInjector("i-testinstance123", "CN=Test MBS Root");
  }

  private Injector createTestInjector(String instanceId) {
    return createTestInjector(instanceId, "CN=Test MBS Root");
  }

  private Injector createTestInjector(String instanceId, String commonName) {
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory certFactory =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            spec, new X500Name(commonName), Optional.empty(), KeyUsage.keyCertSign);

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

  private static MeasurementBoundBundle activeCertificate(TrustPackageProvider provider) {
    TrustPackage trustPackage = provider.getActiveTrustPackage();
    assertEquals(1, trustPackage.bundles().size());
    assertTrue(trustPackage.crossSignedCertificates().isEmpty());
    return trustPackage.bundles().get(0);
  }

  @Test
  public void runOneIteration_emptyStorage_createsAndStoresCertificate() throws Exception {
    Injector injector = createTestInjector();
    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);

    assertThrows(IllegalStateException.class, provider::getActiveTrustPackage);

    runMonitorIteration(injector);

    MeasurementBoundBundle mbc = activeCertificate(provider);
    assertNotNull(mbc);
    assertNotNull(mbc.getCertificate());
    assertNotNull(mbc.getPrivateKey());
    assertNotNull(mbc.getAttestationToken());
    assertEquals("CN=Test MBS Root", mbc.getCertificate().getSubjectX500Principal().getName());
    assertEquals(DEFAULT_CONFIG_NOT_BEFORE, mbc.getCertificate().getNotBefore().toInstant());
    assertEquals(DEFAULT_CONFIG_NOT_AFTER, mbc.getCertificate().getNotAfter().toInstant());

    // Verify artifacts are stored in S3
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0)));
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getAttestationDocPath(0)));
    assertTrue(
        s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getKmsEncryptedDataKeyPath(0)));
    assertTrue(
        s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getAesEncryptedPrivateKeyPath(0)));
    // Verify lock file was cleanly released upon successful generation
    assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getLockPath()));

    // Verify stored certificate matches returned certificate
    byte[] storedCertBytes = s3TestClient.getFile(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0));
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate storedCert =
        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(storedCertBytes));
    assertEquals(mbc.getCertificate().getPublicKey(), storedCert.getPublicKey());
    assertEquals(DEFAULT_CONFIG_NOT_BEFORE, storedCert.getNotBefore().toInstant());
    assertEquals(DEFAULT_CONFIG_NOT_AFTER, storedCert.getNotAfter().toInstant());

    // Verify root cert and key consistency provided by TrustPackageProvider
    assertEquals(mbc.getCertificate(), activeCertificate(provider).getCertificate());
    assertEquals(mbc.getPrivateKey(), activeCertificate(provider).getPrivateKey());
  }

  @Test
  public void runOneIteration_existingStorage_loadsStoredCertificate() throws Exception {
    // Generate initial certificate and artifacts in S3
    Injector firstInjector = createTestInjector();
    runMonitorIteration(firstInjector);
    MeasurementBoundBundle initialMbc =
        activeCertificate(firstInjector.getInstance(TrustPackageProvider.class));

    byte[] initialCertBytes = s3TestClient.getFile(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0));
    byte[] initialKmsKeyBytes =
        s3TestClient.getFile(PRIVATE_BUCKET, S3BackupPaths.getKmsEncryptedDataKeyPath(0));
    byte[] initialAesKeyBytes =
        s3TestClient.getFile(PRIVATE_BUCKET, S3BackupPaths.getAesEncryptedPrivateKeyPath(0));

    // Create a second injector simulating a fresh enclave start
    Injector secondInjector = createTestInjector();
    TrustPackageProvider secondProvider = secondInjector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(secondInjector);
    MeasurementBoundBundle loadedMbc = activeCertificate(secondProvider);

    assertNotNull(loadedMbc);
    assertEquals(
        initialMbc.getCertificate().getSubjectX500Principal(),
        loadedMbc.getCertificate().getSubjectX500Principal());
    assertEquals(
        initialMbc.getCertificate().getPublicKey(), loadedMbc.getCertificate().getPublicKey());
    assertArrayEquals(
        initialMbc.getPrivateKey().getEncoded(), loadedMbc.getPrivateKey().getEncoded());

    // Verify S3 files were loaded and not overwritten
    assertArrayEquals(
        initialCertBytes, s3TestClient.getFile(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0)));
    assertArrayEquals(
        initialKmsKeyBytes,
        s3TestClient.getFile(PRIVATE_BUCKET, S3BackupPaths.getKmsEncryptedDataKeyPath(0)));
    assertArrayEquals(
        initialAesKeyBytes,
        s3TestClient.getFile(PRIVATE_BUCKET, S3BackupPaths.getAesEncryptedPrivateKeyPath(0)));
  }

  @Test
  public void runOneIteration_corruptedStorage_rejectsAndLeavesCertEmpty() {
    s3TestClient.putFile(
        PUBLIC_BUCKET,
        S3BackupPaths.getRootCertPath(0),
        "incomplete set of MBS backup objects".getBytes(StandardCharsets.UTF_8));
    Injector injector = createTestInjector();
    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);
    assertThrows(IllegalStateException.class, provider::getActiveTrustPackage);
    runMonitorIteration(injector);
    assertEquals(Metrics.ConfigEvent.SUCCESS, fakeMetrics.lastConfigEvent);
    assertEquals(Metrics.GenerationEvent.SUCCESS, fakeMetrics.lastGenerationEvent);
    assertEquals(Metrics.LoadEvent.STORED_BACKUP_CORRUPTED, fakeMetrics.lastLoadEvent);
    assertEquals(Metrics.MbsEvent.FAILURE, fakeMetrics.lastMbsEvent);
    // Not regenerated: no lock taken and no private artifacts written.
    assertTrue(s3TestClient.listFiles(PRIVATE_BUCKET).isEmpty());
    assertThrows(IllegalStateException.class, provider::getActiveTrustPackage);
  }

  // TODO: remove when all envs deploy the config file
  @Test
  public void runOneIteration_missingConfig_fallsBackToHardcodedDefaultConfigAndGenerates() {
    s3TestClient.deleteFile(PUBLIC_BUCKET, S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH);
    Injector injector = createTestInjector();
    TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(injector);

    MeasurementBoundBundle mbc = activeCertificate(provider);
    assertNotNull(mbc);
    assertEquals(
        Instant.parse("2026-10-01T00:00:00Z"), mbc.getCertificate().getNotBefore().toInstant());
    assertEquals(
        Instant.parse("2027-02-02T13:00:00Z"), mbc.getCertificate().getNotAfter().toInstant());
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, S3BackupPaths.getRootCertPath(0)));
    assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getLockPath()));
  }

  @Test
  public void runOneIteration_concurrentInstances_mutualExclusionAndSingleWinner()
      throws Exception {
    int numThreads = 20;
    java.util.concurrent.ExecutorService executor =
        java.util.concurrent.Executors.newFixedThreadPool(numThreads);
    try {
      java.util.List<java.util.concurrent.Callable<MeasurementBoundBundle>> tasks =
          new java.util.ArrayList<>();
      for (int i = 0; i < numThreads; i++) {
        final int threadId = i;
        tasks.add(
            () -> {
              Injector injector = createTestInjector("i-worker-" + threadId);
              TrustPackageProvider provider = injector.getInstance(TrustPackageProvider.class);
              runMonitorIteration(injector);
              MeasurementBoundBundle cert = activeCertificate(provider);
              assertNotNull(cert);
              return cert;
            });
      }

      java.util.List<java.util.concurrent.Future<MeasurementBoundBundle>> futures =
          executor.invokeAll(tasks);
      java.util.List<MeasurementBoundBundle> results = new java.util.ArrayList<>();
      for (java.util.concurrent.Future<MeasurementBoundBundle> future : futures) {
        results.add(future.get());
      }

      // Verify all instances received the exact same generated certificate
      MeasurementBoundBundle first = results.get(0);
      assertNotNull(first);
      for (int i = 1; i < results.size(); i++) {
        MeasurementBoundBundle current = results.get(i);
        assertEquals(
            first.getCertificate().getSubjectX500Principal(),
            current.getCertificate().getSubjectX500Principal());
        assertEquals(
            first.getCertificate().getPublicKey(), current.getCertificate().getPublicKey());
        assertArrayEquals(first.getPrivateKey().getEncoded(), current.getPrivateKey().getEncoded());
      }

      // Verify lock file was cleanly released by winner
      assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, S3BackupPaths.getLockPath()));
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void runOneIteration_updatesRunningInstanceWhenStorageChangesInBackground()
      throws Exception {
    // 1. Normal operation on Certificate A
    Injector runningInjector = createTestInjector("i-running-1", "CN=Initial MBS Root");
    TrustPackageProvider runningProvider = runningInjector.getInstance(TrustPackageProvider.class);

    runMonitorIteration(runningInjector);
    MeasurementBoundBundle certA = activeCertificate(runningProvider);
    assertNotNull(certA);
    assertSame(certA, activeCertificate(runningProvider));
    assertEquals("CN=Initial MBS Root", certA.getCertificate().getSubjectX500Principal().getName());

    // Normal operation: verify active signing works with Certificate A's keypair
    byte[] testPayload = "test-signature-payload".getBytes(StandardCharsets.UTF_8);
    Signature sigA = Signature.getInstance("SHA256withRSA");
    sigA.initSign(certA.getPrivateKey());
    sigA.update(testPayload);
    byte[] signatureA = sigA.sign();

    sigA.initVerify(certA.getCertificate().getPublicKey());
    sigA.update(testPayload);
    assertTrue(sigA.verify(signatureA));

    // Wait-free access continues returning Certificate A
    assertSame(certA, activeCertificate(runningProvider));

    // 2. Storage is updated in the background with Certificate B
    // (Simulating rotation: S3 buckets are re-provisioned and populated with new credentials)
    s3TestClient.clearBucket(PUBLIC_BUCKET);
    s3TestClient.clearBucket(PRIVATE_BUCKET);
    s3TestClient.putFile(
        PUBLIC_BUCKET, S3BackupPaths.CERTIFICATES_CONFIG_FILE_PATH, DEFAULT_CONFIG_TEXTPROTO);

    Injector rotationInjector = createTestInjector("i-rotator-1", "CN=Rotated MBS Root");
    TrustPackageProvider rotationProvider =
        rotationInjector.getInstance(TrustPackageProvider.class);
    runMonitorIteration(rotationInjector);
    MeasurementBoundBundle certB = activeCertificate(rotationProvider);
    assertNotNull(certB);
    assertSame(certB, activeCertificate(rotationProvider));
    assertEquals("CN=Rotated MBS Root", certB.getCertificate().getSubjectX500Principal().getName());
    assertNotEquals(
        certA.getCertificate().getSerialNumber(), certB.getCertificate().getSerialNumber());

    // Before reload is triggered, running provider still operates on Certificate A
    assertEquals(
        "CN=Initial MBS Root",
        activeCertificate(runningProvider).getCertificate().getSubjectX500Principal().getName());
    assertSame(certA, activeCertificate(runningProvider));

    // 3. Reload is triggered on the running instance
    runMonitorIteration(runningInjector);
    MeasurementBoundBundle reloadedCert = activeCertificate(runningProvider);

    // 4. Verify running provider has updated to Certificate B
    assertNotNull(reloadedCert);
    assertEquals(
        "CN=Rotated MBS Root", reloadedCert.getCertificate().getSubjectX500Principal().getName());
    assertEquals(
        certB.getCertificate().getSerialNumber(), reloadedCert.getCertificate().getSerialNumber());
    assertArrayEquals(
        certB.getPrivateKey().getEncoded(), reloadedCert.getPrivateKey().getEncoded());

    // Verify subsequent wait-free calls return Certificate B atomically
    MeasurementBoundBundle activeCert = activeCertificate(runningProvider);
    assertSame(reloadedCert, activeCert);
    assertEquals(
        "CN=Rotated MBS Root", activeCert.getCertificate().getSubjectX500Principal().getName());

    // Verify normal operation with new keypair: signing and verifying with Certificate B
    Signature sigB = Signature.getInstance("SHA256withRSA");
    sigB.initSign(activeCert.getPrivateKey());
    sigB.update(testPayload);
    byte[] signatureB = sigB.sign();

    sigB.initVerify(activeCert.getCertificate().getPublicKey());
    sigB.update(testPayload);
    assertTrue(sigB.verify(signatureB));

    // Verify cross-check: signature from B fails verification against old Certificate A
    sigB.initVerify(certA.getCertificate().getPublicKey());
    sigB.update(testPayload);
    assertFalse(sigB.verify(signatureB));
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
