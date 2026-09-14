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
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.KeyBackupBucketProperties;
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
import com.google.mbs.testing.FakeAttestationCollector;
import com.google.mbs.testing.FakeKmsClient;
import com.google.mbs.testing.S3TestClient;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
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

  private static final LocalStackContainer localstack =
      new LocalStackContainer(DockerImageName.parse("localstack/localstack:4.14.0"))
          .withServices(LocalStackContainer.Service.S3)
          .withEnv("STRICT_S3_CHECKSUMS", "0")
          .withStartupTimeout(Duration.ofSeconds(120));

  private static S3Client s3Client;
  private static S3TestClient s3TestClient;

  private FakeKmsClient fakeKmsClient;
  private FakeAttestationCollector fakeAttestationCollector;
  private KeyBackupBucketProperties bucketProperties;

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
    bucketProperties = new KeyBackupBucketPropertiesFactory(PUBLIC_BUCKET, PRIVATE_BUCKET).create();

    s3TestClient.createBucket(PUBLIC_BUCKET);
    s3TestClient.createBucket(PRIVATE_BUCKET);
    s3TestClient.clearBucket(PUBLIC_BUCKET);
    s3TestClient.clearBucket(PRIVATE_BUCKET);

    // Verify test tooling cleared the buckets so tests start from a clean state.
    assertFalse(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getCertPath()));
    assertFalse(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getAttestationDocPath()));
    assertFalse(
        s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getKmsEncryptedDataKeyPath()));
    assertFalse(
        s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath()));
    assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getLockPath()));
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
            spec,
            new X500Name(commonName),
            Duration.ofDays(30),
            Optional.empty(),
            KeyUsage.keyCertSign);

    return Guice.createInjector(
        new MbsCoreModule(),
        new AbstractModule() {
          @Override
          protected void configure() {
            bind(KmsClientInterface.class).toInstance(fakeKmsClient);
            bind(AttestationCollector.class).toInstance(fakeAttestationCollector);
            bind(S3Client.class).toInstance(s3Client);
            bind(Metrics.class).to(NoOpMetrics.class);
            bind(String.class).annotatedWith(PublicBackupBucket.class).toInstance(PUBLIC_BUCKET);
            bind(String.class).annotatedWith(PrivateBackupBucket.class).toInstance(PRIVATE_BUCKET);
            bind(String.class).annotatedWith(KmsKeyArn.class).toInstance(KMS_KEY_ARN);
            bind(String.class).annotatedWith(InstanceId.class).toInstance(instanceId);
            bind(byte[].class).annotatedWith(AttestationUserData.class).toInstance(TEST_USER_DATA);
            bind(MbsCertificateFactory.class).toInstance(certFactory);
          }
        });
  }

  @Test
  public void loadOrGenerateCertificate_emptyStorage_createsAndStoresCertificate()
      throws Exception {
    Injector injector = createTestInjector();
    MeasurementBoundCertificateProvider provider =
        injector.getInstance(MeasurementBoundCertificateProvider.class);
    MeasurementBoundCertificateReloader reloader =
        injector.getInstance(MeasurementBoundCertificateReloader.class);

    assertThrows(IllegalStateException.class, provider::getCertificate);

    reloader.reloadCertificate();

    MeasurementBoundCertificate mbc = provider.getCertificate();
    assertNotNull(mbc);
    assertNotNull(mbc.getCertificate());
    assertNotNull(mbc.getPrivateKey());
    assertNotNull(mbc.getAttestationToken());
    assertEquals("CN=Test MBS Root", mbc.getCertificate().getSubjectX500Principal().getName());

    // Verify artifacts are stored in S3
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getCertPath()));
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getAttestationDocPath()));
    assertTrue(
        s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getKmsEncryptedDataKeyPath()));
    assertTrue(
        s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath()));
    // Verify lock file was cleanly released upon successful generation
    assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getLockPath()));

    // Verify stored certificate matches returned certificate
    byte[] storedCertBytes = s3TestClient.getFile(PUBLIC_BUCKET, bucketProperties.getCertPath());
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate storedCert =
        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(storedCertBytes));
    assertEquals(mbc.getCertificate().getPublicKey(), storedCert.getPublicKey());

    // Verify root cert and key consistency provided by MeasurementBoundCertificateProvider
    assertEquals(mbc.getCertificate(), provider.getCertificate().getCertificate());
    assertEquals(mbc.getPrivateKey(), provider.getCertificate().getPrivateKey());
  }

  @Test
  public void loadOrGenerateCertificate_existingStorage_loadsStoredCertificate() throws Exception {
    // Generate initial certificate and artifacts in S3
    Injector firstInjector = createTestInjector();
    MeasurementBoundCertificateReloader firstReloader =
        firstInjector.getInstance(MeasurementBoundCertificateReloader.class);
    firstReloader.reloadCertificate();
    MeasurementBoundCertificate initialMbc =
        firstInjector.getInstance(MeasurementBoundCertificateProvider.class).getCertificate();

    byte[] initialCertBytes = s3TestClient.getFile(PUBLIC_BUCKET, bucketProperties.getCertPath());
    byte[] initialKmsKeyBytes =
        s3TestClient.getFile(PRIVATE_BUCKET, bucketProperties.getKmsEncryptedDataKeyPath());
    byte[] initialAesKeyBytes =
        s3TestClient.getFile(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath());

    // Create a second injector simulating a fresh enclave start
    Injector secondInjector = createTestInjector();
    MeasurementBoundCertificateReloader secondReloader =
        secondInjector.getInstance(MeasurementBoundCertificateReloader.class);
    MeasurementBoundCertificateProvider secondProvider =
        secondInjector.getInstance(MeasurementBoundCertificateProvider.class);

    secondReloader.reloadCertificate();
    MeasurementBoundCertificate loadedMbc = secondProvider.getCertificate();

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
        initialCertBytes, s3TestClient.getFile(PUBLIC_BUCKET, bucketProperties.getCertPath()));
    assertArrayEquals(
        initialKmsKeyBytes,
        s3TestClient.getFile(PRIVATE_BUCKET, bucketProperties.getKmsEncryptedDataKeyPath()));
    assertArrayEquals(
        initialAesKeyBytes,
        s3TestClient.getFile(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath()));
  }

  @Test
  public void loadOrGenerateCertificate_missingRootCert_triggersRegeneration() throws Exception {
    Injector firstInjector = createTestInjector();
    firstInjector.getInstance(MeasurementBoundCertificateReloader.class).reloadCertificate();

    // Delete the root cert from S3
    s3TestClient.deleteFile(PUBLIC_BUCKET, bucketProperties.getCertPath());
    assertFalse(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getCertPath()));

    // Fresh start should regenerate all artifacts
    Injector secondInjector = createTestInjector();
    secondInjector.getInstance(MeasurementBoundCertificateReloader.class).reloadCertificate();
    MeasurementBoundCertificateProvider secondProvider =
        secondInjector.getInstance(MeasurementBoundCertificateProvider.class);
    MeasurementBoundCertificate regeneratedMbc = secondProvider.getCertificate();

    assertNotNull(regeneratedMbc);
    assertSame(regeneratedMbc, secondProvider.getCertificate());
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getCertPath()));
    assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getLockPath()));
  }

  @Test
  public void loadOrGenerateCertificate_missingPrivateKeyArtifact_triggersRegeneration() {
    Injector firstInjector = createTestInjector();
    firstInjector.getInstance(MeasurementBoundCertificateReloader.class).reloadCertificate();

    // Delete private key artifact while leaving cert intact in public bucket
    s3TestClient.deleteFile(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath());
    assertFalse(
        s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath()));

    // Next instance acquires lock, regenerates artifacts, and cleans up lock
    Injector secondInjector = createTestInjector();
    secondInjector.getInstance(MeasurementBoundCertificateReloader.class).reloadCertificate();
    MeasurementBoundCertificateProvider secondProvider =
        secondInjector.getInstance(MeasurementBoundCertificateProvider.class);
    MeasurementBoundCertificate regeneratedMbc = secondProvider.getCertificate();

    assertNotNull(regeneratedMbc);
    assertSame(regeneratedMbc, secondProvider.getCertificate());
    assertTrue(
        s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath()));
    assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getLockPath()));
  }

  @Test
  public void loadOrGenerateCertificate_concurrentInstances_mutualExclusionAndSingleWinner()
      throws Exception {
    int numThreads = 20;
    java.util.concurrent.ExecutorService executor =
        java.util.concurrent.Executors.newFixedThreadPool(numThreads);
    try {
      java.util.List<java.util.concurrent.Callable<MeasurementBoundCertificate>> tasks =
          new java.util.ArrayList<>();
      for (int i = 0; i < numThreads; i++) {
        final int threadId = i;
        tasks.add(
            () -> {
              Injector injector = createTestInjector("i-worker-" + threadId);
              MeasurementBoundCertificateReloader reloader =
                  injector.getInstance(MeasurementBoundCertificateReloader.class);
              MeasurementBoundCertificateProvider provider =
                  injector.getInstance(MeasurementBoundCertificateProvider.class);
              reloader.reloadCertificate();
              MeasurementBoundCertificate cert = provider.getCertificate();
              assertNotNull(cert);
              return cert;
            });
      }

      java.util.List<java.util.concurrent.Future<MeasurementBoundCertificate>> futures =
          executor.invokeAll(tasks);
      java.util.List<MeasurementBoundCertificate> results = new java.util.ArrayList<>();
      for (java.util.concurrent.Future<MeasurementBoundCertificate> future : futures) {
        results.add(future.get());
      }

      // Verify all instances received the exact same generated certificate
      MeasurementBoundCertificate first = results.get(0);
      assertNotNull(first);
      for (int i = 1; i < results.size(); i++) {
        MeasurementBoundCertificate current = results.get(i);
        assertEquals(
            first.getCertificate().getSubjectX500Principal(),
            current.getCertificate().getSubjectX500Principal());
        assertEquals(
            first.getCertificate().getPublicKey(), current.getCertificate().getPublicKey());
        assertArrayEquals(first.getPrivateKey().getEncoded(), current.getPrivateKey().getEncoded());
      }

      // Verify lock file was cleanly released by winner
      assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getLockPath()));
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void loadOrGenerateCertificate_danglingLockManuallyDeleted_recoversAndGeneratesCert()
      throws Exception {
    // Seed an existing dangling lock file in S3 without root.cert to simulate crashed generator
    s3TestClient.putFile(
        PRIVATE_BUCKET,
        bucketProperties.getLockPath(),
        "dangling-lock".getBytes(StandardCharsets.UTF_8));
    assertTrue(s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getLockPath()));

    Injector injector = createTestInjector();
    MeasurementBoundCertificateReloader reloader =
        injector.getInstance(MeasurementBoundCertificateReloader.class);
    MeasurementBoundCertificateProvider provider =
        injector.getInstance(MeasurementBoundCertificateProvider.class);

    java.util.concurrent.ExecutorService executor =
        java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      java.util.concurrent.Future<?> future =
          executor.submit((Runnable) reloader::reloadCertificate);

      // Give the reloader time to start, encounter the lock, and enter the retry loop
      Thread.sleep(600);
      assertFalse(future.isDone());

      // Operator manually deletes the dangling lock file from S3
      s3TestClient.deleteFile(PRIVATE_BUCKET, bucketProperties.getLockPath());
      assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getLockPath()));

      // Waiting reloader should automatically acquire the lock on its next attempt and complete
      future.get(5, java.util.concurrent.TimeUnit.SECONDS);
      MeasurementBoundCertificate certificate = provider.getCertificate();
      assertNotNull(certificate);
      assertSame(certificate, provider.getCertificate());
      assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getCertPath()));
      assertFalse(s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getLockPath()));
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void reloadCertificate_updatesRunningInstanceWhenStorageChangesInBackground()
      throws Exception {
    // 1. Normal operation on Certificate A
    Injector runningInjector = createTestInjector("i-running-1", "CN=Initial MBS Root");
    MeasurementBoundCertificateReloader runningReloader =
        runningInjector.getInstance(MeasurementBoundCertificateReloader.class);
    MeasurementBoundCertificateProvider runningProvider =
        runningInjector.getInstance(MeasurementBoundCertificateProvider.class);

    runningReloader.reloadCertificate();
    MeasurementBoundCertificate certA = runningProvider.getCertificate();
    assertNotNull(certA);
    assertSame(certA, runningProvider.getCertificate());
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
    assertSame(certA, runningProvider.getCertificate());

    // 2. Storage is updated in the background with Certificate B
    // (Simulating rotation: S3 buckets are re-provisioned and populated with new credentials)
    s3TestClient.clearBucket(PUBLIC_BUCKET);
    s3TestClient.clearBucket(PRIVATE_BUCKET);

    Injector rotationInjector = createTestInjector("i-rotator-1", "CN=Rotated MBS Root");
    MeasurementBoundCertificateReloader rotationReloader =
        rotationInjector.getInstance(MeasurementBoundCertificateReloader.class);
    MeasurementBoundCertificateProvider rotationProvider =
        rotationInjector.getInstance(MeasurementBoundCertificateProvider.class);
    rotationReloader.reloadCertificate();
    MeasurementBoundCertificate certB = rotationProvider.getCertificate();
    assertNotNull(certB);
    assertSame(certB, rotationProvider.getCertificate());
    assertEquals("CN=Rotated MBS Root", certB.getCertificate().getSubjectX500Principal().getName());
    assertNotEquals(
        certA.getCertificate().getSerialNumber(), certB.getCertificate().getSerialNumber());

    // Before reload is triggered, running provider still operates on Certificate A
    assertEquals(
        "CN=Initial MBS Root",
        runningProvider.getCertificate().getCertificate().getSubjectX500Principal().getName());
    assertSame(certA, runningProvider.getCertificate());

    // 3. Reload is triggered on the running instance
    runningReloader.reloadCertificate();
    MeasurementBoundCertificate reloadedCert = runningProvider.getCertificate();

    // 4. Verify running provider has updated to Certificate B
    assertNotNull(reloadedCert);
    assertEquals(
        "CN=Rotated MBS Root", reloadedCert.getCertificate().getSubjectX500Principal().getName());
    assertEquals(
        certB.getCertificate().getSerialNumber(), reloadedCert.getCertificate().getSerialNumber());
    assertArrayEquals(
        certB.getPrivateKey().getEncoded(), reloadedCert.getPrivateKey().getEncoded());

    // Verify subsequent wait-free calls return Certificate B atomically
    MeasurementBoundCertificate activeCert = runningProvider.getCertificate();
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
}
