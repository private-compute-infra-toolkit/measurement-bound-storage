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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.kmsclient.KmsClientInterface;
import com.google.mbs.attestationcollection.AttestationCollector;
import com.google.mbs.qualifier.AttestationUserData;
import com.google.mbs.qualifier.KmsKeyArn;
import com.google.mbs.qualifier.MbsRoot;
import com.google.mbs.qualifier.PrivateBackupBucket;
import com.google.mbs.qualifier.PublicBackupBucket;
import com.google.mbs.testing.FakeAttestationCollector;
import com.google.mbs.testing.FakeKmsClient;
import com.google.mbs.testing.S3TestClient;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
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
  }

  private Injector createTestInjector() {
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory certFactory =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            spec,
            new X500Name("CN=Test MBS Root"),
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

    MeasurementBoundCertificate mbc = provider.loadOrGenerateCertificate();

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

    // Verify stored certificate matches returned certificate
    byte[] storedCertBytes = s3TestClient.getFile(PUBLIC_BUCKET, bucketProperties.getCertPath());
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate storedCert =
        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(storedCertBytes));
    assertEquals(mbc.getCertificate().getPublicKey(), storedCert.getPublicKey());

    // Verify root cert and key bindings provided by MbsCoreModule
    X509Certificate rootCert =
        injector.getInstance(com.google.inject.Key.get(X509Certificate.class, MbsRoot.class));
    PrivateKey rootKey =
        injector.getInstance(com.google.inject.Key.get(PrivateKey.class, MbsRoot.class));
    assertEquals(mbc.getCertificate(), rootCert);
    assertEquals(mbc.getPrivateKey(), rootKey);
  }

  @Test
  public void loadOrGenerateCertificate_existingStorage_loadsStoredCertificate() throws Exception {
    // Generate initial certificate and artifacts in S3
    Injector firstInjector = createTestInjector();
    MeasurementBoundCertificateProvider firstProvider =
        firstInjector.getInstance(MeasurementBoundCertificateProvider.class);
    MeasurementBoundCertificate initialMbc = firstProvider.loadOrGenerateCertificate();

    byte[] initialCertBytes = s3TestClient.getFile(PUBLIC_BUCKET, bucketProperties.getCertPath());
    byte[] initialKmsKeyBytes =
        s3TestClient.getFile(PRIVATE_BUCKET, bucketProperties.getKmsEncryptedDataKeyPath());
    byte[] initialAesKeyBytes =
        s3TestClient.getFile(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath());

    // Create a second injector and provider simulating a fresh enclave start
    Injector secondInjector = createTestInjector();
    MeasurementBoundCertificateProvider secondProvider =
        secondInjector.getInstance(MeasurementBoundCertificateProvider.class);

    MeasurementBoundCertificate loadedMbc = secondProvider.loadOrGenerateCertificate();

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
    firstInjector.getInstance(MeasurementBoundCertificate.class);

    // Delete the root cert from S3
    s3TestClient.deleteFile(PUBLIC_BUCKET, bucketProperties.getCertPath());
    assertFalse(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getCertPath()));

    // Fresh start should regenerate all artifacts
    Injector secondInjector = createTestInjector();
    MeasurementBoundCertificateProvider secondProvider =
        secondInjector.getInstance(MeasurementBoundCertificateProvider.class);
    MeasurementBoundCertificate regeneratedMbc = secondProvider.loadOrGenerateCertificate();

    assertNotNull(regeneratedMbc);
    assertTrue(s3TestClient.fileExists(PUBLIC_BUCKET, bucketProperties.getCertPath()));
  }

  @Test
  public void loadOrGenerateCertificate_missingPrivateKeyArtifact_triggersRegeneration() {
    Injector firstInjector = createTestInjector();
    firstInjector.getInstance(MeasurementBoundCertificate.class);

    // Delete private key artifact while leaving cert intact in public bucket
    s3TestClient.deleteFile(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath());
    assertFalse(
        s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath()));

    // Next instance detects missing artifact via KeyBackupNotFoundException and regenerates
    Injector secondInjector = createTestInjector();
    MeasurementBoundCertificateProvider secondProvider =
        secondInjector.getInstance(MeasurementBoundCertificateProvider.class);

    MeasurementBoundCertificate regeneratedMbc = secondProvider.loadOrGenerateCertificate();

    assertNotNull(regeneratedMbc);
    assertTrue(
        s3TestClient.fileExists(PRIVATE_BUCKET, bucketProperties.getAesEncryptedPrivateKeyPath()));
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
