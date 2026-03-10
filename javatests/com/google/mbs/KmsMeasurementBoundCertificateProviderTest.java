/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.util.SecretBytes;
import com.google.kmsclient.KmsClientInterface;
import com.google.kmsclient.KmsGeneratedKey;
import com.google.mbs.attestationcollection.AttestationCollector;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.tlog.TlogEntry;
import com.google.tlog.TransparencyLogClient;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@RunWith(JUnit4.class)
public class KmsMeasurementBoundCertificateProviderTest {

  @Mock private KmsClientInterface kmsClient;
  @Mock private S3Client s3Client;
  @Mock private TransparencyLogClient tlogClient;
  @Mock private AttestationCollector attestationCollector;

  private MeasurementBoundCertificateProvider certificateProvider;
  private static final String BUCKET_NAME = "test-bucket";
  private static final String KMS_KEY_ARN = "test-kms-key-arn";
  private static final String OBJECTS_COMMON_PREFIX = "default/";
  private static final byte[] TEST_USER_DATA = "test_userdata".getBytes(StandardCharsets.UTF_8);

  KeyBackupBucketProperties bucketProperties =
      new KeyBackupBucketPropertiesFactory(BUCKET_NAME).create();

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    certificateProvider =
        new KmsMeasurementBoundCertificateProvider(
            kmsClient,
            s3Client,
            bucketProperties,
            KMS_KEY_ARN,
            TEST_USER_DATA,
            tlogClient,
            attestationCollector);
  }

  @Test
  public void loadOrGenerateCertificate_loadsFromS3() throws Exception {
    KeyPair keyPair = generateKeyPair();
    X509Certificate certificate =
        CertificateGenerator.generateSelfSignedCertificate(keyPair).certificate;

    byte[] plaintextDataKey = generateAesKey();
    byte[] kmsEncryptedDataKey = "kms-encrypted-data-key".getBytes(StandardCharsets.UTF_8);
    byte[] aesEncryptedPrivateKey = encrypt(keyPair.getPrivate().getEncoded(), plaintextDataKey);

    // Mock S3 GetObject calls
    ResponseInputStream<GetObjectResponse> certStream =
        new ResponseInputStream<>(
            GetObjectResponse.builder().build(),
            new ByteArrayInputStream(certificate.getEncoded()));
    when(s3Client.getObject(
            GetObjectRequest.builder()
                .bucket(BUCKET_NAME)
                .key(bucketProperties.getCertPath())
                .build()))
        .thenReturn(certStream);

    ResponseInputStream<GetObjectResponse> kmsKeyStream =
        new ResponseInputStream<>(
            GetObjectResponse.builder().build(), new ByteArrayInputStream(kmsEncryptedDataKey));
    when(s3Client.getObject(
            GetObjectRequest.builder()
                .bucket(BUCKET_NAME)
                .key(bucketProperties.getKmsEncryptedDataKeyPath())
                .build()))
        .thenReturn(kmsKeyStream);

    ResponseInputStream<GetObjectResponse> aesKeyStream =
        new ResponseInputStream<>(
            GetObjectResponse.builder().build(), new ByteArrayInputStream(aesEncryptedPrivateKey));
    when(s3Client.getObject(
            GetObjectRequest.builder()
                .bucket(BUCKET_NAME)
                .key(bucketProperties.getAesEncryptedPrivateKeyPath())
                .build()))
        .thenReturn(aesKeyStream);

    byte[] attestationDocBytes = "attestation-doc".getBytes(StandardCharsets.UTF_8);
    ResponseInputStream<GetObjectResponse> attestationDocStream =
        new ResponseInputStream<>(
            GetObjectResponse.builder().build(), new ByteArrayInputStream(attestationDocBytes));
    when(s3Client.getObject(
            GetObjectRequest.builder()
                .bucket(BUCKET_NAME)
                .key(bucketProperties.getAttestationDocPath())
                .build()))
        .thenReturn(attestationDocStream);

    // Mock KmsClientInterface decrypt call
    when(kmsClient.decrypt(kmsEncryptedDataKey, KMS_KEY_ARN)).thenReturn(plaintextDataKey);

    MeasurementBoundCertificate result = certificateProvider.loadOrGenerateCertificate();

    assertNotNull(result);
    assertEquals(
        certificate.getSubjectX500Principal(), result.getCertificate().getSubjectX500Principal());
    assertArrayEquals(
        certificate.getPublicKey().getEncoded(),
        result.getCertificate().getPublicKey().getEncoded());
    assertArrayEquals(keyPair.getPrivate().getEncoded(), result.getPrivateKey().getEncoded());
    assertEquals(
        Base64.getEncoder().encodeToString(attestationDocBytes),
        result.getAttestationToken().getBase64());
  }

  @Test
  public void loadOrGenerateCertificate_generatesAndStores() throws Exception {
    // Mock S3 GetObject to throw NoSuchKeyException
    when(s3Client.getObject(any(GetObjectRequest.class)))
        .thenThrow(NoSuchKeyException.builder().build());

    // Mock KmsClientInterface generateDataKey call
    byte[] dataKeyPlaintext = generateAesKey();
    byte[] dataKeyCiphertext = "test-ciphertext-key".getBytes(StandardCharsets.UTF_8);
    KmsGeneratedKey kmsGeneratedKey =
        KmsGeneratedKey.builder()
            .setPlaintext(dataKeyPlaintext)
            .setCiphertext(dataKeyCiphertext)
            .build();
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenReturn(kmsGeneratedKey);

    // Mock AttestationCollector call
    byte[] attestationDoc = "Mocked attestation doc".getBytes(StandardCharsets.UTF_8);
    AttestationToken token = AttestationToken.fromBytes(attestationDoc);
    when(attestationCollector.collectBoundToPubkey(any(), any())).thenReturn(token);

    // Mock TransparencyLogClient recordCertificate call
    String tlogEntryJson = "{\"id\": \"test\"}";
    TlogEntry tlogEntry = new TlogEntry(tlogEntryJson);
    when(tlogClient.recordCertificate(any(X509Certificate.class), any(PrivateKey.class)))
        .thenReturn(tlogEntry);

    MeasurementBoundCertificate result = certificateProvider.loadOrGenerateCertificate();

    assertNotNull(result);
    assertNotNull(result.getCertificate());
    assertNotNull(result.getPrivateKey());
    assertEquals(
        Base64.getEncoder().encodeToString(attestationDoc),
        result.getAttestationToken().getBase64());

    // Verify the call to attestationCollector and capture the argument
    ArgumentCaptor<PublicKey> pubkeyBoundToAttestationDocCaptor =
        ArgumentCaptor.forClass(PublicKey.class);
    verify(attestationCollector)
        .collectBoundToPubkey(pubkeyBoundToAttestationDocCaptor.capture(), eq(TEST_USER_DATA));
    assertEquals(
        result.getCertificate().getPublicKey(), pubkeyBoundToAttestationDocCaptor.getValue());

    // Verify that the generated cert and keys were stored in S3
    ArgumentCaptor<PutObjectRequest> putRequestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    ArgumentCaptor<RequestBody> requestBodyCaptor = ArgumentCaptor.forClass(RequestBody.class);

    verify(s3Client, times(5)).putObject(putRequestCaptor.capture(), requestBodyCaptor.capture());

    // Find the request that stored the KMS encrypted data key and assert on it
    boolean kmsKeyFound = false;
    boolean tlogEntryFound = false;
    boolean certFound = false;
    boolean attestationDocFound = false;
    for (int i = 0; i < putRequestCaptor.getAllValues().size(); i++) {
      String key = putRequestCaptor.getAllValues().get(i).key();
      byte[] content =
          requestBodyCaptor
              .getAllValues()
              .get(i)
              .contentStreamProvider()
              .newStream()
              .readAllBytes();
      if (key.equals(bucketProperties.getKmsEncryptedDataKeyPath())) {
        assertEquals(BUCKET_NAME, putRequestCaptor.getAllValues().get(i).bucket());
        assertArrayEquals(dataKeyCiphertext, content);
        kmsKeyFound = true;
      } else if (key.equals(bucketProperties.getTlogEntryPath())) {
        assertEquals(BUCKET_NAME, putRequestCaptor.getAllValues().get(i).bucket());
        assertArrayEquals(tlogEntryJson.getBytes(StandardCharsets.UTF_8), content);
        tlogEntryFound = true;
      } else if (key.equals(bucketProperties.getCertPath())) {
        assertEquals(BUCKET_NAME, putRequestCaptor.getAllValues().get(i).bucket());
        assertArrayEquals(result.getCertificate().getEncoded(), content);
        certFound = true;
      } else if (key.equals(bucketProperties.getAttestationDocPath())) {
        assertEquals(BUCKET_NAME, putRequestCaptor.getAllValues().get(i).bucket());
        assertArrayEquals(attestationDoc, content);
        attestationDocFound = true;
      }
    }
    if (!kmsKeyFound) fail("Could not find PutObjectRequest for KMS encrypted data key");
    if (!tlogEntryFound) fail("Could not find PutObjectRequest for Tlog entry");
    if (!certFound) fail("Could not find PutObjectRequest for cert");
    if (!attestationDocFound) fail("Could not find PutObjectRequest for attestationDoc");
  }

  @Test
  public void loadOrGenerateCertificate_reconcilesMissingTlogEntry() throws Exception {
    KeyPair keyPair = generateKeyPair();
    X509Certificate certificate =
        CertificateGenerator.generateSelfSignedCertificate(keyPair).certificate;

    byte[] plaintextDataKey = generateAesKey();
    byte[] kmsEncryptedDataKey = "kms-encrypted-data-key".getBytes(StandardCharsets.UTF_8);
    byte[] aesEncryptedPrivateKey = encrypt(keyPair.getPrivate().getEncoded(), plaintextDataKey);

    // Mock S3 GetObject calls for cert and key
    ResponseInputStream<GetObjectResponse> certStream =
        new ResponseInputStream<>(
            GetObjectResponse.builder().build(),
            new ByteArrayInputStream(certificate.getEncoded()));
    when(s3Client.getObject(
            GetObjectRequest.builder()
                .bucket(BUCKET_NAME)
                .key(bucketProperties.getCertPath())
                .build()))
        .thenReturn(certStream);

    ResponseInputStream<GetObjectResponse> kmsKeyStream =
        new ResponseInputStream<>(
            GetObjectResponse.builder().build(), new ByteArrayInputStream(kmsEncryptedDataKey));
    when(s3Client.getObject(
            GetObjectRequest.builder()
                .bucket(BUCKET_NAME)
                .key(bucketProperties.getKmsEncryptedDataKeyPath())
                .build()))
        .thenReturn(kmsKeyStream);

    ResponseInputStream<GetObjectResponse> aesKeyStream =
        new ResponseInputStream<>(
            GetObjectResponse.builder().build(), new ByteArrayInputStream(aesEncryptedPrivateKey));
    when(s3Client.getObject(
            GetObjectRequest.builder()
                .bucket(BUCKET_NAME)
                .key(bucketProperties.getAesEncryptedPrivateKeyPath())
                .build()))
        .thenReturn(aesKeyStream);

    byte[] attestationDocBytes = "attestation-doc".getBytes(StandardCharsets.UTF_8);
    ResponseInputStream<GetObjectResponse> attestationDocStream =
        new ResponseInputStream<>(
            GetObjectResponse.builder().build(), new ByteArrayInputStream(attestationDocBytes));
    when(s3Client.getObject(
            GetObjectRequest.builder()
                .bucket(BUCKET_NAME)
                .key(bucketProperties.getAttestationDocPath())
                .build()))
        .thenReturn(attestationDocStream);

    // Mock KmsClientInterface decrypt call
    when(kmsClient.decrypt(kmsEncryptedDataKey, KMS_KEY_ARN)).thenReturn(plaintextDataKey);

    // Mock S3 headObject to indicate tlog entry is missing
    when(s3Client.headObject(any(HeadObjectRequest.class))) // Specify the class
        .thenAnswer(
            invocation -> {
              HeadObjectRequest req = invocation.getArgument(0);
              if (BUCKET_NAME.equals(req.bucket())
                  && bucketProperties.getTlogEntryPath().equals(req.key())) {
                throw NoSuchKeyException.builder().build();
              }
              return software.amazon.awssdk.services.s3.model.HeadObjectResponse.builder().build();
            });

    // Mock TransparencyLogClient getTlogEntryByCertificate call
    String reconciledTlogJson = "{\"id\": \"reconciled\"}";
    TlogEntry reconciledTlogEntry = new TlogEntry(reconciledTlogJson);
    when(tlogClient.getTlogEntryByCertificate(certificate))
        .thenReturn(Optional.of(reconciledTlogEntry));

    MeasurementBoundCertificate result = certificateProvider.loadOrGenerateCertificate();
    assertEquals(
        Base64.getEncoder().encodeToString(attestationDocBytes),
        result.getAttestationToken().getBase64());

    // Verify that the reconciled tlog entry was stored in S3
    ArgumentCaptor<PutObjectRequest> putRequestCaptor =
        ArgumentCaptor.forClass(PutObjectRequest.class);
    ArgumentCaptor<RequestBody> requestBodyCaptor = ArgumentCaptor.forClass(RequestBody.class);

    verify(s3Client).putObject(putRequestCaptor.capture(), requestBodyCaptor.capture());

    assertEquals(BUCKET_NAME, putRequestCaptor.getValue().bucket());
    assertEquals(bucketProperties.getTlogEntryPath(), putRequestCaptor.getValue().key());
    assertArrayEquals(
        reconciledTlogJson.getBytes(StandardCharsets.UTF_8),
        requestBodyCaptor.getValue().contentStreamProvider().newStream().readAllBytes());
    verify(tlogClient).getTlogEntryByCertificate(certificate);
  }

  private KeyPair generateKeyPair() throws GeneralSecurityException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  private byte[] generateAesKey() throws GeneralSecurityException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    SecretKey secretKey = keyGen.generateKey();
    return secretKey.getEncoded();
  }

  private byte[] encrypt(byte[] plaintext, byte[] key) throws GeneralSecurityException {
    return getAead(key).encrypt(plaintext, new byte[0]);
  }

  @AccessesPartialKey
  private Aead getAead(byte[] key) throws GeneralSecurityException {

    AesGcmKey aesGcmkey =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES256_GCM)
            .setKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
            .setIdRequirement(1)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmkey).withFixedId(1).makePrimary())
            .build();
    return keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
  }
}
