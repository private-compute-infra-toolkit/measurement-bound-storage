/*
 * Copyright 2025 Google LLC
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
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
import com.google.kmsclient.KmsException;
import com.google.kmsclient.KmsGeneratedKey;
import com.google.mbs.attestationcollection.AttestationCollector;
import com.google.mbs.attestationcollection.AttestationToken;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class KmsMeasurementBoundCertificateProviderTest {

  @Mock private KmsClientInterface kmsClient;
  @Mock private KeyBackupStorage storage;
  @Mock private AttestationCollector attestationCollector;
  @Mock private Metrics mockMetrics;

  private MeasurementBoundCertificateProvider certificateProvider;
  private static final String KMS_KEY_ARN = "test-kms-key-arn";
  private static final byte[] TEST_USER_DATA = "test_userdata".getBytes(StandardCharsets.UTF_8);

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory certificateFactory =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            spec,
            new X500Name("CN=Test CA"),
            Duration.ofDays(30),
            Optional.empty(),
            KeyUsage.keyCertSign);

    certificateProvider =
        new KmsMeasurementBoundCertificateProvider(
            kmsClient,
            storage,
            KMS_KEY_ARN,
            TEST_USER_DATA,
            attestationCollector,
            certificateFactory,
            mockMetrics);
  }

  @FunctionalInterface
  private interface CertificateEncoder {
    byte[] encode(X509Certificate certificate) throws Exception;
  }

  private void runLoadOrGenerateCertificate_loadsFromStorageTest(CertificateEncoder encoder)
      throws Exception {
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
                spec,
                new X500Name("CN=Test CA"),
                Duration.ofDays(30),
                Optional.empty(),
                KeyUsage.keyCertSign)
            .generate();
    X509Certificate certificate = certAndKey.certificate();
    PrivateKey privateKey = certAndKey.privateKey();

    byte[] plaintextDataKey = generateAesKey();
    byte[] kmsEncryptedDataKey = "kms-encrypted-data-key".getBytes(StandardCharsets.UTF_8);
    byte[] aesEncryptedPrivateKey = encrypt(privateKey.getEncoded(), plaintextDataKey);
    byte[] attestationDocBytes = "attestation-doc".getBytes(StandardCharsets.UTF_8);

    when(storage.getCertBytes()).thenReturn(encoder.encode(certificate));
    when(storage.getKmsEncryptedDataKey()).thenReturn(kmsEncryptedDataKey);
    when(storage.getAeadEncryptedPrivateKey()).thenReturn(aesEncryptedPrivateKey);
    when(storage.getAttestationDocBytes()).thenReturn(attestationDocBytes);
    when(kmsClient.decrypt(kmsEncryptedDataKey, KMS_KEY_ARN)).thenReturn(plaintextDataKey);

    MeasurementBoundCertificate result = certificateProvider.loadOrGenerateCertificate();

    assertNotNull(result);
    assertEquals(
        certificate.getSubjectX500Principal(), result.getCertificate().getSubjectX500Principal());
    assertArrayEquals(
        certificate.getPublicKey().getEncoded(),
        result.getCertificate().getPublicKey().getEncoded());
    assertArrayEquals(privateKey.getEncoded(), result.getPrivateKey().getEncoded());
    assertEquals(
        Base64.getEncoder().encodeToString(attestationDocBytes),
        result.getAttestationToken().getBase64());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void loadOrGenerateCertificate_loadsFromStorageDer() throws Exception {
    runLoadOrGenerateCertificate_loadsFromStorageTest(X509Certificate::getEncoded);
  }

  @Test
  public void loadOrGenerateCertificate_loadsFromStoragePem() throws Exception {
    runLoadOrGenerateCertificate_loadsFromStorageTest(
        KmsMeasurementBoundCertificateProvider::toPemBytes);
  }

  @Test
  public void loadOrGenerateCertificate_generatesAndStores() throws Exception {
    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));

    byte[] dataKeyPlaintext = generateAesKey();
    byte[] dataKeyCiphertext = "test-ciphertext-key".getBytes(StandardCharsets.UTF_8);
    KmsGeneratedKey kmsGeneratedKey =
        KmsGeneratedKey.builder()
            .setPlaintext(dataKeyPlaintext)
            .setCiphertext(dataKeyCiphertext)
            .build();
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenReturn(kmsGeneratedKey);

    byte[] attestationDoc = "Mocked attestation doc".getBytes(StandardCharsets.UTF_8);
    AttestationToken token = AttestationToken.fromBytes(attestationDoc);
    when(attestationCollector.collectBoundToPubkey(any(), any())).thenReturn(token);

    MeasurementBoundCertificate result = certificateProvider.loadOrGenerateCertificate();

    assertNotNull(result);
    assertNotNull(result.getCertificate());
    assertNotNull(result.getPrivateKey());
    assertEquals("CN=Test CA", result.getCertificate().getSubjectX500Principal().getName());
    assertEquals(
        Base64.getEncoder().encodeToString(attestationDoc),
        result.getAttestationToken().getBase64());

    ArgumentCaptor<PublicKey> pubkeyBoundToAttestationDocCaptor =
        ArgumentCaptor.forClass(PublicKey.class);
    verify(attestationCollector)
        .collectBoundToPubkey(pubkeyBoundToAttestationDocCaptor.capture(), eq(TEST_USER_DATA));
    assertEquals(
        result.getCertificate().getPublicKey(), pubkeyBoundToAttestationDocCaptor.getValue());

    verify(storage).putAeadEncryptedPrivateKey(any(byte[].class));
    verify(storage).putKmsEncryptedDataKey(eq(dataKeyCiphertext));
    verify(storage)
        .putCertBytes(
            eq(KmsMeasurementBoundCertificateProvider.toPemBytes(result.getCertificate())));
    verify(storage).putAttestationDocBytes(eq(attestationDoc));
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void loadOrGenerateCertificate_withCustomConfig_generatesCustomCert() throws Exception {
    Date notBefore = Date.from(Instant.now().minus(Duration.ofDays(1)));
    Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(30)));
    int expectedPathLen = 5;
    boolean[] keyUsage = new boolean[9];
    keyUsage[0] = true; // digitalSignature
    keyUsage[5] = true; // keyCertSign

    MbsCertificateFactory customBuilder =
        () -> {
          KeyPair keyPair;
          try {
            keyPair = generateKeyPair();
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          X509Certificate mockCert = mock(X509Certificate.class);
          X500Principal subjectPrincipal = new X500Principal("CN=Custom Service");
          X500Principal issuerPrincipal = new X500Principal("CN=Custom Issuer");

          when(mockCert.getSubjectX500Principal()).thenReturn(subjectPrincipal);
          when(mockCert.getIssuerX500Principal()).thenReturn(issuerPrincipal);
          when(mockCert.getPublicKey()).thenReturn(keyPair.getPublic());
          when(mockCert.getNotBefore()).thenReturn(notBefore);
          when(mockCert.getNotAfter()).thenReturn(notAfter);
          when(mockCert.getKeyUsage()).thenReturn(keyUsage);
          when(mockCert.getBasicConstraints()).thenReturn(expectedPathLen); // pathLenConstraint

          try {
            when(mockCert.getEncoded()).thenReturn("custom-cert-bytes".getBytes());
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          return new MbsCertificateFactory.X509CertificateAndPrivateKey(
              mockCert, keyPair.getPrivate());
        };

    MeasurementBoundCertificateProvider customProvider =
        new KmsMeasurementBoundCertificateProvider(
            kmsClient,
            storage,
            KMS_KEY_ARN,
            TEST_USER_DATA,
            attestationCollector,
            customBuilder,
            mockMetrics);

    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));

    byte[] dataKeyPlaintext = generateAesKey();
    byte[] dataKeyCiphertext = "test-ciphertext-key".getBytes(StandardCharsets.UTF_8);
    KmsGeneratedKey kmsGeneratedKey =
        KmsGeneratedKey.builder()
            .setPlaintext(dataKeyPlaintext)
            .setCiphertext(dataKeyCiphertext)
            .build();
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenReturn(kmsGeneratedKey);

    byte[] attestationDoc = "Custom attestation doc".getBytes(StandardCharsets.UTF_8);
    AttestationToken token = AttestationToken.fromBytes(attestationDoc);
    when(attestationCollector.collectBoundToPubkey(any(), any())).thenReturn(token);

    MeasurementBoundCertificate result = customProvider.loadOrGenerateCertificate();

    assertNotNull(result);
    assertEquals("CN=Custom Service", result.getCertificate().getSubjectX500Principal().getName());
    assertEquals("CN=Custom Issuer", result.getCertificate().getIssuerX500Principal().getName());
    assertEquals(notBefore, result.getCertificate().getNotBefore());
    assertEquals(notAfter, result.getCertificate().getNotAfter());
    assertArrayEquals(keyUsage, result.getCertificate().getKeyUsage());
    assertEquals(expectedPathLen, result.getCertificate().getBasicConstraints());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void loadOrGenerateCertificate_builderThrowsRuntimeException_propagatesWrappedError()
      throws Exception {
    MbsCertificateFactory throwingBuilder =
        () -> {
          throw new RuntimeException("Simulated builder failure");
        };

    MeasurementBoundCertificateProvider customProvider =
        new KmsMeasurementBoundCertificateProvider(
            kmsClient,
            storage,
            KMS_KEY_ARN,
            TEST_USER_DATA,
            attestationCollector,
            throwingBuilder,
            mockMetrics);

    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));

    byte[] dataKeyPlaintext = generateAesKey();
    byte[] dataKeyCiphertext = "test-ciphertext-key".getBytes(StandardCharsets.UTF_8);
    KmsGeneratedKey kmsGeneratedKey =
        KmsGeneratedKey.builder()
            .setPlaintext(dataKeyPlaintext)
            .setCiphertext(dataKeyCiphertext)
            .build();
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenReturn(kmsGeneratedKey);

    assertThrows(
        RuntimeException.class,
        () -> {
          customProvider.loadOrGenerateCertificate();
        });
    org.mockito.Mockito.verifyNoInteractions(mockMetrics);
  }

  @Test
  public void loadOrGenerateCertificate_factoryReturnsNonRsaCert_throwsIllegalArgumentException()
      throws Exception {
    MbsCertificateFactory invalidBuilder =
        () -> {
          KeyPair keyPair;
          try {
            keyPair = generateKeyPair();
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          X509Certificate mockCert = mock(X509Certificate.class);
          PublicKey mockPubKey = mock(PublicKey.class);
          when(mockPubKey.getAlgorithm()).thenReturn("EC");
          when(mockCert.getPublicKey()).thenReturn(mockPubKey);
          try {
            when(mockCert.getEncoded()).thenReturn("invalid-cert-bytes".getBytes());
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          return new MbsCertificateFactory.X509CertificateAndPrivateKey(
              mockCert, keyPair.getPrivate());
        };

    MeasurementBoundCertificateProvider customProvider =
        new KmsMeasurementBoundCertificateProvider(
            kmsClient,
            storage,
            KMS_KEY_ARN,
            TEST_USER_DATA,
            attestationCollector,
            invalidBuilder,
            mockMetrics);

    // Mock collectBoundToPubkey to throw IllegalArgumentException for non-RSA keys
    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenThrow(new IllegalArgumentException("Only RSA keys are supported"));
    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));

    byte[] dataKeyPlaintext = generateAesKey();
    KmsGeneratedKey kmsGeneratedKey =
        KmsGeneratedKey.builder()
            .setPlaintext(dataKeyPlaintext)
            .setCiphertext("test-ciphertext-key".getBytes())
            .build();
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenReturn(kmsGeneratedKey);

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          customProvider.loadOrGenerateCertificate();
        });
    org.mockito.Mockito.verifyNoInteractions(mockMetrics);
  }

  @Test
  public void loadOrGenerateCertificate_storageThrowsException_propagatesWrappedError()
      throws Exception {
    when(storage.getCertBytes())
        .thenThrow(new KeyBackupStorageException("Storage connection error"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.loadOrGenerateCertificate();
        });
  }

  @Test
  public void loadOrGenerateCertificate_kmsDecryptFails_reportsKmsOperationFailed()
      throws Exception {
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
                spec,
                new X500Name("CN=Test CA"),
                Duration.ofDays(30),
                Optional.empty(),
                KeyUsage.keyCertSign)
            .generate();
    X509Certificate certificate = certAndKey.certificate();
    PrivateKey privateKey = certAndKey.privateKey();

    byte[] plaintextDataKey = generateAesKey();
    byte[] kmsEncryptedDataKey = "kms-encrypted-data-key".getBytes(StandardCharsets.UTF_8);
    byte[] aesEncryptedPrivateKey = encrypt(privateKey.getEncoded(), plaintextDataKey);

    // Setup storage to return cert and encrypted keys (so we get to KMS decrypt)
    when(storage.getCertBytes()).thenReturn(certificate.getEncoded());
    when(storage.getKmsEncryptedDataKey()).thenReturn(kmsEncryptedDataKey);
    // Mock KMS decrypt to throw KmsException
    when(kmsClient.decrypt(kmsEncryptedDataKey, KMS_KEY_ARN))
        .thenThrow(new KmsException("KMS error"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.loadOrGenerateCertificate();
        });

    verify(mockMetrics).recordEvent(Metrics.MbsEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void loadOrGenerateCertificate_kmsGenerateKeyFails_reportsKmsOperationFailed()
      throws Exception {
    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));
    // Mock KMS generateDataKey to throw KmsException
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenThrow(new KmsException("KMS error"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.loadOrGenerateCertificate();
        });

    verify(mockMetrics).recordEvent(Metrics.MbsEvent.KMS_OPERATION_FAILED);
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
    AesGcmKey aesGcmKey =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES256_GCM)
            .setKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
            .setIdRequirement(1)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmKey).withFixedId(1).makePrimary())
            .build();
    return keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
  }
}
