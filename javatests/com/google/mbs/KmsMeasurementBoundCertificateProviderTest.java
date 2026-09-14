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

import static com.google.mbs.domain.Metrics.ReloadStatus.FAILURE;
import static com.google.mbs.domain.Metrics.ReloadStatus.SUCCESS;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import com.google.mbs.domain.AttestationCollector;
import com.google.mbs.domain.AttestationToken;
import com.google.mbs.domain.KeyBackupNotFoundException;
import com.google.mbs.domain.KeyBackupStorage;
import com.google.mbs.domain.KeyBackupStorageException;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.KmsGeneratedKey;
import com.google.mbs.domain.MeasurementBoundCertificate;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.StorageAlreadyLockedException;
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

  private KmsMeasurementBoundCertificateProvider certificateProvider;
  private static final String KMS_KEY_ARN = "test-kms-key-arn";
  private static final byte[] TEST_USER_DATA = "test_userdata".getBytes(StandardCharsets.UTF_8);

  @Before
  public void setUp() throws Exception {
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
    certificateProvider.initialRetryBackoff = Duration.ZERO;
    certificateProvider.maxRetryBackoff = Duration.ZERO;
    certificateProvider.maxLoadRetries = 3;
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

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = certificateProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, certificateProvider.getCertificate());
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

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = certificateProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, certificateProvider.getCertificate());
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

    KmsMeasurementBoundCertificateProvider customProvider =
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

    customProvider.reloadCertificate();
    MeasurementBoundCertificate result = customProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, customProvider.getCertificate());
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

    KmsMeasurementBoundCertificateProvider customProvider =
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
          customProvider.reloadCertificate();
        });
    verify(mockMetrics).setReloadStatus(FAILURE);
    verify(mockMetrics, never()).recordEvent(any());
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

    KmsMeasurementBoundCertificateProvider customProvider =
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
          customProvider.reloadCertificate();
        });
    verify(mockMetrics).setReloadStatus(FAILURE);
    verify(mockMetrics, never()).recordEvent(any());
  }

  @Test
  public void loadOrGenerateCertificate_storageThrowsException_propagatesWrappedError()
      throws Exception {
    when(storage.getCertBytes())
        .thenThrow(new KeyBackupStorageException("Storage connection error"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.reloadCertificate();
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
          certificateProvider.reloadCertificate();
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
          certificateProvider.reloadCertificate();
        });

    verify(mockMetrics).recordEvent(Metrics.MbsEvent.KMS_OPERATION_FAILED);
  }

  @Test
  public void loadOrGenerateCertificate_emptyStorage_acquiresLockAndGeneratesCert()
      throws Exception {
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

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = certificateProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, certificateProvider.getCertificate());
    verify(storage).acquireLock();
    verify(storage)
        .putCertBytes(
            eq(KmsMeasurementBoundCertificateProvider.toPemBytes(result.getCertificate())));
    verify(storage).releaseLock();
  }

  @Test
  public void loadOrGenerateCertificate_generationFails_doesNotReleaseLock() throws Exception {
    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenThrow(new KmsException("KMS error"));

    assertThrows(
        RuntimeException.class,
        () -> {
          certificateProvider.reloadCertificate();
        });

    verify(storage, never()).releaseLock();
  }

  @Test
  public void loadOrGenerateCertificate_loadedUnderLock_releasesLock() throws Exception {
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

    byte[] dataKeyPlaintext = generateAesKey();
    byte[] dataKeyCiphertext = "test-ciphertext-key".getBytes(StandardCharsets.UTF_8);
    byte[] aeadEncryptedPrivateKey = encrypt(privateKey.getEncoded(), dataKeyPlaintext);

    // Initial check fails, but check after acquiring lock succeeds
    when(storage.getCertBytes())
        .thenThrow(new KeyBackupNotFoundException("Cert not found"))
        .thenReturn(KmsMeasurementBoundCertificateProvider.toPemBytes(certificate));
    when(storage.getKmsEncryptedDataKey()).thenReturn(dataKeyCiphertext);
    when(kmsClient.decrypt(dataKeyCiphertext, KMS_KEY_ARN)).thenReturn(dataKeyPlaintext);
    when(storage.getAeadEncryptedPrivateKey()).thenReturn(aeadEncryptedPrivateKey);
    when(storage.getAttestationDocBytes())
        .thenReturn("Attestation doc".getBytes(StandardCharsets.UTF_8));

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = certificateProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, certificateProvider.getCertificate());
    verify(storage).acquireLock();
    verify(storage).releaseLock();
    verify(kmsClient, never()).generateDataKey(any());
  }

  @Test
  public void loadOrGenerateCertificate_alreadyLocked_waitsAndLoadsWinnerCert() throws Exception {
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

    when(storage.getCertBytes())
        .thenThrow(new KeyBackupNotFoundException("Cert not found on initial attempt"))
        .thenThrow(new KeyBackupNotFoundException("Cert not found on first retry"))
        .thenReturn(KmsMeasurementBoundCertificateProvider.toPemBytes(certificate));

    doThrow(new StorageAlreadyLockedException("Already locked")).when(storage).acquireLock();
    when(storage.getKmsEncryptedDataKey()).thenReturn(kmsEncryptedDataKey);
    when(storage.getAeadEncryptedPrivateKey()).thenReturn(aesEncryptedPrivateKey);
    when(storage.getAttestationDocBytes()).thenReturn(attestationDocBytes);
    when(kmsClient.decrypt(kmsEncryptedDataKey, KMS_KEY_ARN)).thenReturn(plaintextDataKey);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = certificateProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, certificateProvider.getCertificate());
    assertEquals("CN=Test CA", result.getCertificate().getSubjectX500Principal().getName());
    // Verify that KMS generateDataKey was NEVER called since this instance lost the lock
    verify(kmsClient, never()).generateDataKey(any());
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void loadOrGenerateCertificate_danglingLockDeleted_recoversAndAcquiresLock()
      throws Exception {
    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));

    // First attempt fails to acquire lock (simulating dangling lock), second attempt succeeds
    doThrow(new StorageAlreadyLockedException("Already locked"))
        .doNothing()
        .when(storage)
        .acquireLock();

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

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = certificateProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, certificateProvider.getCertificate());
    // Verified it attempted lock twice, generated keys, wrote artifacts, and released lock
    verify(storage, times(2)).acquireLock();
    verify(storage).releaseLock();
    verify(kmsClient).generateDataKey(KMS_KEY_ARN);
  }

  @Test
  public void loadOrGenerateCertificate_waitLoopMaxRetriesExceeded_throwsIllegalStateException()
      throws Exception {
    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));
    doThrow(new StorageAlreadyLockedException("Already locked")).when(storage).acquireLock();

    assertThrows(
        IllegalStateException.class,
        () -> {
          certificateProvider.reloadCertificate();
        });
  }

  @Test
  public void loadOrGenerateCertificate_lockContention_emitsWaitingForMbsLockEvent()
      throws Exception {
    certificateProvider.maxLoadRetries = 3;
    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));
    doThrow(new StorageAlreadyLockedException("Already locked")).when(storage).acquireLock();

    assertThrows(
        IllegalStateException.class,
        () -> {
          certificateProvider.reloadCertificate();
        });

    verify(mockMetrics, times(3)).recordEvent(Metrics.MbsEvent.WAITING_FOR_MBS_LOCK);
    verify(mockMetrics, never()).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void loadOrGenerateCertificate_noLockContention_doesNotEmitWaitingForMbsLockEvent()
      throws Exception {
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

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = certificateProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, certificateProvider.getCertificate());
    verify(mockMetrics, never()).recordEvent(Metrics.MbsEvent.WAITING_FOR_MBS_LOCK);
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
  }

  @Test
  public void loadOrGenerateCertificate_lockContentionThenRecovers_emitsWaitingThenSuccess()
      throws Exception {
    certificateProvider.maxLoadRetries = 5;
    when(storage.getCertBytes()).thenThrow(new KeyBackupNotFoundException("Cert not found"));

    int[] lockAttempts = new int[1];
    doAnswer(
            invocation -> {
              if (++lockAttempts[0] <= 2) {
                throw new StorageAlreadyLockedException("Already locked");
              }
              return null;
            })
        .when(storage)
        .acquireLock();

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

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate result = certificateProvider.getCertificate();

    assertNotNull(result);
    assertSame(result, certificateProvider.getCertificate());
    // Attempts 1 and 2 encountered lock contention, emitting WAITING_FOR_MBS_LOCK before succeeding
    // on
    // attempt 3
    verify(mockMetrics, times(2)).recordEvent(Metrics.MbsEvent.WAITING_FOR_MBS_LOCK);
    verify(mockMetrics).recordEvent(Metrics.MbsEvent.SUCCESS);
    verify(storage).releaseLock();
  }

  @Test
  public void reloadCertificate_updatesCertificateWhenStorageChanges() throws Exception {
    MbsCertificateFactory.CertSignatureSpec spec =
        new MbsCertificateFactory.CertSignatureSpec("RSA", 2048, "SHA256withRSA");
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey1 =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
                spec,
                new X500Name("CN=Test CA 1"),
                Duration.ofDays(30),
                Optional.empty(),
                KeyUsage.keyCertSign)
            .generate();
    byte[] plaintextDataKey1 = generateAesKey();
    byte[] kmsKey1 = "kms-key-1".getBytes(StandardCharsets.UTF_8);
    byte[] encPrivKey1 = encrypt(certAndKey1.privateKey().getEncoded(), plaintextDataKey1);

    when(storage.getCertBytes()).thenReturn(certAndKey1.certificate().getEncoded());
    when(storage.getKmsEncryptedDataKey()).thenReturn(kmsKey1);
    when(storage.getAeadEncryptedPrivateKey()).thenReturn(encPrivKey1);
    when(storage.getAttestationDocBytes())
        .thenReturn("attestation-1".getBytes(StandardCharsets.UTF_8));
    when(kmsClient.decrypt(kmsKey1, KMS_KEY_ARN)).thenReturn(plaintextDataKey1);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate initial = certificateProvider.getCertificate();
    assertNotNull(initial);
    assertEquals("CN=Test CA 1", initial.getCertificate().getSubjectX500Principal().getName());

    // Storage is updated with a rotated certificate
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey2 =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
                spec,
                new X500Name("CN=Test CA 2"),
                Duration.ofDays(30),
                Optional.empty(),
                KeyUsage.keyCertSign)
            .generate();
    byte[] plaintextDataKey2 = generateAesKey();
    byte[] kmsKey2 = "kms-key-2".getBytes(StandardCharsets.UTF_8);
    byte[] encPrivKey2 = encrypt(certAndKey2.privateKey().getEncoded(), plaintextDataKey2);

    when(storage.getCertBytes()).thenReturn(certAndKey2.certificate().getEncoded());
    when(storage.getKmsEncryptedDataKey()).thenReturn(kmsKey2);
    when(storage.getAeadEncryptedPrivateKey()).thenReturn(encPrivKey2);
    when(storage.getAttestationDocBytes())
        .thenReturn("attestation-2".getBytes(StandardCharsets.UTF_8));
    when(kmsClient.decrypt(kmsKey2, KMS_KEY_ARN)).thenReturn(plaintextDataKey2);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate reloaded = certificateProvider.getCertificate();
    assertNotNull(reloaded);
    assertEquals("CN=Test CA 2", reloaded.getCertificate().getSubjectX500Principal().getName());
    assertEquals(
        "CN=Test CA 2",
        certificateProvider.getCertificate().getCertificate().getSubjectX500Principal().getName());
    verify(mockMetrics, atLeastOnce()).setReloadStatus(SUCCESS);
  }

  @Test
  public void reloadCertificate_failureThrowsAndRetainsActiveCertificate() throws Exception {
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
    byte[] plaintextDataKey = generateAesKey();
    byte[] kmsKey = "kms-key".getBytes(StandardCharsets.UTF_8);
    byte[] encPrivKey = encrypt(certAndKey.privateKey().getEncoded(), plaintextDataKey);

    when(storage.getCertBytes()).thenReturn(certAndKey.certificate().getEncoded());
    when(storage.getKmsEncryptedDataKey()).thenReturn(kmsKey);
    when(storage.getAeadEncryptedPrivateKey()).thenReturn(encPrivKey);
    when(storage.getAttestationDocBytes())
        .thenReturn("attestation".getBytes(StandardCharsets.UTF_8));
    when(kmsClient.decrypt(kmsKey, KMS_KEY_ARN)).thenReturn(plaintextDataKey);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate initial = certificateProvider.getCertificate();
    assertNotNull(initial);

    // Simulate transient storage error during reload
    when(storage.getCertBytes())
        .thenThrow(new KeyBackupStorageException("S3 error", new RuntimeException()));

    assertThrows(KeyBackupStorageException.class, () -> certificateProvider.reloadCertificate());
    // Active certificate remains serving and unchanged
    assertSame(initial, certificateProvider.getCertificate());
    verify(mockMetrics).setReloadStatus(FAILURE);
  }

  @Test
  public void getCertificate_uninitialized_throwsIllegalStateException() {
    IllegalStateException ex =
        assertThrows(IllegalStateException.class, () -> certificateProvider.getCertificate());
    assertEquals("Measurement-bound certificate has not been initialized yet", ex.getMessage());
  }

  @Test
  public void getCertificate_lockFree_concurrentReadsReturnActiveCertificate() throws Exception {
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
    byte[] plaintextDataKey = generateAesKey();
    byte[] kmsKey = "kms-key".getBytes(StandardCharsets.UTF_8);
    byte[] encPrivKey = encrypt(certAndKey.privateKey().getEncoded(), plaintextDataKey);

    when(storage.getCertBytes()).thenReturn(certAndKey.certificate().getEncoded());
    when(storage.getKmsEncryptedDataKey()).thenReturn(kmsKey);
    when(storage.getAeadEncryptedPrivateKey()).thenReturn(encPrivKey);
    when(storage.getAttestationDocBytes())
        .thenReturn("attestation".getBytes(StandardCharsets.UTF_8));
    when(kmsClient.decrypt(kmsKey, KMS_KEY_ARN)).thenReturn(plaintextDataKey);

    certificateProvider.reloadCertificate();
    MeasurementBoundCertificate loaded = certificateProvider.getCertificate();

    int threadCount = 10;
    java.util.concurrent.ExecutorService executor =
        java.util.concurrent.Executors.newFixedThreadPool(threadCount);
    java.util.concurrent.CyclicBarrier barrier =
        new java.util.concurrent.CyclicBarrier(threadCount);
    java.util.List<java.util.concurrent.Future<MeasurementBoundCertificate>> futures =
        new java.util.ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      futures.add(
          executor.submit(
              () -> {
                barrier.await();
                return certificateProvider.getCertificate();
              }));
    }

    for (java.util.concurrent.Future<MeasurementBoundCertificate> future : futures) {
      assertSame(loaded, future.get());
    }
    executor.shutdown();

    // Verify storage and KMS decrypt were only called once (during reloadCertificate),
    // and all concurrent getCertificate() calls were wait-free atomic reads.
    verify(storage, times(1)).getCertBytes();
    verify(kmsClient, times(1)).decrypt(kmsKey, KMS_KEY_ARN);
  }

  @Test
  public void reloadCertificate_concurrentCalls_serialized() throws Exception {
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
    byte[] plaintextDataKey = generateAesKey();
    byte[] kmsKey = "kms-key".getBytes(StandardCharsets.UTF_8);
    byte[] encPrivKey = encrypt(certAndKey.privateKey().getEncoded(), plaintextDataKey);

    when(storage.getCertBytes()).thenReturn(certAndKey.certificate().getEncoded());
    when(storage.getKmsEncryptedDataKey()).thenReturn(kmsKey);
    when(storage.getAeadEncryptedPrivateKey()).thenReturn(encPrivKey);
    when(storage.getAttestationDocBytes())
        .thenReturn("attestation".getBytes(StandardCharsets.UTF_8));
    when(kmsClient.decrypt(kmsKey, KMS_KEY_ARN)).thenReturn(plaintextDataKey);

    int threadCount = 5;
    java.util.concurrent.ExecutorService executor =
        java.util.concurrent.Executors.newFixedThreadPool(threadCount);
    java.util.concurrent.CyclicBarrier barrier =
        new java.util.concurrent.CyclicBarrier(threadCount);
    java.util.List<java.util.concurrent.Future<MeasurementBoundCertificate>> futures =
        new java.util.ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      futures.add(
          executor.submit(
              () -> {
                barrier.await();
                certificateProvider.reloadCertificate();
                return certificateProvider.getCertificate();
              }));
    }

    for (java.util.concurrent.Future<MeasurementBoundCertificate> future : futures) {
      assertNotNull(future.get());
    }
    executor.shutdown();
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
