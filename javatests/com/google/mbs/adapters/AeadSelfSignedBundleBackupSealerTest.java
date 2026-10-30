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

package com.google.mbs.adapters;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.AttestationToken;
import com.google.mbs.domain.BackupCorruptedException;
import com.google.mbs.domain.CertificateCodec;
import com.google.mbs.domain.KmsClientInterface;
import com.google.mbs.domain.KmsException;
import com.google.mbs.domain.KmsGeneratedKey;
import com.google.mbs.domain.SelfSignedBundle;
import com.google.mbs.domain.SelfSignedBundleBackup;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class AeadSelfSignedBundleBackupSealerTest {

  private static final String KMS_KEY_ARN = "test-kms-key-arn";
  private static final byte[] DATA_KEY_PLAINTEXT = new byte[32];
  private static final byte[] DATA_KEY_CIPHERTEXT =
      "kms-encrypted-data-key".getBytes(StandardCharsets.UTF_8);
  private static final KmsGeneratedKey DATA_KEY =
      KmsGeneratedKey.builder()
          .setPlaintext(DATA_KEY_PLAINTEXT)
          .setCiphertext(DATA_KEY_CIPHERTEXT)
          .build();
  private static final byte[] VALID_CERT_BYTES = "cert-a".getBytes(StandardCharsets.UTF_8);
  private static final byte[] OTHER_CERT_BYTES = "cert-b".getBytes(StandardCharsets.UTF_8);

  private static SelfSignedBundle validBundle;
  private static SelfSignedBundle otherBundle;

  @Mock private KmsClientInterface kmsClient;
  @Mock private CertificateCodec certificateCodec;

  private AeadSelfSignedBundleBackupSealer sealer;
  private SelfSignedBundleBackup validBackup;

  @BeforeClass
  public static void setUpClass() throws Exception {
    validBundle = generateBundle("attestation-a");
    otherBundle = generateBundle("attestation-b");
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenReturn(DATA_KEY);
    when(kmsClient.decrypt(DATA_KEY_CIPHERTEXT, KMS_KEY_ARN)).thenReturn(DATA_KEY_PLAINTEXT);
    when(certificateCodec.toBytes(validBundle.certificate())).thenReturn(VALID_CERT_BYTES);
    when(certificateCodec.toBytes(otherBundle.certificate())).thenReturn(OTHER_CERT_BYTES);
    when(certificateCodec.toCertificate(VALID_CERT_BYTES)).thenReturn(validBundle.certificate());
    when(certificateCodec.toCertificate(OTHER_CERT_BYTES)).thenReturn(otherBundle.certificate());

    sealer = new AeadSelfSignedBundleBackupSealer(kmsClient, KMS_KEY_ARN, certificateCodec);
    validBackup = sealer.seal(validBundle);
    clearInvocations(kmsClient, certificateCodec);
  }

  private static SelfSignedBundle generateBundle(String attestation) throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    X509Certificate certificate = mock(X509Certificate.class);
    when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());
    when(certificate.getSigAlgName()).thenReturn("SHA256withRSA");
    return new SelfSignedBundle(
        certificate,
        keyPair.getPrivate(),
        AttestationToken.fromBytes(attestation.getBytes(StandardCharsets.UTF_8)));
  }

  private static SelfSignedBundleBackup sealWithoutAssociatedData(
      SelfSignedBundle bundle, byte[] certBytes) throws Exception {
    byte[] encryptedKey =
        AeadSelfSignedBundleBackupSealer.getAead(DATA_KEY_PLAINTEXT)
            .encrypt(bundle.privateKey().getEncoded(), new byte[0]);
    return new SelfSignedBundleBackup(
        certBytes, DATA_KEY_CIPHERTEXT, encryptedKey, bundle.attestationToken().getBytes());
  }

  @Test
  public void seal_andUnseal_roundTripsBundleViaKms() throws Exception {
    SelfSignedBundleBackup backup = sealer.seal(validBundle);

    verify(kmsClient).generateDataKey(KMS_KEY_ARN);
    verify(certificateCodec).toBytes(validBundle.certificate());
    assertArrayEquals(VALID_CERT_BYTES, backup.certBytes());
    assertArrayEquals(DATA_KEY_CIPHERTEXT, backup.kmsEncryptedDataKey());
    assertArrayEquals(validBundle.attestationToken().getBytes(), backup.attestationDocBytes());

    SelfSignedBundle unsealed = sealer.unseal(backup);

    verify(kmsClient).decrypt(DATA_KEY_CIPHERTEXT, KMS_KEY_ARN);
    verify(certificateCodec).toCertificate(VALID_CERT_BYTES);
    verifyNoMoreInteractions(kmsClient, certificateCodec);
    assertEquals(validBundle.certificate(), unsealed.certificate());
    assertArrayEquals(validBundle.privateKey().getEncoded(), unsealed.privateKey().getEncoded());
    assertEquals(validBundle.attestationToken(), unsealed.attestationToken());
  }

  @Test
  public void kmsFailure_throwsKmsException() throws Exception {
    when(kmsClient.generateDataKey(KMS_KEY_ARN)).thenThrow(new KmsException("KMS error"));
    when(kmsClient.decrypt(DATA_KEY_CIPHERTEXT, KMS_KEY_ARN))
        .thenThrow(new KmsException("KMS error"));

    assertThrows(KmsException.class, () -> sealer.seal(validBundle));
    assertThrows(KmsException.class, () -> sealer.unseal(validBackup));
  }

  @Test
  public void invalidDataKeyLength_throwsException() throws Exception {
    byte[] shortKey = new byte[16];
    when(kmsClient.generateDataKey(KMS_KEY_ARN))
        .thenReturn(
            KmsGeneratedKey.builder()
                .setPlaintext(shortKey)
                .setCiphertext(DATA_KEY_CIPHERTEXT)
                .build());
    when(kmsClient.decrypt(DATA_KEY_CIPHERTEXT, KMS_KEY_ARN)).thenReturn(shortKey);

    assertThrows(IllegalStateException.class, () -> sealer.seal(validBundle));
    assertThrows(BackupCorruptedException.class, () -> sealer.unseal(validBackup));
  }

  @Test
  public void unseal_wrongDataKeyFromKms_throwsBackupCorruptedException() throws Exception {
    byte[] wrongKey = new byte[32];
    wrongKey[0] = 1;
    when(kmsClient.decrypt(DATA_KEY_CIPHERTEXT, KMS_KEY_ARN)).thenReturn(wrongKey);

    assertThrows(BackupCorruptedException.class, () -> sealer.unseal(validBackup));
  }

  @Test
  public void unseal_corruptedCertificateBytes_throwsBackupCorruptedException() {
    byte[] corruptedBytes = "corrupted-cert".getBytes(StandardCharsets.UTF_8);
    when(certificateCodec.toCertificate(corruptedBytes))
        .thenThrow(new IllegalArgumentException("Corrupted cert"));
    SelfSignedBundleBackup corruptedCert =
        new SelfSignedBundleBackup(
            corruptedBytes,
            validBackup.kmsEncryptedDataKey(),
            validBackup.aeadEncryptedPrivateKey(),
            validBackup.attestationDocBytes());

    assertThrows(BackupCorruptedException.class, () -> sealer.unseal(corruptedCert));
  }

  @Test
  public void unseal_corruptedEncryptedPrivateKey_throwsBackupCorruptedException() {
    SelfSignedBundleBackup corruptedKey =
        new SelfSignedBundleBackup(
            validBackup.certBytes(),
            validBackup.kmsEncryptedDataKey(),
            "corrupted-ciphertext".getBytes(StandardCharsets.UTF_8),
            validBackup.attestationDocBytes());

    assertThrows(BackupCorruptedException.class, () -> sealer.unseal(corruptedKey));
  }

  @Test
  public void unseal_mismatchedPrivateKey_throwsBackupCorruptedException() throws Exception {
    SelfSignedBundleBackup otherBackup = sealer.seal(otherBundle);
    SelfSignedBundleBackup mismatched =
        new SelfSignedBundleBackup(
            validBackup.certBytes(),
            otherBackup.kmsEncryptedDataKey(),
            otherBackup.aeadEncryptedPrivateKey(),
            validBackup.attestationDocBytes());

    assertThrows(BackupCorruptedException.class, () -> sealer.unseal(mismatched));
  }

  @Test
  public void unseal_tamperedAttestationBytes_throwsBackupCorruptedException() {
    SelfSignedBundleBackup tamperedAttestation =
        new SelfSignedBundleBackup(
            validBackup.certBytes(),
            validBackup.kmsEncryptedDataKey(),
            validBackup.aeadEncryptedPrivateKey(),
            "swapped-attestation".getBytes(StandardCharsets.UTF_8));

    assertThrows(BackupCorruptedException.class, () -> sealer.unseal(tamperedAttestation));
  }

  @Test
  public void unseal_tamperedCertificateBytes_throwsBackupCorruptedException() {
    SelfSignedBundleBackup tamperedCertBytes =
        new SelfSignedBundleBackup(
            OTHER_CERT_BYTES,
            validBackup.kmsEncryptedDataKey(),
            validBackup.aeadEncryptedPrivateKey(),
            validBackup.attestationDocBytes());

    assertThrows(BackupCorruptedException.class, () -> sealer.unseal(tamperedCertBytes));
  }

  @Test
  public void unseal_legacyBackupWithoutAssociatedData_succeeds() throws Exception {
    SelfSignedBundle unsealed =
        sealer.unseal(sealWithoutAssociatedData(validBundle, VALID_CERT_BYTES));

    assertEquals(validBundle.certificate(), unsealed.certificate());
    assertArrayEquals(validBundle.privateKey().getEncoded(), unsealed.privateKey().getEncoded());
    assertEquals(validBundle.attestationToken(), unsealed.attestationToken());
  }

  @Test
  public void unseal_legacyBackupWithMismatchedPrivateKey_throwsBackupCorruptedException()
      throws Exception {
    SelfSignedBundleBackup mismatchedLegacyBackup =
        sealWithoutAssociatedData(
            new SelfSignedBundle(
                validBundle.certificate(),
                otherBundle.privateKey(),
                validBundle.attestationToken()),
            VALID_CERT_BYTES);

    assertThrows(BackupCorruptedException.class, () -> sealer.unseal(mismatchedLegacyBackup));
  }

  @Test
  public void buildAssociatedData_constructsExpectedWireFormat() {
    HexFormat hex = HexFormat.of();
    byte[] certBytes = hex.parseHex("feed");
    byte[] attestationBytes = hex.parseHex("deadbeef");

    byte[] associatedData =
        AeadSelfSignedBundleBackupSealer.buildAssociatedData(certBytes, attestationBytes);

    byte[] expected =
        hex.parseHex(
            "00000001" // ASSOCIATED_DATA_VERSION = 1
                + "00000002" // certBytes.length = 2
                + "feed" // certBytes
                + "00000004" // attestationBytes.length = 4
                + "deadbeef" // attestationBytes
            );
    assertArrayEquals(expected, associatedData);
  }
}
