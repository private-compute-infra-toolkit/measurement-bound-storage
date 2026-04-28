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

package com.google.kmsclient.aws;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.kmsclient.KmsException;
import com.google.kmsclient.KmsGeneratedKey;
import com.google.platform.aws.nsm.NitroSecurityModule;
import com.google.platform.aws.nsm.NitroSecurityModuleFactory;
import java.security.PublicKey;
import java.security.Security;
import java.util.Optional;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

@RunWith(JUnit4.class)
public class AwsKmsClientTest {

  private static final String KEY_ID = "test-key-id";
  private static final byte[] ATTESTATION_DOC = "test-attestation-doc".getBytes();
  private static final byte[] PLAINTEXT = "test-plaintext".getBytes();
  private static final byte[] CIPHERTEXT = "test-ciphertext".getBytes();

  private NitroSecurityModuleFactory mockNsmFactory;
  private NitroSecurityModule mockNsm;
  private KmsClient mockKmsClient;
  private AwsKmsClient awsKmsClient;

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Before
  public void setUp() throws Exception {
    mockNsmFactory = mock(NitroSecurityModuleFactory.class);
    mockNsm = mock(NitroSecurityModule.class);
    mockKmsClient = mock(KmsClient.class);

    when(mockNsmFactory.create()).thenReturn(mockNsm);

    when(mockNsm.getAttestationDocument(any(), any(), any()))
        .thenAnswer(
            invocation -> {
              Optional<byte[]> publicKeyBytes = invocation.getArgument(2);
              return publicKeyBytes.orElseThrow(
                  () -> new IllegalArgumentException("Public key missing"));
            });

    awsKmsClient = new AwsKmsClient(mockKmsClient, mockNsmFactory);
  }

  @Test
  public void generateDataKey_success() throws Exception {
    when(mockKmsClient.generateDataKey(any(GenerateDataKeyRequest.class)))
        .thenAnswer(
            invocation -> {
              GenerateDataKeyRequest request = invocation.getArgument(0);
              byte[] publicKeyBytes = request.recipient().attestationDocument().asByteArray();
              PublicKey publicKey = decodePublicKey(publicKeyBytes);
              SdkBytes cmsBlob = generateCmsBlob(PLAINTEXT, publicKey);
              return GenerateDataKeyResponse.builder()
                  .ciphertextForRecipient(cmsBlob)
                  .ciphertextBlob(SdkBytes.fromByteArray(CIPHERTEXT))
                  .build();
            });

    KmsGeneratedKey result = awsKmsClient.generateDataKey(KEY_ID);

    assertArrayEquals(PLAINTEXT, result.plaintext());
    assertArrayEquals(CIPHERTEXT, result.ciphertext());
  }

  @Test
  public void decrypt_success() throws Exception {
    when(mockKmsClient.decrypt(any(DecryptRequest.class)))
        .thenAnswer(
            invocation -> {
              DecryptRequest request = invocation.getArgument(0);
              byte[] publicKeyBytes = request.recipient().attestationDocument().asByteArray();
              PublicKey publicKey = decodePublicKey(publicKeyBytes);
              SdkBytes cmsBlob = generateCmsBlob(PLAINTEXT, publicKey);
              return DecryptResponse.builder().ciphertextForRecipient(cmsBlob).build();
            });

    byte[] result = awsKmsClient.decrypt(CIPHERTEXT, KEY_ID);

    assertArrayEquals(PLAINTEXT, result);
  }

  @Test
  public void generateDataKey_missingRecipient_fails() throws Exception {
    GenerateDataKeyResponse response =
        GenerateDataKeyResponse.builder()
            .ciphertextBlob(SdkBytes.fromByteArray(CIPHERTEXT))
            .build();
    when(mockKmsClient.generateDataKey(any(GenerateDataKeyRequest.class))).thenReturn(response);

    assertThrows(KmsException.class, () -> awsKmsClient.generateDataKey(KEY_ID));
  }

  @Test
  public void decrypt_missingRecipient_fails() throws Exception {
    DecryptResponse response = DecryptResponse.builder().build();
    when(mockKmsClient.decrypt(any(DecryptRequest.class))).thenReturn(response);

    assertThrows(KmsException.class, () -> awsKmsClient.decrypt(CIPHERTEXT, KEY_ID));
  }

  private PublicKey decodePublicKey(byte[] encodedKey) throws Exception {
    java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
    java.security.spec.X509EncodedKeySpec spec =
        new java.security.spec.X509EncodedKeySpec(encodedKey);
    return keyFactory.generatePublic(spec);
  }

  private SdkBytes generateCmsBlob(byte[] plaintext, PublicKey publicKey) throws Exception {
    CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
    gen.addRecipientInfoGenerator(
        new JceKeyTransRecipientInfoGenerator(new byte[] {1, 2, 3}, publicKey)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME));
    CMSEnvelopedData envData =
        gen.generate(
            new CMSProcessableByteArray(plaintext),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build());
    return SdkBytes.fromByteArray(envData.getEncoded());
  }
}
