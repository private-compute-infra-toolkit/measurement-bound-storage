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

import com.google.kmsclient.KmsClientInterface;
import com.google.kmsclient.KmsException;
import com.google.kmsclient.KmsGeneratedKey;
import com.google.platform.aws.nsm.NitroSecurityModule;
import com.google.platform.aws.nsm.NitroSecurityModuleFactory;
import jakarta.inject.Inject;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.util.Optional;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyEncryptionMechanism;
import software.amazon.awssdk.services.kms.model.RecipientInfo;

/**
 * AWS-specific implementation of KmsClientInterface using AWS SDK and Nitro Security Module. This
 * implementation provides Nitro attestation documents to KMS.
 */
public class AwsKmsClient implements KmsClientInterface {

  private final KmsClient kmsClient;
  private final NitroSecurityModuleFactory nsmFactory;

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Inject
  public AwsKmsClient(KmsClient kmsClient, NitroSecurityModuleFactory nsmFactory) {
    this.kmsClient = kmsClient;
    this.nsmFactory = nsmFactory;
  }

  protected KeyPair generateEphemeralKeyPair() {
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(4096);
      return keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Failed to initialize RSA key generator", e);
    }
  }

  @Override
  public KmsGeneratedKey generateDataKey(String keyId) throws KmsException {
    try (NitroSecurityModule nsm = nsmFactory.create()) {
      KeyPair keyPair = generateEphemeralKeyPair();
      PublicKey publicKey = keyPair.getPublic();
      byte[] attestationDoc =
          nsm.getAttestationDocument(
              Optional.empty(), Optional.empty(), Optional.of(publicKey.getEncoded()));

      RecipientInfo recipientInfo =
          RecipientInfo.builder()
              .attestationDocument(SdkBytes.fromByteArray(attestationDoc))
              .keyEncryptionAlgorithm(KeyEncryptionMechanism.RSAES_OAEP_SHA_256)
              .build();

      GenerateDataKeyRequest request =
          GenerateDataKeyRequest.builder()
              .keyId(keyId)
              .keySpec(DataKeySpec.AES_256)
              .recipient(recipientInfo)
              .build();

      GenerateDataKeyResponse response = kmsClient.generateDataKey(request);

      if (response.ciphertextForRecipient() == null
          || response.ciphertextForRecipient().asByteArray().length == 0) {
        throw new KmsException(
            "KMS response missing expected ciphertextForRecipient in attested flow");
      }
      byte[] plaintext =
          decryptCiphertextForRecipient(response.ciphertextForRecipient().asByteArray(), keyPair);

      return KmsGeneratedKey.builder()
          .setPlaintext(plaintext)
          .setCiphertext(response.ciphertextBlob().asByteArray())
          .build();
    } catch (Exception e) {
      throw new KmsException("Failed to generate data key from AWS KMS with NSM", e);
    }
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, String keyId) throws KmsException {
    try (NitroSecurityModule nsm = nsmFactory.create()) {
      KeyPair keyPair = generateEphemeralKeyPair();
      PublicKey publicKey = keyPair.getPublic();
      byte[] attestationDoc =
          nsm.getAttestationDocument(
              Optional.empty(), Optional.empty(), Optional.of(publicKey.getEncoded()));

      RecipientInfo recipientInfo =
          RecipientInfo.builder()
              .attestationDocument(SdkBytes.fromByteArray(attestationDoc))
              .keyEncryptionAlgorithm(KeyEncryptionMechanism.RSAES_OAEP_SHA_256)
              .build();

      DecryptRequest request =
          DecryptRequest.builder()
              .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
              .keyId(keyId)
              .recipient(recipientInfo)
              .build();

      DecryptResponse response = kmsClient.decrypt(request);

      if (response.ciphertextForRecipient() == null
          || response.ciphertextForRecipient().asByteArray().length == 0) {
        throw new KmsException(
            "KMS response missing expected ciphertextForRecipient in attested flow");
      }
      return decryptCiphertextForRecipient(
          response.ciphertextForRecipient().asByteArray(), keyPair);
    } catch (Exception e) {
      throw new KmsException("Failed to decrypt ciphertext using AWS KMS with NSM", e);
    }
  }

  private byte[] decryptCiphertextForRecipient(byte[] ciphertext, KeyPair keyPair)
      throws Exception {
    CMSEnvelopedData envelopedData = new CMSEnvelopedData(ciphertext);
    RecipientInformationStore recipients = envelopedData.getRecipientInfos();
    RecipientInformation recipient = recipients.getRecipients().iterator().next();

    JceKeyTransEnvelopedRecipient jceRecipient =
        new JceKeyTransEnvelopedRecipient(keyPair.getPrivate());
    jceRecipient.setProvider(BouncyCastleProvider.PROVIDER_NAME);

    return recipient.getContent(jceRecipient);
  }
}
