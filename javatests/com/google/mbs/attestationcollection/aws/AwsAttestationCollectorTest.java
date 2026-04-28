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
package com.google.mbs.attestationcollection.aws;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.io.Resources;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.platform.aws.nsm.NitroSecurityModule;
import com.google.platform.aws.nsm.NitroSecurityModuleFactory;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(JUnit4.class)
public class AwsAttestationCollectorTest {

  private static final String TCA_ROOT_CERT_PATH =
      "com/google/mbs/attestationcollection/aws/res/tca_root_certificate.pem";

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  @Mock private NitroSecurityModuleFactory mockNsmFactory;
  @Mock private NitroSecurityModule mockNsm;

  private AwsAttestationCollector collector;

  private X509Certificate rootCertificate;
  private PublicKey publicKey;

  @Before
  public void setUp() throws Exception {
    when(mockNsmFactory.create()).thenReturn(mockNsm);
    collector = new AwsAttestationCollector(mockNsmFactory);

    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    rootCertificate =
        (X509Certificate)
            certFactory.generateCertificate(
                Resources.asByteSource(Resources.getResource(TCA_ROOT_CERT_PATH)).openStream());
    publicKey = rootCertificate.getPublicKey();
  }

  @Test
  public void collectBoundToPubkey_withPubkey_success() {
    byte[] fakeAttestationDoc = "fake_attestation_doc".getBytes();
    byte[] expectedPublicKey = publicKey.getEncoded();
    byte[] userData = "test_userdata".getBytes(StandardCharsets.UTF_8);

    when(mockNsm.getAttestationDocument(any(), eq(Optional.empty()), any()))
        .thenReturn(fakeAttestationDoc);

    AttestationToken token = collector.collectBoundToPubkey(publicKey, userData);

    assertThat(token.getBase64()).isEqualTo(Base64.getEncoder().encodeToString(fakeAttestationDoc));

    ArgumentCaptor<Optional<byte[]>> userDataCaptor = ArgumentCaptor.forClass(Optional.class);
    ArgumentCaptor<Optional<byte[]>> publicKeyCaptor = ArgumentCaptor.forClass(Optional.class);

    verify(mockNsm)
        .getAttestationDocument(
            userDataCaptor.capture(), eq(Optional.empty()), publicKeyCaptor.capture());

    Optional<byte[]> actualUserData = userDataCaptor.getValue();
    assertThat(actualUserData).isPresent();
    assertThat(actualUserData.get()).isEqualTo(userData);

    Optional<byte[]> actualPublicKey = publicKeyCaptor.getValue();
    assertThat(actualPublicKey).isPresent();
    assertThat(actualPublicKey.get()).isEqualTo(expectedPublicKey);
  }

  @Test(expected = IllegalArgumentException.class)
  public void collectBoundToPubkey_withTooLargeUserData_throwsException() {
    byte[] largeUserData = new byte[1025];
    collector.collectBoundToPubkey(publicKey, largeUserData);
  }

  @Test(expected = IllegalArgumentException.class)
  public void collectBoundToPubkey_withTooLargePublicKey_throwsException() {
    // Create a mock public key that returns a large encoded byte array
    PublicKey mockLargeKey = org.mockito.Mockito.mock(PublicKey.class);
    when(mockLargeKey.getEncoded()).thenReturn(new byte[1025]);

    collector.collectBoundToPubkey(mockLargeKey);
  }
}
