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

// javatests/com/google/tlog/RekorClientImplTest.java
package com.google.tlog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import dev.sigstore.json.GsonSupplier;
import dev.sigstore.rekor.client.HashedRekordRequest;
import dev.sigstore.rekor.client.ImmutableRekorEntry;
import dev.sigstore.rekor.client.ImmutableVerification;
import dev.sigstore.rekor.client.RekorClient;
import dev.sigstore.rekor.client.RekorResponse;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class RekorClientImplTest {

  private RekorClient mockRekorClient;
  private TransparencyLogClient tlogClient;
  private X509Certificate testCert;
  private KeyPair testKeyPair;
  private ImmutableRekorEntry fakeRekorEntry;

  @Before
  public void setUp() throws Exception {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    mockRekorClient = mock(RekorClient.class);
    tlogClient = new RekorClientImpl(mockRekorClient);

    // Generate a test keypair and self-signed certificate
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
    kpg.initialize(2048);
    testKeyPair = kpg.generateKeyPair();

    X500Name name = new X500Name("CN=Test CA");
    long now = System.currentTimeMillis();
    Date notBefore = new Date(now - 1000L * 60 * 60 * 24);
    Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * 30);
    BigInteger serial = BigInteger.valueOf(now);

    JcaX509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            name, serial, notBefore, notAfter, name, testKeyPair.getPublic());
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(testKeyPair.getPrivate());
    testCert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

    // Create a fake RekorEntry based on sample
    String bodyJson =
        "{\"apiVersion\":\"0.0.1\",\"kind\":\"hashedrekord\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"fakehash\"}},\"signature\":{\"content\":\"fakesig\",\"publicKey\":{\"content\":\"fakekey\"}}}}";
    String encodedBody = Base64.getEncoder().encodeToString(bodyJson.getBytes());

    fakeRekorEntry =
        ImmutableRekorEntry.builder()
            .logID("d32f30a3c32d639c2b762205a21c7bb07788e68283a4ae6f42118723a1bea496")
            .logIndex(1688L)
            .integratedTime(1656448131L)
            .body(encodedBody)
            .verification(
                ImmutableVerification.builder()
                    .signedEntryTimestamp(
                        "MEUCIQCO8dFvolJwFZDHkhkSdsW3Ny+07fG8CF7G32feG8NJMgIgd2qfJ5shezuXX8I1S6DsudvIZ8xN/+y95at/V5xHfEQ=")
                    .build())
            .build();

    RekorResponse mockRekorResponse = mock(RekorResponse.class);
    when(mockRekorResponse.getEntry()).thenReturn(fakeRekorEntry);
    when(mockRekorClient.putEntry(any(HashedRekordRequest.class))).thenReturn(mockRekorResponse);
  }

  @Test
  public void recordCertificate_success() throws Exception {
    TlogEntry entry = tlogClient.recordCertificate(testCert, testKeyPair.getPrivate());
    assertNotNull(entry);
    assertNotNull(entry.getEntryJson());
    String expectedJson = GsonSupplier.GSON.get().toJson(fakeRekorEntry);
    assertEquals(expectedJson, entry.getEntryJson());
  }

  @Test
  public void getTlogEntryByCertificate_success() throws Exception {
    String fakeUuid = "fake-entry-uuid";
    // Mock searchEntry to return the UUID
    when(mockRekorClient.searchEntry(any(), any(), any(), any()))
        .thenReturn(Collections.singletonList(fakeUuid));

    // Mock getEntry to return the fakeRekorEntry
    when(mockRekorClient.getEntry(fakeUuid)).thenReturn(Optional.of(fakeRekorEntry));

    Optional<TlogEntry> entryOpt = tlogClient.getTlogEntryByCertificate(testCert);

    assertTrue(entryOpt.isPresent());
    TlogEntry entry = entryOpt.get();
    assertNotNull(entry.getEntryJson());
    String expectedJson = GsonSupplier.GSON.get().toJson(fakeRekorEntry);
    assertEquals(expectedJson, entry.getEntryJson());
  }

  @Test
  public void getTlogEntryByCertificate_notFound() throws Exception {
    // Mock searchEntry to return empty list
    when(mockRekorClient.searchEntry(any(), any(), any(), any()))
        .thenReturn(Collections.emptyList());

    Optional<TlogEntry> entryOpt = tlogClient.getTlogEntryByCertificate(testCert);

    assertTrue(entryOpt.isEmpty());
  }

  // TODO: Add tests for error scenarios, e.g., RekorClient throwing IOException
}
