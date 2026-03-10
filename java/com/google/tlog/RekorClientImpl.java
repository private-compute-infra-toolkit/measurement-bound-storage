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

package com.google.tlog;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.io.BaseEncoding;
import dev.sigstore.json.GsonSupplier;
import dev.sigstore.rekor.client.HashedRekordRequest;
import dev.sigstore.rekor.client.RekorClient;
import dev.sigstore.rekor.client.RekorClientHttp;
import dev.sigstore.rekor.client.RekorEntry;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.rekor.client.RekorResponse;
import dev.sigstore.trustroot.Service;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class RekorClientImpl implements TransparencyLogClient {

  private final RekorClient rekorClient;

  public RekorClientImpl(String rekorUrl) {
    this.rekorClient =
        RekorClientHttp.builder().setService(Service.of(URI.create(rekorUrl), 0)).build();
  }

  @VisibleForTesting
  public RekorClientImpl(RekorClient rekorClient) {
    this.rekorClient = rekorClient;
  }

  @Override
  public TlogEntry recordCertificate(X509Certificate certificate, PrivateKey privateKey)
      throws IOException,
          RekorParseException,
          NoSuchAlgorithmException,
          SignatureException,
          InvalidKeyException,
          CertificateEncodingException {

    // 1. Calculate the SHA256 hash of the full DER-encoded certificate
    byte[] certDer = certificate.getEncoded();
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] artifactDigest = digest.digest(certDer);

    // 2. Sign the raw certificate DER bytes
    Signature signatureInstance = Signature.getInstance("SHA256withRSA"); // Assuming RSA keys
    signatureInstance.initSign(privateKey);
    signatureInstance.update(certDer); // Sign the raw DER bytes
    byte[] signature = signatureInstance.sign();

    // 3. Extract public key and convert to PEM
    java.security.PublicKey pubKey = certificate.getPublicKey();
    StringWriter pemStrWriter = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(pemStrWriter)) {
      pemWriter.writeObject(pubKey);
    }
    byte[] publicKeyPem = pemStrWriter.toString().getBytes(UTF_8);

    // 4. Prepare Rekor Request
    HashedRekordRequest request =
        HashedRekordRequest.newHashedRekordRequest(artifactDigest, publicKeyPem, signature);

    // 5. Call Rekor
    RekorResponse response;
    try {
      response = rekorClient.putEntry(request);
    } catch (IOException e) {
      // Per discussion, fail hard if Rekor is unavailable during bootstrap
      throw new RuntimeException("Failed to record certificate in Rekor: " + e.getMessage(), e);
    }

    // 6. Return TlogEntry
    String rekorEntryJson = GsonSupplier.GSON.get().toJson(response.getEntry());
    return new TlogEntry(rekorEntryJson);
  }

  @Override
  public Optional<TlogEntry> getTlogEntryByCertificate(X509Certificate certificate)
      throws IOException,
          RekorParseException,
          CertificateEncodingException,
          NoSuchAlgorithmException {
    // Calculate the SHA256 hash of the full DER-encoded certificate
    byte[] certDer = certificate.getEncoded();
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] certHash = digest.digest(certDer);
    String certHashHex = BaseEncoding.base16().lowerCase().encode(certHash);

    String prefixedHash = "sha256:" + certHashHex;
    List<String> entryUUIDs = rekorClient.searchEntry(null, prefixedHash, null, null);

    if (entryUUIDs != null && !entryUUIDs.isEmpty()) {
      // Entries are returned newest first, so the first one is the most recent.
      String entryUUID = entryUUIDs.get(0);
      Optional<RekorEntry> entry = rekorClient.getEntry(entryUUID);
      if (entry.isPresent()) {
        // Serialize the RekorEntry back to JSON
        String rekorEntryJson = GsonSupplier.GSON.get().toJson(entry.get());
        return Optional.of(new TlogEntry(rekorEntryJson));
      }
    }
    return Optional.empty();
  }
}
