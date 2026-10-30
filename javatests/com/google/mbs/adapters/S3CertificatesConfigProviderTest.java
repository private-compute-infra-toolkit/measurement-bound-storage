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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.InvalidCertificatesConfigException;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.Metrics.ConfigEvent;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

@RunWith(JUnit4.class)
public class S3CertificatesConfigProviderTest {

  private static final String BUCKET_NAME = "test-public-bucket";
  private static final String CONFIG_KEY = "certificates_config.textproto";

  private static final String VALID_TEXT_PROTO =
      "self_signed_certificates {\n"
          + "  key: 1\n"
          + "  value {\n"
          + "    epoch_id: 1\n"
          + "    validity_period {\n"
          + "      not_before { seconds: 1700000000 nanos: 0 }\n"
          + "      not_after { seconds: 1710000000 nanos: 0 }\n"
          + "    }\n"
          + "  }\n"
          + "}\n"
          + "active_self_signed_certificate_ids: 1\n"
          + "acceptable_self_signed_certificate_ids: 1\n";

  @Mock private S3Client s3Client;
  @Mock private Metrics metrics;

  private CertificatesConfigBucketProperties bucketProperties;
  private S3CertificatesConfigProvider provider;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    bucketProperties = new CertificatesConfigBucketProperties(BUCKET_NAME, CONFIG_KEY);
    provider = new S3CertificatesConfigProvider(s3Client, bucketProperties, metrics);
  }

  @After
  public void tearDown() {
    verify(metrics, times(1)).recordConfigEvent(any());
    verifyNoMoreInteractions(metrics);
  }

  @Test
  public void getCertificatesConfig_validConfig_returnsMappedConfig() throws Exception {
    stubS3Response(VALID_TEXT_PROTO.getBytes(StandardCharsets.UTF_8));

    CertificatesConfig config = provider.getCertificatesConfig();

    assertThat(config.selfSignedCertificates()).containsKey(1);
    assertThat(config.selfSignedCertificates().get(1).epochId()).isEqualTo(1);
    assertThat(config.selfSignedCertificates().get(1).validityPeriod().notBefore())
        .isEqualTo(Instant.ofEpochSecond(1700000000));
    assertThat(config.selfSignedCertificates().get(1).validityPeriod().notAfter())
        .isEqualTo(Instant.ofEpochSecond(1710000000));
    assertThat(config.activeSelfSignedCertificateIds()).containsExactly(1);
    assertThat(config.acceptableSelfSignedCertificateIds()).containsExactly(1);

    verify(s3Client).getObject(eq(expectedGetObjectRequest()), any(ResponseTransformer.class));
    verify(metrics).recordConfigEvent(ConfigEvent.SUCCESS);
  }

  @Test
  public void getCertificatesConfig_noSuchKey_recordsMetricAndThrowsInvalidConfig() {
    when(s3Client.getObject(eq(expectedGetObjectRequest()), any(ResponseTransformer.class)))
        .thenThrow(NoSuchKeyException.builder().message("Key not found").build());

    InvalidCertificatesConfigException thrown =
        assertThrows(
            InvalidCertificatesConfigException.class, () -> provider.getCertificatesConfig());

    assertThat(thrown).hasCauseThat().isInstanceOf(NoSuchKeyException.class);
    verify(metrics).recordConfigEvent(ConfigEvent.COULD_NOT_FETCH_CONFIGURATION_FILE);
  }

  @Test
  public void getCertificatesConfig_noSuchBucket_recordsMetricAndThrowsInvalidConfig() {
    when(s3Client.getObject(eq(expectedGetObjectRequest()), any(ResponseTransformer.class)))
        .thenThrow(NoSuchBucketException.builder().message("Bucket not found").build());

    InvalidCertificatesConfigException thrown =
        assertThrows(
            InvalidCertificatesConfigException.class, () -> provider.getCertificatesConfig());

    assertThat(thrown).hasCauseThat().isInstanceOf(NoSuchBucketException.class);
    verify(metrics).recordConfigEvent(ConfigEvent.COULD_NOT_FETCH_CONFIGURATION_FILE);
  }

  @Test
  public void getCertificatesConfig_sdkException_recordsMetricAndThrowsInvalidConfig() {
    when(s3Client.getObject(eq(expectedGetObjectRequest()), any(ResponseTransformer.class)))
        .thenThrow(SdkClientException.create("S3 network error"));

    InvalidCertificatesConfigException thrown =
        assertThrows(
            InvalidCertificatesConfigException.class, () -> provider.getCertificatesConfig());

    assertThat(thrown).hasCauseThat().isInstanceOf(SdkClientException.class);
    verify(metrics).recordConfigEvent(ConfigEvent.COULD_NOT_FETCH_CONFIGURATION_FILE);
  }

  @Test
  public void getCertificatesConfig_invalidTextProto_throwsInvalidConfig() {
    stubS3Response("not_a_valid_text_proto: !!!".getBytes(StandardCharsets.UTF_8));

    assertThrows(InvalidCertificatesConfigException.class, () -> provider.getCertificatesConfig());
    verify(metrics).recordConfigEvent(ConfigEvent.INVALID_CONFIGURATION_FILE);
  }

  @Test
  public void getCertificatesConfig_unexpectedRuntimeException_recordsGeneralFailureAndRethrows() {
    when(s3Client.getObject(eq(expectedGetObjectRequest()), any(ResponseTransformer.class)))
        .thenThrow(new IllegalStateException("Connection pool shut down"));

    assertThrows(IllegalStateException.class, () -> provider.getCertificatesConfig());
    verify(metrics).recordConfigEvent(ConfigEvent.GENERAL_FAILURE);
  }

  private GetObjectRequest expectedGetObjectRequest() {
    return GetObjectRequest.builder().bucket(BUCKET_NAME).key(CONFIG_KEY).build();
  }

  private void stubS3Response(byte[] content) {
    when(s3Client.getObject(eq(expectedGetObjectRequest()), any(ResponseTransformer.class)))
        .thenReturn(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), content));
  }
}
