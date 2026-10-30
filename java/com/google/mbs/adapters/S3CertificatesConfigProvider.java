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

import com.google.common.flogger.FluentLogger;
import com.google.mbs.domain.CertificatesConfig;
import com.google.mbs.domain.CertificatesConfigProvider;
import com.google.mbs.domain.InvalidCertificatesConfigException;
import com.google.mbs.domain.Metrics;
import com.google.mbs.domain.Metrics.ConfigEvent;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.Objects;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

/** AWS S3 adapter that loads and parses {@link CertificatesConfig} from an S3 bucket. */
@Singleton
public class S3CertificatesConfigProvider implements CertificatesConfigProvider {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private final S3Client s3Client;
  private final CertificatesConfigBucketProperties bucketProperties;
  private final Metrics metrics;

  @Inject
  public S3CertificatesConfigProvider(
      S3Client s3Client, CertificatesConfigBucketProperties bucketProperties, Metrics metrics) {
    this.s3Client = Objects.requireNonNull(s3Client);
    this.bucketProperties = Objects.requireNonNull(bucketProperties);
    this.metrics = Objects.requireNonNull(metrics);
  }

  @Override
  public CertificatesConfig getCertificatesConfig() throws InvalidCertificatesConfigException {
    try {
      return fetchAndParse();
    } catch (RuntimeException e) {
      metrics.recordConfigEvent(ConfigEvent.GENERAL_FAILURE);
      logger.atSevere().withCause(e).log(
          "Unexpected failure loading certificates configuration from S3 bucket '%s', key '%s'",
          bucketProperties.bucketName(), bucketProperties.configFileName());
      throw e;
    }
  }

  private CertificatesConfig fetchAndParse() throws InvalidCertificatesConfigException {
    String bucket = bucketProperties.bucketName();
    String key = bucketProperties.configFileName();
    logger.atInfo().log(
        "Fetching certificates configuration from S3 bucket '%s', key '%s'", bucket, key);

    ResponseBytes<GetObjectResponse> responseBytes;
    try {
      responseBytes =
          s3Client.getObject(
              GetObjectRequest.builder().bucket(bucket).key(key).build(),
              ResponseTransformer.toBytes());
    } catch (NoSuchKeyException | NoSuchBucketException e) {
      metrics.recordConfigEvent(ConfigEvent.COULD_NOT_FETCH_CONFIGURATION_FILE);
      logger.atWarning().withCause(e).log(
          "Certificates configuration file not found in S3 bucket '%s', key '%s'", bucket, key);
      throw new InvalidCertificatesConfigException(
          String.format("Certificates config file not found at %s/%s", bucket, key), e);
    } catch (SdkException e) {
      metrics.recordConfigEvent(ConfigEvent.COULD_NOT_FETCH_CONFIGURATION_FILE);
      logger.atWarning().withCause(e).log(
          "Failed to fetch certificates configuration from S3 bucket '%s', key '%s'", bucket, key);
      throw new InvalidCertificatesConfigException(
          String.format(
              "Failed to fetch certificates config from S3 bucket '%s', key '%s'", bucket, key),
          e);
    }

    String textProto = responseBytes.asUtf8String();
    try {
      CertificatesConfig config = CertificatesConfigMapper.fromTextProto(textProto);
      metrics.recordConfigEvent(ConfigEvent.SUCCESS);
      return config;
    } catch (InvalidCertificatesConfigException e) {
      metrics.recordConfigEvent(ConfigEvent.INVALID_CONFIGURATION_FILE);
      logger.atWarning().withCause(e).log(
          "Invalid certificates configuration in S3 bucket '%s', key '%s'", bucket, key);
      throw e;
    }
  }
}
