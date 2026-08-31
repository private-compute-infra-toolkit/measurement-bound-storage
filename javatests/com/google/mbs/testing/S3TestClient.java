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

package com.google.mbs.testing;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;

/** Test helper client providing encapsulated S3 bucket and object operations. */
public final class S3TestClient {

  private final S3Client s3Client;

  public S3TestClient(S3Client s3Client) {
    this.s3Client = s3Client;
  }

  /** Creates a bucket if it does not already exist. */
  public void createBucket(String bucketName) {
    try {
      s3Client.createBucket(CreateBucketRequest.builder().bucket(bucketName).build());
    } catch (S3Exception e) {
      if (e.statusCode() != 409
          && (e.awsErrorDetails() == null
              || !"BucketAlreadyOwnedByYou".equals(e.awsErrorDetails().errorCode()))) {
        throw e;
      }
    }
  }

  /** Empties all objects from a bucket and deletes the bucket. */
  public void deleteBucket(String bucketName) {
    clearBucket(bucketName);
    try {
      s3Client.deleteBucket(DeleteBucketRequest.builder().bucket(bucketName).build());
    } catch (NoSuchBucketException e) {
      // Bucket already deleted
    }
  }

  /** Removes all objects from a bucket. */
  public void clearBucket(String bucketName) {
    try {
      ListObjectsV2Response listResponse =
          s3Client.listObjectsV2(ListObjectsV2Request.builder().bucket(bucketName).build());
      for (S3Object s3Object : listResponse.contents()) {
        deleteFile(bucketName, s3Object.key());
      }
    } catch (NoSuchBucketException e) {
      // Bucket does not exist, nothing to clear
    }
  }

  /** Stores a byte array content at the specified bucket and key. */
  public void putFile(String bucketName, String key, byte[] content) {
    s3Client.putObject(
        PutObjectRequest.builder().bucket(bucketName).key(key).build(),
        RequestBody.fromBytes(content));
  }

  /** Stores a string content as UTF-8 bytes at the specified bucket and key. */
  public void putFile(String bucketName, String key, String content) {
    putFile(bucketName, key, content.getBytes(StandardCharsets.UTF_8));
  }

  /** Retrieves byte array content of an object. Throws NoSuchKeyException if missing. */
  public byte[] getFile(String bucketName, String key) {
    return s3Client
        .getObject(
            GetObjectRequest.builder().bucket(bucketName).key(key).build(),
            ResponseTransformer.toBytes())
        .asByteArray();
  }

  /** Retrieves content of an object if present, or empty Optional if missing. */
  public Optional<byte[]> getFileIfExists(String bucketName, String key) {
    try {
      return Optional.of(getFile(bucketName, key));
    } catch (NoSuchKeyException | NoSuchBucketException e) {
      return Optional.empty();
    } catch (S3Exception e) {
      if (e.statusCode() == 404) {
        return Optional.empty();
      }
      throw e;
    }
  }

  /** Checks if a file exists in S3. */
  public boolean fileExists(String bucketName, String key) {
    try {
      s3Client.headObject(HeadObjectRequest.builder().bucket(bucketName).key(key).build());
      return true;
    } catch (NoSuchKeyException e) {
      return false;
    } catch (S3Exception e) {
      if (e.statusCode() == 404) {
        return false;
      }
      throw e;
    }
  }

  /** Deletes an object from a bucket. */
  public void deleteFile(String bucketName, String key) {
    s3Client.deleteObject(DeleteObjectRequest.builder().bucket(bucketName).key(key).build());
  }

  /** Lists all object keys in a bucket. */
  public List<String> listFiles(String bucketName) {
    return listFiles(bucketName, "");
  }

  /** Lists all object keys in a bucket matching a key prefix. */
  public List<String> listFiles(String bucketName, String prefix) {
    ListObjectsV2Response response =
        s3Client.listObjectsV2(
            ListObjectsV2Request.builder().bucket(bucketName).prefix(prefix).build());
    return response.contents().stream().map(S3Object::key).toList();
  }
}
