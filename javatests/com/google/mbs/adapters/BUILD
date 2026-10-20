# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_java//java:defs.bzl", "java_test")

package(default_visibility = ["//visibility:public"])

java_test(
    name = "S3KeyBackupStorageTest",
    size = "small",
    srcs = ["S3KeyBackupStorageTest.java"],
    deps = [
        "//java/com/google/mbs:certmanagement",
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)

java_test(
    name = "S3CompleteBackupHandleTest",
    size = "small",
    srcs = ["S3CompleteBackupHandleTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "S3CompleteCrossSignedCertHandleTest",
    size = "small",
    srcs = ["S3CompleteCrossSignedCertHandleTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "S3EmptyBackupHandleTest",
    size = "small",
    srcs = ["S3EmptyBackupHandleTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "S3EmptyCrossSignedCertHandleTest",
    size = "small",
    srcs = ["S3EmptyCrossSignedCertHandleTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "S3BackupPathsTest",
    size = "small",
    srcs = ["S3BackupPathsTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
    ],
)

java_test(
    name = "S3BackupReaderTest",
    size = "small",
    srcs = ["S3BackupReaderTest.java"],
    deps = [
        "//java/com/google/mbs:certmanagement",
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)

java_test(
    name = "S3BackupWriterTest",
    size = "small",
    srcs = ["S3BackupWriterTest.java"],
    deps = [
        "//java/com/google/mbs:certmanagement",
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
        "@maven//:software_amazon_awssdk_aws_core",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)

java_test(
    name = "AwsAttestationCollectorTest",
    size = "small",
    srcs = ["AwsAttestationCollectorTest.java"],
    resources = ["res/tca_root_certificate.pem"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/adapters/nsm",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "AwsKmsClientTest",
    size = "small",
    srcs = ["AwsKmsClientTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/adapters/nsm",
        "//java/com/google/mbs/domain",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
        "@maven//:software_amazon_awssdk_kms",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)

java_test(
    name = "MeasurementBoundCertificateMonitorTest",
    size = "small",
    srcs = ["MeasurementBoundCertificateMonitorTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_guava_guava",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "CertificatesConfigMapperTest",
    size = "small",
    srcs = ["CertificatesConfigMapperTest.java"],
    resources = [
        "res/valid_certificates_config.textproto",
    ],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "//proto:certificates_config_java_proto",
        "@com_google_protobuf//:protobuf_java",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
    ],
)

java_test(
    name = "S3CertificatesConfigProviderTest",
    size = "small",
    srcs = ["S3CertificatesConfigProviderTest.java"],
    deps = [
        "//java/com/google/mbs:certmanagement",
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)

java_test(
    name = "DefaultingCertificatesConfigProviderTest",
    size = "small",
    srcs = ["DefaultingCertificatesConfigProviderTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)
