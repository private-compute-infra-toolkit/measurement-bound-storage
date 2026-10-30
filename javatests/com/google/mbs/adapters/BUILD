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
    name = "PemCertificateCodecTest",
    size = "small",
    srcs = ["PemCertificateCodecTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)

java_test(
    name = "AeadSelfSignedBundleBackupSealerTest",
    size = "small",
    srcs = ["AeadSelfSignedBundleBackupSealerTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_crypto_tink_tink",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "DefaultSelfSignedCertificateFactoryTest",
    size = "small",
    srcs = ["DefaultSelfSignedCertificateFactoryTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)

java_test(
    name = "DefaultCrossSignedCertificateBackupGeneratorTest",
    size = "small",
    srcs = ["DefaultCrossSignedCertificateBackupGeneratorTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "S3BackupStorageTest",
    size = "small",
    srcs = ["S3BackupStorageTest.java"],
    deps = [
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
    name = "S3CompleteSelfSignedBundleBackupHandleTest",
    size = "small",
    srcs = ["S3CompleteSelfSignedBundleBackupHandleTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "S3CompleteCrossSignedCertificateBackupHandleTest",
    size = "small",
    srcs = ["S3CompleteCrossSignedCertificateBackupHandleTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "S3EmptySelfSignedBundleBackupHandleTest",
    size = "small",
    srcs = ["S3EmptySelfSignedBundleBackupHandleTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "S3EmptyCrossSignedCertificateBackupHandleTest",
    size = "small",
    srcs = ["S3EmptyCrossSignedCertificateBackupHandleTest.java"],
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
    name = "ScheduledCertificateMonitorTest",
    size = "small",
    srcs = ["ScheduledCertificateMonitorTest.java"],
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

java_test(
    name = "BackupBucketPropertiesFactoryTest",
    size = "small",
    srcs = ["BackupBucketPropertiesFactoryTest.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "@maven//:junit_junit",
    ],
)
