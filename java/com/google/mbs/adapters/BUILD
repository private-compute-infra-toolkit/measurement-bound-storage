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

load("@rules_java//java:defs.bzl", "java_library")

package(default_visibility = ["//visibility:public"])

java_library(
    name = "adapters",
    srcs = [
        "AeadSelfSignedBundleBackupSealer.java",
        "AwsAttestationCollector.java",
        "AwsKmsClient.java",
        "BackupBucketProperties.java",
        "BackupBucketPropertiesFactory.java",
        "CertificatesConfigBucketProperties.java",
        "CertificatesConfigMapper.java",
        "DefaultCrossSignedCertificateBackupGenerator.java",
        "DefaultSelfSignedCertificateFactory.java",
        "DefaultingCertificatesConfigProvider.java",
        "PemCertificateCodec.java",
        "S3BackupPaths.java",
        "S3BackupReader.java",
        "S3BackupStorage.java",
        "S3BackupWriter.java",
        "S3CertificatesConfigProvider.java",
        "S3CompleteCrossSignedCertificateBackupHandle.java",
        "S3CompleteSelfSignedBundleBackupHandle.java",
        "S3EmptyCrossSignedCertificateBackupHandle.java",
        "S3EmptySelfSignedBundleBackupHandle.java",
        "S3StorageSnapshot.java",
        "ScheduledCertificateMonitor.java",
        "SelfSignedBundleBackupElement.java",
    ],
    plugins = [
        "//java/com/google/mbs/domain:auto_value_plugin",
    ],
    runtime_deps = [
        "@maven//:com_google_flogger_flogger_system_backend",
    ],
    deps = [
        "//java/com/google/mbs/adapters/nsm",
        "//java/com/google/mbs/domain",
        "//java/com/google/mbs/qualifier",
        "//proto:certificates_config_java_proto",
        "@com_google_protobuf//:protobuf_java",
        "@maven//:com_google_auto_value_auto_value_annotations",
        "@maven//:com_google_crypto_tink_tink",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:software_amazon_awssdk_auth",
        "@maven//:software_amazon_awssdk_kms",
        "@maven//:software_amazon_awssdk_regions",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)
