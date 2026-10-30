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

load("@rules_java//java:defs.bzl", "java_library", "java_plugin")

package(default_visibility = ["//visibility:public"])

java_plugin(
    name = "auto_value_plugin",
    processor_class = "com.google.auto.value.processor.AutoValueProcessor",
    deps = ["@maven//:com_google_auto_value_auto_value"],
)

java_plugin(
    name = "auto_builder_plugin",
    processor_class = "com.google.auto.value.processor.AutoBuilderProcessor",
    deps = ["@maven//:com_google_auto_value_auto_value"],
)

java_library(
    name = "domain",
    srcs = [
        "AttestationCollector.java",
        "AttestationToken.java",
        "BackupAccessFailedException.java",
        "BackupAlreadyExistsException.java",
        "BackupCorruptedException.java",
        "BackupIncompleteException.java",
        "BackupNotFoundException.java",
        "BackupPartiallyWrittenException.java",
        "BackupStorage.java",
        "BackupStorageAlreadyLockedException.java",
        "BackupStorageException.java",
        "CertificateCodec.java",
        "CertificateGenerator.java",
        "CertificateMonitor.java",
        "CertificatesConfig.java",
        "CertificatesConfigProvider.java",
        "CrossSignedCertificate.java",
        "CrossSignedCertificateBackup.java",
        "CrossSignedCertificateBackupGenerator.java",
        "CrossSignedCertificateBackupHandle.java",
        "CrossSignedCertificateId.java",
        "DefaultCertificateGenerator.java",
        "InvalidCertificatesConfigException.java",
        "KmsClientInterface.java",
        "KmsException.java",
        "KmsGeneratedKey.java",
        "Metrics.java",
        "SelfSignedBundle.java",
        "SelfSignedBundleBackup.java",
        "SelfSignedBundleBackupGenerator.java",
        "SelfSignedBundleBackupHandle.java",
        "SelfSignedBundleBackupSealer.java",
        "SelfSignedCertificate.java",
        "SelfSignedCertificateFactory.java",
        "StorageSnapshot.java",
        "TrustPackage.java",
        "TrustPackageProvider.java",
        "TrustPackageReloader.java",
        "TrustPackageService.java",
        "ValidityPeriod.java",
    ],
    plugins = [
        ":auto_builder_plugin",
        ":auto_value_plugin",
    ],
    runtime_deps = [
        "@maven//:com_google_flogger_flogger_system_backend",
    ],
    deps = [
        "//java/com/google/mbs/qualifier",
        "@maven//:com_google_auto_value_auto_value_annotations",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
        "@maven//:jakarta_inject_jakarta_inject_api",
    ],
)
