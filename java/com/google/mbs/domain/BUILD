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

java_library(
    name = "domain",
    srcs = [
        "AttestationCollector.java",
        "AttestationToken.java",
        "BundleCorruptedException.java",
        "CertificateMonitor.java",
        "KeyBackup.java",
        "KeyBackupAccessFailedException.java",
        "KeyBackupBucketProperties.java",
        "KeyBackupIncompleteException.java",
        "KeyBackupNotFoundException.java",
        "KeyBackupPartiallyWrittenException.java",
        "KeyBackupStorage.java",
        "KeyBackupStorageException.java",
        "KmsClientInterface.java",
        "KmsException.java",
        "KmsGeneratedKey.java",
        "MeasurementBoundCertificate.java",
        "MeasurementBoundCertificateProvider.java",
        "MeasurementBoundCertificateReloader.java",
        "Metrics.java",
        "StorageAlreadyLockedException.java",
        "TrustPackage.java",
    ],
    plugins = [":auto_value_plugin"],
    deps = [
        "@maven//:com_google_auto_value_auto_value_annotations",
        "@maven//:org_jspecify_jspecify",
    ],
)
