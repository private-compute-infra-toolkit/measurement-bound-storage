# Copyright 2025 Google LLC
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
    name = "certmanagement",
    srcs = [
        "KeyBackupBucketProperties.java",
        "KeyBackupBucketPropertiesFactory.java",
        "KeyPairs.java",
        "KmsMeasurementBoundCertificateProvider.java",
        "MbsCertificateFactory.java",
        "MeasurementBoundCertificate.java",
        "MeasurementBoundCertificateProvider.java",
        "Metrics.java",
        "NoOpMetrics.java",
    ],
    plugins = [":auto_value_plugin"],
    runtime_deps = [
        "@maven//:com_google_flogger_flogger_system_backend",
    ],
    deps = [
        "//java/com/google/kmsclient",
        "//java/com/google/kmsclient/aws",
        "//java/com/google/mbs/attestationcollection",
        "//java/com/google/tlog",
        "@maven//:com_google_auto_value_auto_value_annotations",
        "@maven//:com_google_crypto_tink_tink",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:software_amazon_awssdk_auth",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)

java_library(
    name = "dummy_cert_provider",
    srcs = ["DummyMeasurementBoundCertificateProvider.java"],
    deps = [
        ":certmanagement",
        "//java/com/google/mbs/attestationcollection",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)
