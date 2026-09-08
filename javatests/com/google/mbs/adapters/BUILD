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
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
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
