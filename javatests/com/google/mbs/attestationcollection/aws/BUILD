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

load("@rules_java//java:defs.bzl", "java_library", "java_test")

package(default_visibility = ["//visibility:public"])

java_library(
    name = "tests",
    srcs = [
        "AwsAttestationCollectorTest.java",
    ],
    resources = ["res/tca_root_certificate.pem"],
    deps = [
        "//java/com/google/mbs/attestationcollection",
        "//java/com/google/mbs/attestationcollection/aws",
        "//java/com/google/platform/aws/nsm",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_inject_guice",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "AwsAttestationCollectorTest",
    size = "small",
    test_class = "com.google.mbs.attestationcollection.aws.AwsAttestationCollectorTest",
    runtime_deps = [
        ":tests",
    ],
)
