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

# java/com/google/kmsclient/aws/BUILD

load("@rules_java//java:defs.bzl", "java_library")

package(default_visibility = ["//visibility:public"])

java_library(
    name = "aws",
    srcs = [
        "AwsKmsClient.java",
        "AwsKmsClientModule.java",
    ],
    deps = [
        "//java/com/google/kmsclient",
        "//java/com/google/platform/aws/nsm",
        "@maven//:com_google_inject_guice",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:software_amazon_awssdk_auth",
        "@maven//:software_amazon_awssdk_kms",
        "@maven//:software_amazon_awssdk_regions",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)
