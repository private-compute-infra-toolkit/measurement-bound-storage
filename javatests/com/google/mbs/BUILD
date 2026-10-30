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

load("@rules_java//java:defs.bzl", "java_test")

package(default_visibility = ["//visibility:public"])

java_test(
    name = "MbsModuleTest",
    size = "small",
    srcs = ["MbsModuleTest.java"],
    deps = [
        "//java/com/google/mbs:dummy_cert_provider",
        "//java/com/google/mbs:module",
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/adapters/nsm",
        "//java/com/google/mbs/domain",
        "//java/com/google/mbs/qualifier",
        "@maven//:com_google_inject_guice",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
        "@maven//:software_amazon_awssdk_s3",
    ],
)

java_test(
    name = "MbsIntegrationTest",
    size = "medium",
    srcs = ["MbsIntegrationTest.java"],
    tags = [
        "exclusive",
        "requires-docker",
        "requires-network",
    ],
    deps = [
        "//java/com/google/mbs:module",
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "//java/com/google/mbs/dummy",
        "//java/com/google/mbs/qualifier",
        "//javatests/com/google/mbs/testing",
        "//proto:certificates_config_java_proto",
        "@com_google_protobuf//:protobuf_java",
        "@maven//:com_google_inject_extensions_guice_testlib",
        "@maven//:com_google_inject_guice",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_testcontainers_localstack",
        "@maven//:org_testcontainers_testcontainers",
        "@maven//:software_amazon_awssdk_auth",
        "@maven//:software_amazon_awssdk_http_client_spi",
        "@maven//:software_amazon_awssdk_regions",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)
