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

load("@rules_java//java:defs.bzl", "java_library")

package(default_visibility = ["//visibility:public"])

alias(
    name = "dummy_cert_provider",
    actual = "//java/com/google/mbs/dummy:dummy_cert_provider",
)

java_library(
    name = "module",
    srcs = [
        "AwsMbsModule.java",
        "MbsCoreModule.java",
        "MbsModule.java",
    ],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/adapters/nsm",
        "//java/com/google/mbs/domain",
        "//java/com/google/mbs/qualifier",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_inject_guice",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:software_amazon_awssdk_auth",
        "@maven//:software_amazon_awssdk_kms",
        "@maven//:software_amazon_awssdk_regions",
        "@maven//:software_amazon_awssdk_s3",
    ],
)

java_library(
    name = "mbs",
    exports = [
        ":module",
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "//java/com/google/mbs/qualifier",
    ],
)

alias(
    name = "nsm_jni_tar",
    actual = "//java/com/google/mbs/adapters/nsm:nsm_jni_tar",
)
