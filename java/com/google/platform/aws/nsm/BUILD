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

load("@rules_cc//cc:defs.bzl", "cc_binary")
load("@rules_java//java:defs.bzl", "java_library")
load("@rules_pkg//:pkg.bzl", "pkg_tar")

package(default_visibility = ["//visibility:public"])

java_library(
    name = "nsm",
    srcs = [
        "AwsNsmModule.java",
        "DefaultNitroSecurityModuleFactory.java",
        "NitroSecurityModule.java",
        "NitroSecurityModuleFactory.java",
        "NsmJniResult.java",
    ],
    runtime_deps = [":nsm_jni"],
    deps = ["@maven//:com_google_inject_guice"],
)

cc_binary(
    name = "nsm_jni",
    srcs = ["nsm_jni.c"],
    copts = ["-Wno-implicit-function-declaration"],  # header libnsm.h is not generated along libnsm_static. We are using the library without including the header.
    linkshared = True,
    deps = [
        "@aws-nitro-enclaves-nsm-api_src//:libnsm_static",
        "@bazel_tools//tools/jdk:jni",
    ],
)

pkg_tar(
    name = "nsm_jni_tar",
    srcs = [
        ":nsm_jni",
    ],
    ownername = "root.root",
    package_dir = "/usr/lib/x86_64-linux-gnu/jni",
)
