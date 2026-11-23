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

load("@rules_java//java:defs.bzl", "java_binary", "java_library")

package(default_visibility = ["//visibility:public"])

java_library(
    name = "root_certificates_tool_lib",
    srcs = ["RootCertificatesTool.java"],
    deps = [
        "//java/com/google/mbs/adapters",
        "//java/com/google/mbs/domain",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
    ],
)

java_binary(
    name = "root_certificates_tool",
    main_class = "com.google.mbs.tools.RootCertificatesTool",
    runtime_deps = [":root_certificates_tool_lib"],
)
