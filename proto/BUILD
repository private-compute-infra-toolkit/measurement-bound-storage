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

load("@com_google_protobuf//bazel:java_proto_library.bzl", "java_proto_library")

package(default_visibility = ["//visibility:public"])

# google.mbs.v1.CertificatesConfig is owned by the PCIT API repository
# (api/google/mbs/v1/certificates_config.proto), which only ships the
# proto_library; the Java bindings are generated here.
java_proto_library(
    name = "certificates_config_java_proto",
    deps = ["@pcit_api//google/mbs/v1:certificates_config_proto"],
)
