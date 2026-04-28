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

load("@rules_rust//rust:defs.bzl", "rust_static_library")

package(default_visibility = ["//visibility:public"])

rust_static_library(
    name = "libnsm_static",
    srcs = ["nsm-lib/src/lib.rs"],
    # Set 2021 edition to disable unsafe no_mangle attribute error
    edition = "2021",
    deps = [
        "@crates//:aws-nitro-enclaves-nsm-api",
        "@crates//:serde_bytes",
    ],
)
