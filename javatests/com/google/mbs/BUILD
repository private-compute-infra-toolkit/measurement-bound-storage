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
    name = "KmsMeasurementBoundCertificateProviderTest",
    size = "small",
    srcs = ["KmsMeasurementBoundCertificateProviderTest.java"],
    deps = [
        "//java/com/google/kmsclient",
        "//java/com/google/mbs:certmanagement",
        "//java/com/google/mbs/attestationcollection",
        "//java/com/google/tlog",
        "@maven//:com_google_code_gson_gson",
        "@maven//:com_google_crypto_tink_tink",
        "@maven//:com_google_guava_guava",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
        "@maven//:software_amazon_awssdk_auth",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
    ],
)

java_test(
    name = "KeyBackupBucketPropertiesFactoryTest",
    size = "small",
    srcs = ["KeyBackupBucketPropertiesFactoryTest.java"],
    deps = [
        "//java/com/google/mbs:certmanagement",
    ],
)

java_test(
    name = "MbsCertificateFactoryTest",
    size = "small",
    srcs = ["MbsCertificateFactoryTest.java"],
    deps = [
        "//java/com/google/mbs:certmanagement",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)
