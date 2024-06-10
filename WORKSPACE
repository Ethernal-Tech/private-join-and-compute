# Copyright 2019 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""WORKSPACE file for Private Join and Compute."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("//bazel:pjc_deps.bzl", "pjc_deps")

pjc_deps()

# gRPC
# must be included separately, since we need to load transitive deps of grpc.
http_archive(
    name = "com_github_grpc_grpc",
    sha256 = "feaeeb315133ea5e3b046c2c0231f5b86ef9d297e536a14b73e0393335f8b157", 
    strip_prefix = "grpc-1.51.3",
    urls = [
        "https://github.com/grpc/grpc/archive/v1.51.3.tar.gz",
    ],
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
grpc_deps()

load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")
grpc_extra_deps()

load("@rules_python//python:pip.bzl", "pip_parse")

pip_parse(
    name = "pip_deps",
    requirements_lock = ":requirements.txt",
)

load("@pip_deps//:requirements.bzl", "install_deps")

install_deps()

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_foreign_cc",
    # TODO: Get the latest sha256 value from a bazel debug message or the latest 
    #       release on the releases page: https://github.com/bazelbuild/rules_foreign_cc/releases
    #
    # sha256 = "...",
    strip_prefix = "rules_foreign_cc-0.9.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/0.9.0.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies()

all_content = """filegroup(name = "libsodium_all", srcs = glob(["**"]), visibility = ["//visibility:public"])"""

http_archive(
    name = "libsodium",
    url = "https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable.tar.gz",
    strip_prefix = "libsodium-stable",
    build_file_content = all_content
)
