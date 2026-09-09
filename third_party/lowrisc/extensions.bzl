# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _lowrisc_repos():
    # A CHERIoT-capable LLVM 22 build of the toolchain, needed by
    # `//toolchain:cheriot_toolchain`. This is an untagged artifact from the CI
    # long-term cache rather than a `lowrisc-toolchains` release, so it carries
    # no version in its name; switch back to a release URL once one ships with
    # CHERIoT support.
    http_archive(
        name = "lowrisc_rv32imcb_toolchain",
        url = "https://storage.googleapis.com/lowrisc-ci-longterm-cache/lowrisc-toolchain-rv32imcb-x86_64-cheriot-lto2.tar.xz",
        sha256 = "61eb26a20c1ead5024cdb7e69e79b4ca42e7bc0e0f0eff962fecd56ab6024cd4",
        strip_prefix = "lowrisc-toolchain-rv32imcb-x86_64-",
        build_file = ":BUILD.lowrisc_rv32imcb_toolchain.bazel",
    )

lowrisc_rv32imcb_toolchain = module_extension(
    implementation = lambda _: _lowrisc_repos(),
)
