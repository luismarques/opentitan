# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

package(default_visibility = ["//visibility:public"])

# The keysets are depended on for their key files: they carry the proprietary
# RAW and the PKCS#8 encoding of the same application keys.
sh_test(
    name = "spx_key_convert_test",
    srcs = ["spx_key_convert_test.sh"],
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:slh_dsa_keyset",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset",
        "//sw/host/opentitantool",
    ],
)
