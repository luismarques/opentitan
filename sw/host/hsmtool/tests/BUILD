# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

package(default_visibility = ["//visibility:public"])

sh_library(
    name = "test_lib",
    srcs = ["test_lib.sh"],
)

[
    sh_test(
        name = "slh_dsa_generate_test_{}".format(parameter_set),
        srcs = ["hsmtool_runner.sh"],
        args = [
            "--module=$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
            "--token=fake_keys -u user -p 123456",
            "slh-dsa",
            "generate",
            "--label fake",
            "--parameter-set {}".format(parameter_set),
        ],
        data = [
            "//signing/softhsm",
            "//signing/softhsm:conf",
            "//sw/host/hsmtool",
            "@softhsm2//:gen_dir",
        ],
        env = {
            "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
        },
        deps = [":test_lib"],
    )
    for parameter_set in [
        "sha2-128s",
        "shake-128s",
        "sha2-128f",
        "shake-128f",
        "sha2-192s",
        "shake-192s",
        "sha2-192f",
        "shake-192f",
        "sha2-256s",
        "shake-256s",
        "sha2-256f",
        "shake-256f",
    ]
]

sh_test(
    name = "slh_dsa_roundtrip_test",
    srcs = ["hsmtool_roundtrip_runner.sh"],
    args = [
        "slh-dsa",
        "fake_app_prod_slh_dsa",
        "$(rootpath :tqbf.txt)",
    ],
    data = [
        "tqbf.txt",
        "//signing/softhsm",
        "//signing/softhsm:conf",
        "//sw/host/hsmtool",
        "@softhsm2//:gen_dir",
    ],
    env = {
        "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
        "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
    },
    deps = [":test_lib"],
)

sh_test(
    name = "token_exists_test",
    srcs = ["hsmtool_runner.sh"],
    args = [
        "--module=$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
        "--token=fake_keys",
        "token",
        "list",
    ],
    data = [
        "//signing/softhsm",
        "//signing/softhsm:conf",
        "//sw/host/hsmtool",
        "@softhsm2//:gen_dir",
    ],
    env = {
        "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
    },
    deps = [":test_lib"],
)

genrule(
    name = "tqbf_digest",
    srcs = ["tqbf.txt"],
    outs = ["tqbf.digest"],
    cmd = """
        sha256sum $< | cut -f1 -d' ' | tr '[:lower:]' '[:upper:]' | basenc -d --base16 > $@
    """,
)

# ECDSA-Sign a digest with opentitantool and then verify the signature with hsmtool.
sh_test(
    name = "ecdsa_opentitantool_sign_hsmtool_verify_test",
    srcs = ["ot_hsm_runner.sh"],
    data = [
        ":tqbf_digest",
        "//signing/softhsm",
        "//signing/softhsm:conf",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset",
        "//sw/host/hsmtool",
        "//sw/host/opentitantool",
        "@softhsm2//:gen_dir",
    ],
    env = {
        "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
        "FIRST": "opentitantool",
        "OTTOOL_ARGS": """
            --rcfile=
            ecdsa sign
                sw/device/silicon_creator/lib/ownership/keys/fake/app_prod_ecdsa_p256.der
                --input=$(rootpath :tqbf_digest)
                --output=tqbf.ecdsa_sig
        """,
        "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
        "HSMTOOL_ARGS": """
            -t fake_keys -u user -p 123456
            ecdsa verify
                --little-endian
                --label=fake_app_prod_ecdsa
                $(rootpath :tqbf_digest)
                tqbf.ecdsa_sig
        """,
    },
    deps = [":test_lib"],
)

# ECDSA-Sign a digest with hsmtool and then verify the signature with opentitantool.
sh_test(
    name = "ecdsa_hsmtool_sign_opentitantool_verify_test",
    srcs = ["ot_hsm_runner.sh"],
    data = [
        "tqbf.txt",
        ":tqbf_digest",
        "//signing/softhsm",
        "//signing/softhsm:conf",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_pub",
        "//sw/host/hsmtool",
        "//sw/host/opentitantool",
        "@softhsm2//:gen_dir",
    ],
    env = {
        "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
        "FIRST": "hsmtool",
        "OTTOOL_ARGS": """
            --rcfile=
            ecdsa verify
                --digest-file=$(rootpath :tqbf_digest)
                --signature-file=tqbf.ecdsa_sig
                sw/device/silicon_creator/lib/ownership/keys/fake/app_prod_ecdsa_p256.pub.der
        """,
        "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
        # This hsmtool invocation computes the digest from the plain-text `tqbf.txt` input file.
        "HSMTOOL_ARGS": """
            -t fake_keys -u user -p 123456
            ecdsa sign
                --little-endian
                --format=plain-text
                --label=fake_app_prod_ecdsa
                --output=tqbf.ecdsa_sig
                sw/host/hsmtool/tests/tqbf.txt
        """,
    },
    deps = [":test_lib"],
)

_SPX_TESTS = {
    "pure": {
        "domain": "Pure",
        "format": "plain-text",
        "rev_flag": "--spx-hash-reversal-bug=false",
    },
    "prehashed": {
        "domain": "PreHashedSha256",
        "format": "sha256-hash",
        "rev_flag": "--spx-hash-reversal-bug=false",
    },
    "hashreversed": {
        "domain": "PreHashedSha256",
        "format": "sha256-hash-reversed",
        "rev_flag": "--spx-hash-reversal-bug=true",
    },
}

# The two backends hsmtool can sign SPHINCS+/SLH-DSA with, each paired with the
# opentitantool-side file holding the same key in the encoding that backend
# uses.  Both keys are the same key material (see the `spx key convert`
# invocations in the commit that created the SLH-DSA files), so a signature made
# on either side must verify on the other.
#
# `spx` keeps the key in a CKO_DATA object and signs in software with the
# SPHINCS+ reference implementation, which is the same code opentitantool uses.
# Those tests therefore exercise the plumbing around the signature -- digest
# selection, domain separation and the hash reversal quirk -- rather than the
# signature algorithm itself.
#
# `slh-dsa` uses native PKCS#11 CKK_SLH_DSA objects, so the token signs with
# SoftHSM's OpenSSL-backed SLH-DSA.  Those tests are the cross-implementation
# check: reference SPHINCS+ against OpenSSL, in both directions.  They are also
# the only coverage of CKM_HASH_SLH_DSA, which the prehashed domains select.
_SPX_BACKENDS = {
    "spx": {
        "command": "spx",
        "label": "fake_app_prod_spx",
        "key": "app_prod_spx.pem",
        "keyset": "//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset",
        # `hsmtool spx verify` takes <INPUT> <SIGNATURE>.
        "verify_args": "$(rootpath :tqbf_digest)\n                    tqbf.spx_sig",
    },
    "slh_dsa": {
        "command": "slh-dsa",
        "label": "fake_app_prod_slh_dsa",
        "key": "app_prod_slh_dsa.pem",
        "keyset": "//sw/device/silicon_creator/lib/ownership/keys/fake:slh_dsa_keyset",
        # `hsmtool slh-dsa verify` takes <SIGNATURE> <INPUT>, the opposite order
        # from every other hsmtool verify subcommand.
        "verify_args": "tqbf.spx_sig\n                    $(rootpath :tqbf_digest)",
    },
}

# The pre-hashed domains select CKM_HASH_SLH_DSA, which the vendored SoftHSM
# does not implement yet, so both the sign and the verify side of those
# combinations fail with CKR_MECHANISM_INVALID.  The `_BROKEN_ON_SLH_DSA` tags
# below keep those four targets defined and runnable against a patched SoftHSM
# while excluding them from CI, rather than dropping the coverage entirely.
_BROKEN_ON_SLH_DSA = {"PreHashedSha256": ["broken"], "Pure": []}

# Sign a digest with opentitantool and then verify the signature with hsmtool.
[
    sh_test(
        name = "{}_{}_opentitantool_sign_hsmtool_verify_test".format(backend_name, name),
        srcs = ["ot_hsm_runner.sh"],
        data = [
            ":tqbf_digest",
            "//signing/softhsm",
            "//signing/softhsm:conf",
            backend["keyset"],
            "//sw/host/hsmtool",
            "//sw/host/opentitantool",
            "@softhsm2//:gen_dir",
        ],
        env = {
            "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
            "FIRST": "opentitantool",
            "OTTOOL_ARGS": """
                --rcfile=
                spx sign {rev_flag}
                    --domain={domain}
                    $(rootpath :tqbf_digest)
                    sw/device/silicon_creator/lib/ownership/keys/fake/{key}
                    --output=tqbf.spx_sig
            """.format(
                domain = param["domain"],
                key = backend["key"],
                rev_flag = param["rev_flag"],
            ),
            "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
            "HSMTOOL_SPX_MODULE": "pkcs11-ef",
            "HSMTOOL_ARGS": """
                -t fake_keys -u user -p 123456
                {command} verify
                    --label={label}
                    --domain={domain}
                    --format={fmt}
                    {verify_args}
            """.format(
                command = backend["command"],
                domain = param["domain"],
                fmt = param["format"],
                label = backend["label"],
                verify_args = backend["verify_args"],
            ),
        },
        tags = _BROKEN_ON_SLH_DSA[param["domain"]] if backend_name == "slh_dsa" else [],
        deps = [":test_lib"],
    )
    for name, param in _SPX_TESTS.items()
    for backend_name, backend in _SPX_BACKENDS.items()
]

# Sign a digest with hsmtool and then verify the signature with opentitantool.
[
    sh_test(
        name = "{}_{}_hsmtool_sign_opentitantool_verify_test".format(backend_name, name),
        srcs = ["ot_hsm_runner.sh"],
        data = [
            ":tqbf_digest",
            "//signing/softhsm",
            "//signing/softhsm:conf",
            backend["keyset"],
            "//sw/host/hsmtool",
            "//sw/host/opentitantool",
            "@softhsm2//:gen_dir",
        ],
        env = {
            "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
            "FIRST": "hsmtool",
            "OTTOOL_ARGS": """
                --rcfile=
                spx verify {rev_flag}
                    --domain={domain}
                    sw/device/silicon_creator/lib/ownership/keys/fake/{key}
                    $(rootpath :tqbf_digest)
                    tqbf.spx_sig
            """.format(
                domain = param["domain"],
                key = backend["key"],
                rev_flag = param["rev_flag"],
            ),
            "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
            "HSMTOOL_SPX_MODULE": "pkcs11-ef",
            "HSMTOOL_ARGS": """
                -t fake_keys -u user -p 123456
                {command} sign
                    --label={label}
                    --domain={domain}
                    --format={fmt}
                    --output=tqbf.spx_sig
                    $(rootpath :tqbf_digest)
            """.format(
                command = backend["command"],
                domain = param["domain"],
                fmt = param["format"],
                label = backend["label"],
            ),
        },
        tags = _BROKEN_ON_SLH_DSA[param["domain"]] if backend_name == "slh_dsa" else [],
        deps = [":test_lib"],
    )
    for name, param in _SPX_TESTS.items()
    for backend_name, backend in _SPX_BACKENDS.items()
]

filegroup(
    name = "image_bin",
    # A hand assembled binary image.
    # dd if=/dev/zero of=image.bin bs=1k count=1
    # Then, use hexdump tools (e.g. `xxd` and `xxd -r`) to insert the following bytes:
    #
    # 00000330: 0000 0000 4f54 5245 476c 0200 0004 0000  ................
    # 00000340: 0004 0000 0000 0000 0000 0000 0000 0000  ................
    #
    # This sets the identifier, manifest_version, signed_region_end and length fields.
    srcs = ["image.bin"],
)

genrule(
    name = "image_digest",
    srcs = [":image_bin"],
    outs = ["image.digest"],
    # Opentitantool computes the digest by excluding the signature region of the manifest.
    # The signature region is the first 384 bytes.
    cmd = """
        dd if=$< bs=1 skip=384 | sha256sum - | cut -f1 -d' ' | tr '[:lower:]' '[:upper:]' | basenc -d --base16 > $@
    """,
)

# Verify the opentitantool image digest calculation.
sh_test(
    name = "image_digest_test",
    srcs = ["image_digest_test.sh"],
    data = [
        ":image_bin",
        ":image_digest",
        "//sw/host/opentitantool",
    ],
    env = {
        "IMAGE_BIN": "$(rootpath :image_bin)",
        "KNOWN_DIGEST": "$(rootpath :image_digest)",
    },
    deps = [":test_lib"],
)

# ECDSA-Sign an image with opentitantool and then verify the signature with hsmtool.
sh_test(
    name = "manifest_opentitantool_sign_hsmtool_verify_test",
    srcs = ["ot_hsm_runner.sh"],
    data = [
        ":image_bin",
        "//signing/softhsm",
        "//signing/softhsm:conf",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset",
        "//sw/host/hsmtool",
        "//sw/host/opentitantool",
        "@softhsm2//:gen_dir",
    ],
    env = {
        "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
        "FIRST": "opentitantool",
        "OTTOOL_ARGS": """
            --rcfile=
            image manifest update
                --ecdsa-key=sw/device/silicon_creator/lib/ownership/keys/fake/app_prod_ecdsa_p256.der
                --output=image.signed_bin
                $(rootpath :image_bin)
        """,
        "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
        "HSMTOOL_ARGS": """
            -t fake_keys -u user -p 123456
            ecdsa verify
                --little-endian
                --label=fake_app_prod_ecdsa
                --format=slice:384..1024
                --signature-at=0..64
                image.signed_bin
        """,
    },
    deps = [":test_lib"],
)

# ECDSA-Sign an image with hsmtool and then verify the signature with opentitantool.
sh_test(
    name = "manifest_hsmtool_sign_opentitantool_verify_test",
    srcs = ["ot_hsm_runner.sh"],
    data = [
        ":image_bin",
        "//signing/softhsm",
        "//signing/softhsm:conf",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_pub",
        "//sw/host/hsmtool",
        "//sw/host/opentitantool",
        "@softhsm2//:gen_dir",
    ],
    env = {
        "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
        "FIRST": "hsmtool",
        "PREPARE_CMD": """
            sw/host/opentitantool/opentitantool image manifest update
                --ecdsa-key=sw/device/silicon_creator/lib/ownership/keys/fake/app_prod_ecdsa_p256.pub.der
                --output=image.signed_bin
                $(rootpath :image_bin)
        """,
        "OTTOOL_ARGS": """
            --rcfile=
            image manifest verify
                image.signed_bin
        """,
        "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
        "HSMTOOL_ARGS": """
            -t fake_keys -u user -p 123456
            ecdsa sign
                --little-endian
                --label=fake_app_prod_ecdsa
                --format=slice:384..1024
                --update-in-place=0..64
                image.signed_bin
        """,
    },
    deps = [":test_lib"],
)

# The tests above hold the key encoding fixed per backend, so each one only
# proves that a file and the token object derived from it agree.  Nothing in
# them would notice if app_prod_slh_dsa.pem stopped being app_prod_spx.pem
# re-encoded, because the RAW file pairs with the CKO_DATA object and the
# PKCS#8 file pairs with the CKK_SLH_DSA object, and the two pairs never meet.
#
# These two deliberately cross the encoding instead: the proprietary RAW file
# on the opentitantool side against the native SLH-DSA token object, in both
# directions.  They are the only check that the two encodings name one key.
# One domain is enough; the domain axis is swept above.
sh_test(
    name = "spx_raw_key_slh_dsa_token_opentitantool_sign_hsmtool_verify_test",
    srcs = ["ot_hsm_runner.sh"],
    data = [
        ":tqbf_digest",
        "//signing/softhsm",
        "//signing/softhsm:conf",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset",
        "//sw/host/hsmtool",
        "//sw/host/opentitantool",
        "@softhsm2//:gen_dir",
    ],
    env = {
        "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
        "FIRST": "opentitantool",
        "OTTOOL_ARGS": """
            --rcfile=
            spx sign --spx-hash-reversal-bug=false
                --domain=Pure
                $(rootpath :tqbf_digest)
                sw/device/silicon_creator/lib/ownership/keys/fake/app_prod_spx.pem
                --output=tqbf.spx_sig
        """,
        "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
        "HSMTOOL_ARGS": """
            -t fake_keys -u user -p 123456
            slh-dsa verify
                --label=fake_app_prod_slh_dsa
                --domain=Pure
                --format=plain-text
                tqbf.spx_sig
                $(rootpath :tqbf_digest)
        """,
    },
    deps = [":test_lib"],
)

sh_test(
    name = "spx_raw_key_slh_dsa_token_hsmtool_sign_opentitantool_verify_test",
    srcs = ["ot_hsm_runner.sh"],
    data = [
        ":tqbf_digest",
        "//signing/softhsm",
        "//signing/softhsm:conf",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset",
        "//sw/host/hsmtool",
        "//sw/host/opentitantool",
        "@softhsm2//:gen_dir",
    ],
    env = {
        "SOFTHSM2_CONF": "$(rootpath //signing/softhsm:conf)",
        "FIRST": "hsmtool",
        "OTTOOL_ARGS": """
            --rcfile=
            spx verify --spx-hash-reversal-bug=false
                --domain=Pure
                sw/device/silicon_creator/lib/ownership/keys/fake/app_prod_spx.pem
                $(rootpath :tqbf_digest)
                tqbf.spx_sig
        """,
        "HSMTOOL_MODULE": "$(rootpath @softhsm2//:gen_dir)/lib/softhsm/libsofthsm2.so",
        "HSMTOOL_ARGS": """
            -t fake_keys -u user -p 123456
            slh-dsa sign
                --label=fake_app_prod_slh_dsa
                --domain=Pure
                --format=plain-text
                --output=tqbf.spx_sig
                $(rootpath :tqbf_digest)
        """,
    },
    deps = [":test_lib"],
)
