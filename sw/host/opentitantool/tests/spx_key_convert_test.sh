#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Exercise `opentitantool spx key convert` over the encodings it supports,
# using the checked-in fake application keys as the input.
#
# The proprietary RAW file and the PKCS#8 file for a given key are supposed to
# hold the same key material -- the whole SLH-DSA keyset rests on that -- so
# the conversions are checked against the committed files rather than against
# keys this test generates itself.

set -euo pipefail

function run() {
    echo "+ $*"
    "$@"
}

readonly OTTOOL="sw/host/opentitantool/opentitantool"
readonly KEYS="sw/device/silicon_creator/lib/ownership/keys/fake"

# `spx key show` prints the public key of either half of a key pair, in any
# encoding, so it is how this test asks "are these the same key?".
function key_of() {
    ${OTTOOL} --rcfile= spx key show "$1" | grep otp_encoded
}

function same_key() {
    local what="$1" a b
    a="$(key_of "$2")"
    b="$(key_of "$3")"
    if [[ "${a}" != "${b}" ]]; then
        echo "FAIL: ${what}: $2 and $3 hold different keys"
        echo "  $2: ${a}"
        echo "  $3: ${b}"
        exit 1
    fi
    echo "ok: ${what}"
}

echo "### RAW -> PKCS#8 PEM reproduces the committed file ###"
run ${OTTOOL} --rcfile= spx key convert --format pkcs8-pem \
    ${KEYS}/app_prod_spx.pem converted.pkcs8.pem
run cmp converted.pkcs8.pem ${KEYS}/app_prod_slh_dsa.pem

echo "### RAW -> PKCS#8 DER, and the DER key is the same key ###"
run ${OTTOOL} --rcfile= spx key convert --format pkcs8-der \
    ${KEYS}/app_prod_spx.pem converted.der
run ${OTTOOL} --rcfile= spx key convert --format pkcs8-der --public \
    ${KEYS}/app_prod_spx.pem converted.pub.der
same_key "DER private key" converted.der ${KEYS}/app_prod_spx.pem
same_key "DER public key" converted.pub.der ${KEYS}/app_prod_spx.pem

echo "### the DER file really is DER, not PEM ###"
if head -c 11 converted.der | grep -q -- "-----BEGIN"; then
    echo "FAIL: --format pkcs8-der wrote a PEM file"
    exit 1
fi
echo "ok: converted.der is not PEM"

echo "### PKCS#8 DER -> RAW round trips back to the same key ###"
run ${OTTOOL} --rcfile= spx key convert --format pem converted.der roundtrip.pem
same_key "DER -> RAW round trip" roundtrip.pem ${KEYS}/app_prod_spx.pem

echo "### a DER key signs, and its signature verifies against every encoding ###"
echo "opentitantool spx key convert test" >message.bin
run ${OTTOOL} --rcfile= spx sign --domain=Pure \
    message.bin converted.der --output=message.sig
for key in converted.pub.der converted.pkcs8.pem ${KEYS}/app_prod_spx.pem \
           ${KEYS}/app_prod_slh_dsa.pem; do
    run ${OTTOOL} --rcfile= spx verify --domain=Pure "${key}" message.bin message.sig
done

echo "### and does not verify under a different key ###"
if ${OTTOOL} --rcfile= spx verify --domain=Pure \
       ${KEYS}/app_dev_spx.pem message.bin message.sig 2>/dev/null; then
    echo "FAIL: signature verified under app_dev's key"
    exit 1
fi
echo "ok: rejected under a different key"

echo "PASS"
