#!/bin/bash
#
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# WARNING This is a template: the `__x__` strings are substituted by the rules
# in otsim.bzl.

set -e

export RUST_BACKTRACE=1

rom_elf="__rom_elf__"
flash_elf="__flash_elf__"
otp_vmem="__otp__"
otsim_args=( __otsim_args__ )
otsim_default="__otsim__"

test_harness="__test_harness__"
test_cmd=( __test_cmd__ )
args=( __args__ )
opentitantool="__opentitantool__"

# Split our own arguments: anything of the form `--otsim-arg=X` is meant for the
# emulator rather than for the test harness, so that a single run can turn an
# emulator option on without an edit.
#
#     bazel test //sw/device/tests:uart_smoketest_sim_otsim \
#         --test_arg=--otsim-arg=--verilated-uart
#
# `--otsim-args=X Y Z` does the same for several at once, and both come after
# whatever the test itself asked for, so a run wins over a BUILD file.
harness_args=()
for arg in "$@"; do
    case "${arg}" in
        --otsim-arg=*)
            otsim_args+=( "${arg#--otsim-arg=}" )
            ;;
        --otsim-args=*)
            read -r -a arg_words <<<"${arg#--otsim-args=}"
            otsim_args+=( "${arg_words[@]}" )
            ;;
        *)
            harness_args+=( "${arg}" )
            ;;
    esac
done

# Locate the emulator.  It is built outside Bazel, so the default path is baked
# in at analysis time; `$OTSIM` wins over it so that a single run can point at a
# different build without re-analysing.
otsim="${OTSIM:-${otsim_default}}"
if [[ ! -x "${otsim}" ]]; then
    echo "ERROR: '${otsim}' is not an executable, so there is no otsim to run" >&2
    echo "the test against.  Point at your build with either" >&2
    echo "" >&2
    echo "    export OTSIM=/path/to/otsim" >&2
    echo "" >&2
    echo "or '--define otsim=/path/to/otsim'." >&2
    exit 1
fi

# Pick a free port rather than otsim's default, so that concurrent tests (and a
# session the developer left running) do not collide.
proxy_port=""
for _ in $(seq 100); do
    candidate=$(( 20000 + RANDOM % 20000 ))
    if ! (exec 3<>"/dev/tcp/127.0.0.1/${candidate}") 2>/dev/null; then
        proxy_port="${candidate}"
        break
    fi
    exec 3>&- 3<&-
done
if [[ -z "${proxy_port}" ]]; then
    echo "ERROR: could not find a free TCP port for the otsim proxy." >&2
    exit 1
fi

otsim_pid=""

# Wait up to $1 tenths of a second for the emulator to go away.  Returns 0 if
# it did.
wait_for_otsim() {
    for _ in $(seq "$1"); do
        kill -0 "${otsim_pid}" 2>/dev/null || return 0
        sleep 0.1
    done
    ! kill -0 "${otsim_pid}" 2>/dev/null
}

cleanup() {
    ret=$?
    set +ex
    if [[ -n "${otsim_pid}" ]] && kill -0 "${otsim_pid}" 2>/dev/null; then
        # otsim keeps serving after the image has parked, because a host may
        # yet reset it and run something else, so ending the run is up to us.
        #
        # Ask over the proxy rather than signalling, because `Emu Stop` lets it
        # leave the way it would have on its own: it prints the transcript of
        # what the device wrote and exits on whether the image reported a pass.
        # A signal truncates both, so a failing test loses the `[otsim]` lines
        # that say where the machine actually stopped -- which is the part worth
        # reading.
        "${opentitantool}" --rcfile= --logging=error --interface=proxy \
            --proxy=localhost --port="${proxy_port}" emulator stop \
            >/dev/null 2>&1
        wait_for_otsim 50
        # And fall back to a signal, because the reasons this can fail are the
        # reasons cleanup exists: a bazel timeout can land while the socket is
        # mid-request, an emulator wedged before it served the port never
        # answers, and a build of otsim older than the fix that made `Emu Stop`
        # reachable at all replies "unknown emulator request: command".
        if kill -0 "${otsim_pid}" 2>/dev/null; then
            kill "${otsim_pid}" 2>/dev/null
            wait_for_otsim 20
            kill -KILL "${otsim_pid}" 2>/dev/null
        fi
    fi
    # Let the emulator's last output through the `sed` that prefixes it before
    # this script's own exit closes the pipe under it.
    if [[ -n "${otsim_pid}" ]]; then
        wait "${otsim_pid}" 2>/dev/null
    fi
    exit "${ret}"
}
# Bazel sends SIGTERM when the timeout expires and waits a moment before
# killing us, so this runs even on timeout.
trap cleanup EXIT

# otsim reads the OTP image from `img_rma.24.vmem` in its working directory,
# with no way to say otherwise, so give it a directory of its own with the
# environment's OTP image under that name.  Everything else is named by an
# absolute path, because that directory is not the runfiles tree.
runfiles="${PWD}"
work_dir="${TEST_TMPDIR:-${runfiles}}/otsim"
rm -rf "${work_dir}"
mkdir -p "${work_dir}"
if [[ -n "${otp_vmem}" ]]; then
    ln -s "${runfiles}/${otp_vmem}" "${work_dir}/img_rma.24.vmem"
fi

otsim_cmd=( "${otsim}" --headless --proxy "${proxy_port}" "${otsim_args[@]}" )
if [[ -n "${flash_elf}" ]]; then
    otsim_cmd+=( --flash "${runfiles}/${flash_elf}" )
fi
otsim_cmd+=( "${runfiles}/${rom_elf}" )

echo "Starting emulator in ${work_dir}: ${otsim_cmd[*]}"
( cd "${work_dir}" && exec "${otsim_cmd[@]}" ) > >(sed -u 's/^/[otsim] /') 2>&1 &
otsim_pid=$!

# Wait for the proxy to accept connections.  otsim opens the listener before it
# starts stepping the machine, so this is quick, but a cold start under load is
# not instant either.
connected=""
for _ in $(seq 300); do
    if ! kill -0 "${otsim_pid}" 2>/dev/null; then
        echo "ERROR: the emulator exited before it served the proxy port." >&2
        exit 1
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/${proxy_port}") 2>/dev/null; then
        exec 3>&- 3<&-
        connected=1
        break
    fi
    sleep 0.1
done
if [[ -z "${connected}" ]]; then
    echo "ERROR: the emulator did not open port ${proxy_port} within 30s." >&2
    exit 1
fi

set -x
"${test_harness}" "${args[@]}" --port="${proxy_port}" "${harness_args[@]}" "${test_cmd[@]}"
