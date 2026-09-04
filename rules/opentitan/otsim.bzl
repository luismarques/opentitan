# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""The `sim_otsim` execution environment.

`otsim` is an OpenTitan emulator built outside Bazel which speaks the
opentitanlib proxy protocol, so a test drives it through the `proxy` transport
exactly as it would drive a session serving a real board.  Unlike the other
simulators there is no image to bootstrap and no bitstream to load: otsim reads
the ROM and the flash image straight out of their ELF files, so the generated
test script launches the emulator, waits for its proxy port, and runs the test
harness against it.

The emulator is not a Bazel target, so its location has to come from outside
the build.  In order of preference:

  * the `OTSIM` environment variable (`.bazelrc` passes it through to tests),
  * `--define otsim=/path/to/otsim`,
  * `_DEFAULT_OTSIM` below.

Bazel runs tests with `HOME` unset, so the default cannot be written relative
to the home directory and is spelled out in full instead.  That, and the fact
that otsim is not vendored anywhere, is why none of this is fit to upstream.
"""

load(
    "@lowrisc_opentitan//rules/opentitan:providers.bzl",
    "Cw310BinaryInfo",
)
load(
    "@lowrisc_opentitan//rules/opentitan:util.bzl",
    "assemble_for_test",
    "get_fallback",
    "recursive_format",
)
load(
    "//rules/opentitan:exec_env.bzl",
    "ExecEnvInfo",
    "common_test_setup",
    "exec_env_as_dict",
    "exec_env_common_attrs",
)
load("//rules/opentitan:toolchain.bzl", "LOCALTOOLS_TOOLCHAIN")

# Where otsim is checked out and built on this machine.
_DEFAULT_OTSIM = "/home/luismarques/otsim/otsim"

def otsim_params(
        tags = [],
        timeout = "short",
        test_harness = None,
        binaries = {},
        rom = None,
        rom_ext = None,
        otp = None,
        bitstream = None,
        test_cmd = "",
        data = [],
        defines = [],
        max_steps = None,
        otsim_args = [],
        **kwargs):
    """A macro to create otsim parameters for OpenTitan tests.

    Args:
      tags: The test tags to apply to the test rule.
      timeout: The timeout to apply to the test rule.
      test_harness: Use an alternative test harness for this test.
      binaries: Dict of binary labels to substitution parameter names.
      rom: Use an alternate ROM for this test.
      rom_ext: Use an alternate ROM_EXT for this test.
      otp: Use an alternate OTP configuration for this test.
      bitstream: Unused; accepted so that `fpga_params` blocks can be reused.
      test_cmd: Use an alternate test_cmd for this test.
      data: Additional files needed by this test.
      defines: Additional preprocessor defines for this test.
      max_steps: Instruction budget for the emulator.  Unbounded by default,
                 which leaves the harness's own timeout in charge of ending a
                 run that hangs.
      otsim_args: Additional arguments to pass to the emulator.
      kwargs: Additional key-value pairs to override in the test `param` dict.
    Returns:
      struct of test parameters.
    """
    extra_params = {
        "otsim_args": json.encode(otsim_args),
    }
    if max_steps != None:
        extra_params["max_steps"] = str(max_steps)

    return struct(
        # The emulator runs outside the sandbox, so the test has to as well.
        tags = ["local"] + tags,
        timeout = timeout,
        test_harness = test_harness,
        binaries = binaries,
        rom = rom,
        rom_ext = rom_ext,
        otp = otp,
        bitstream = bitstream,
        test_cmd = test_cmd,
        data = data,
        defines = defines,
        param = kwargs | extra_params,
    )

def _transform(ctx, exec_env, name, elf, binary, signed_bin, disassembly, mapfile):
    """Transform binaries into the preferred forms for sim_otsim.

    otsim loads programs from ELF files, so unlike the FPGA environments this
    needs neither a scrambled ROM vmem nor a flash image.

    Args:
      ctx: The rule context.
      exec_env: The ExecEnvInfo for this environment.
      name: The rule name/basename.
      elf: The compiled elf program.
      binary: The raw binary of the compiled program.
      signed_bin: The signed binary (if available).
      disassembly: A disassembly listing.
      mapfile: The linker-created mapfile.
    Returns:
      dict: A dict of fields to create in the provider.
    """
    if ctx.attr.kind == "rom":
        default = elf
        rom = elf
    elif ctx.attr.kind == "ram":
        default = elf
        rom = None
    elif ctx.attr.kind == "flash":
        default = signed_bin if signed_bin else binary
        rom = None
    else:
        fail("Not implemented: kind ==", ctx.attr.kind)

    return {
        "elf": elf,
        "binary": binary,
        "default": default,
        "rom": rom,
        "signed_bin": signed_bin,
        "disassembly": disassembly,
        "mapfile": mapfile,
    }

def _test_dispatch(ctx, exec_env, firmware):
    """Dispatch a test for the sim_otsim environment.

    Args:
      ctx: The rule context.
      exec_env: The ExecEnvInfo for this environment.
      firmware: A label with a Cw310BinaryInfo provider attached.
    Returns:
      (File, List[File]) The test script and needed runfiles.
    """
    test_harness, data_labels, data_files, param, action_param = common_test_setup(ctx, exec_env, firmware)

    # If the test requested an assembled image, then use opentitantool to
    # assemble the image.  Replace the firmware param with the newly assembled
    # image.
    if "assemble" in param:
        assemble = param.get("assemble")
        assemble = recursive_format(assemble, action_param)
        assemble = ctx.expand_location(assemble, data_labels)
        image = assemble_for_test(
            ctx,
            name = ctx.attr.name,
            spec = assemble.strip().split(" "),
            data_files = data_files,
            opentitantool = exec_env._opentitantool,
        )
        param["firmware"] = image.short_path
        action_param["firmware"] = image.path
        data_files.append(image)

    # otsim boots out of ELF files rather than out of a programmed flash, so
    # both images are named by their ELF and there is nothing to bootstrap.
    rom_elf = param.get("rom:elf", "")
    if not rom_elf:
        fail("{}: the sim_otsim environment needs a ROM with an ELF file".format(ctx.attr.name))
    flash_elf = param.get("firmware:elf", "")

    otsim_args = json.decode(param.get("otsim_args", "[]"))
    if "max_steps" in param:
        otsim_args = ["--max-steps", param["max_steps"]] + otsim_args
    otsim_args = " ".join(["'{}'".format(a) for a in otsim_args])

    # Get the pre-test_cmd args.
    args = get_fallback(ctx, "attr.args", exec_env)
    args = " ".join(args).format(**param)
    args = ctx.expand_location(args, data_labels)

    # Pair the `test_cmd` with the test harness: if the test brings its own
    # harness, the environment's default `test_cmd` does not apply to it.
    if ctx.attr.test_harness:
        test_cmd = ctx.attr.test_cmd
    else:
        test_cmd = exec_env.test_cmd
    test_cmd = test_cmd.format(**param)
    test_cmd = ctx.expand_location(test_cmd, data_labels)

    script = ctx.actions.declare_file(ctx.attr.name + ".bash")
    ctx.actions.expand_template(
        template = exec_env.test_script,
        output = script,
        is_executable = True,
        substitutions = {
            "__" + key + "__": val
            for (key, val) in {
                "args": args,
                "flash_elf": flash_elf,
                "otp": param.get("otp", ""),
                "otsim": ctx.var.get("otsim", _DEFAULT_OTSIM),
                "otsim_args": otsim_args,
                "rom_elf": rom_elf,
                "test_cmd": test_cmd,
                "test_harness": test_harness.executable.short_path,
            }.items()
        },
    )
    data_files.append(exec_env._opentitantool.executable)

    return script, data_files

def _sim_otsim(ctx):
    fields = exec_env_as_dict(ctx)
    return ExecEnvInfo(
        # otsim emulates the CW310 target, and reusing its provider means the
        # ROM and any other prebuilt image are taken from the `fpga_cw310`
        # build rather than needing an otsim build of their own.
        provider = Cw310BinaryInfo,
        test_dispatch = _test_dispatch,
        transform = _transform,
        test_script = ctx.file._test_script,
        **fields
    )

sim_otsim = rule(
    implementation = _sim_otsim,
    attrs = exec_env_common_attrs() | {
        "_test_script": attr.label(
            allow_single_file = True,
            default = "//rules/scripts:otsim_test.sh",
        ),
    },
    toolchains = [LOCALTOOLS_TOOLCHAIN],
)
