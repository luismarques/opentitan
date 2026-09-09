# OpenTitan RISC-V toolchain

This directory contains the Bazel configuration for OpenTitan's RISC-V
toolchain.

This LLVM toolchain comes from the [lowrisc-toolchains] repository. See
`third_party/lowrisc/extensions.bzl` for changing the toolchain version.

It is currently pinned to an untagged CHERIoT-capable LLVM 22 build from the CI
long-term cache rather than to a tagged release, because CHERIoT support has not
shipped in one yet.

[lowrisc-toolchains]: https://github.com/lowRISC/lowrisc-toolchains

## Configuration

There are four rules used to configure the toolchain:

1. `cc_toolchain`: groups flags, features, and tools into a toolchain.
2. `cc_tool_map`: assigns tools to actions.
3. `cc_args`: defines flags to add to tools based on actions.
3. `cc_feature`: allows `cc_args` flags to be conditionally enabled.

To add new flags to a tool in the toolchain, define a new `cc_args` target
and assign it to some actions (e.g. compiling C code, linking, etc.). Add the
new flags to `cc_toolchain.args`.

To make flags optional, define a new `cc_feature` for those `cc_args`. Features
can be enabled at the command line using `bazel --features=$feature_name`. Add
the flags to `cc_toolchain.known_features` and optionally to
`cc_toolchain.enabled_features`.

Bazel has three built-in features called `dbg`, `fastbuild`, and `opt` that can
be used to enable and disable flags at different optimization levels.

## CHERIoT

There are two `cc_toolchain`s here: `opentitan_toolchain` for plain RV32 and
`cheriot_toolchain` for the CHERIoT ISA. Both run the same binaries from the
same toolchain archive and share everything in `COMMON_TOOLCHAIN_ARGS` and
`COMMON_TOOLS`; they differ only in the ISA/ABI flags they pass and in which
objdump they disassemble with. Anything that is not ISA-specific belongs in the
shared lists so that both toolchains pick it up.

The two are selected by the `:isa` constraint setting, whose default is
`:isa_rv32`. `:opentitan_platform` therefore resolves to the RV32 toolchain
without naming the setting, and `:cheriot_platform` resolves to the CHERIoT one.
Use `--config=cheriot` to build ordinary `cc_library` targets for CHERIoT.

An `opentitan_binary` is redirected at the CHERIoT toolchain by setting
`platform = CHERIOT_PLATFORM`, which keeps the manifest, signing and slot
geometry of the normal flow. `//sw/device/tests:cheriot_bl0_boot_test` uses that
to build a ROM -> ROM_EXT -> CHERIoT boot chain for the CW340, where the ROM_EXT
stays RV32 and only the owner stage is CHERIoT.

A few things about the CHERIoT side are worth knowing before writing code for
it:

- **CHERIoT is RV32E-based.** `-mcpu=cheriot-ibex` implies `e`, so only
  `x0`-`x15` exist: `a6`, `a7` and `s2`-`s11` are unavailable, which matters
  most for hand-written assembly.
- **Use `-mcpu=cheriot-ibex`, not `-mcpu=cheriot`.** The former matches the
  CHERIoT-capable Ibex in this top and includes the bitmanip extensions; the
  generic `cheriot` CPU omits them.
- **The extension set matches the RV32 one.** The CHERIoT arch strings are
  OpenTitan's RV32 arch strings with `i` replaced by `e` and `xcheriot` added,
  and nothing else. Keep them that way when either side changes, so that code
  does not silently get a different instruction set depending on which
  toolchain built it.
- **Use `-mabi=cheriot-baremetal`, not `-mabi=cheriot`.** The latter is the
  CHERIoT RTOS compartment ABI and expects a loader to resolve
  cross-compartment calls through import tables. Source can tell the two apart
  via `__CHERIOT_BAREMETAL__`.
- **Capabilities are 8 bytes** (`__SIZEOF_CHERI_CAPABILITY__`), so sections
  that can hold one need 8-byte alignment for their tags to line up with the
  meta SRAM words covering them.
- **The binutils objdump cannot disassemble CHERI instructions**; it renders
  them as bare `.insn` directives. `:cheriot_tool_map` therefore points the
  objdump action at `llvm-objdump`. The two do not take the same arguments, so
  the flags live on each toolchain as a `cc_args` on the objdump action rather
  than in `obj_disassemble`.
- **LTO is disabled**, because the toolchain gets it wrong for CHERIoT. See the
  comment on `:cheriot_toolchain`.
- **No OpenTitan library that contains code builds for CHERIoT yet.** Purecap
  rejects the integer-to-pointer casts in `hardened.h`, `abs_mmio.h` and their
  dependents, which rules out the OTTF, the CRT and `manifest_def`. Only headers
  that are purely address and register definitions are usable, so a CHERIoT
  image is assembly for now, and has to set `use_exec_env_libs = False` to stop
  its execution environment linking in RV32 support libraries.
