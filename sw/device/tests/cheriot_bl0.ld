/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Linker script for a CHERIoT first Silicon Owner stage in NVM slot A.
 *
 * This is a cut-down version of `bare_metal_slot_a.ld` plus
 * `bare_metal_common.ld`. It differs in two ways:
 *
 * - There is no `.data`/`.bss` and no CRT, because the C runtime is RV32-only.
 *   The image is pure text and rodata, so nothing needs relocating into SRAM.
 * - Sections that can hold a capability are 8-byte aligned.
 *
 * `_rom_ext_size` and the rest of the slot geometry arrive as `--defsym` link
 * flags from the execution environment's `slot_spec`.
 */

OUTPUT_ARCH(riscv)

/**
 * Indicate that there are no dynamic libraries, whatsoever.
 */
__DYNAMIC = 0;

/**
 * This linker script is preprocessed, OPENTITAN_TOP_MEMORY_LD is a define
 * pointing to the memory layout of the selected top.
 */
INCLUDE OPENTITAN_TOP_MEMORY_LD

/* Slot A starts at the start of NVM plus the fixed size of the ROM_EXT. */
_slot_start_address = ORIGIN(nvm) + _rom_ext_size;

/* Bounded to leave `_nvm_slot_reserved_bytes` empty at the end of Slot A. */
MEMORY {
  cheriot_slot_a(rx) : ORIGIN = _slot_start_address, LENGTH = LENGTH(nvm) / 2 - _rom_ext_size - _nvm_slot_reserved_bytes
}
REGION_ALIAS("owner_nvm", cheriot_slot_a);

/**
 * Marking the entry point correctly for the ELF file. The signer tool will
 * transfer this value to the `entry_point` field of the manifest, which the
 * ROM_EXT then uses to hand over execution.
 */
ENTRY(_start_boot)

/*
 * Manifest fields that depend on the link, consumed by the `.manifest` section
 * in `cheriot_bl0.S`. These mirror the definitions in `bare_metal_common.ld`.
 */
_manifest_code_start = _text_start - _slot_start_address;
_manifest_code_end = _text_end - _slot_start_address;
_manifest_entry_point = _start_boot - _slot_start_address;

/*
 * The value kHardenedBoolFalse (0x1d4) is selected if the code is linked in
 * the NVM region.  Otherwise, the value kHardenedBoolTrue (0x739) is
 * selected.
 */
_manifest_address_translation = (_text_start >= ORIGIN(nvm) &&
                                 _text_start < (ORIGIN(nvm)
                                              + LENGTH(nvm))) ? 0x1d4 : 0x739;

SECTIONS {
  .manifest _slot_start_address : {
    KEEP(*(.manifest))
    . = ALIGN(256);
  } > owner_nvm

  /**
   * Ibex interrupt vector, which must be 256-byte aligned.
   */
  .vectors : ALIGN(256) {
    _text_start = .;
    KEEP(*(.vectors))
  } > owner_nvm

  .crt : ALIGN(4) {
    KEEP(*(.crt))
  } > owner_nvm

  .text : ALIGN(4) {
    *(.text)
    *(.text.*)

    /* Ensure section end is word-aligned. */
    . = ALIGN(4);
    _text_end = .;
  } > owner_nvm

  /**
   * A CHERIoT capability occupies 8 bytes of addressable memory (plus a
   * validity tag held out of band), so anything that can hold one is 8-byte
   * aligned.
   */
  .rodata : ALIGN(8) {
    *(.srodata)
    *(.srodata.*)
    *(.rodata)
    *(.rodata.*)
  } > owner_nvm

  /**
   * `__cap_relocs` records the bounds and permissions for each static
   * capability. Nothing processes it in this image - there is no loader - but
   * it is kept so that its presence (or absence) is visible in the map file.
   */
  __cap_relocs : ALIGN(8) {
    __cap_relocs_start = .;
    KEEP(*(__cap_relocs))
    __cap_relocs_end = .;
  } > owner_nvm

  /DISCARD/ : {
    *(.comment)
    *(.note.*)
    *(.riscv.attributes)
  }
}
