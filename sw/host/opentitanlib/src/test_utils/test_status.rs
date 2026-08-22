// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TestStatus {
    InBootRom = bindgen::test_status::test_status_kTestStatusInBootRom,
    InBootRomHalt = bindgen::test_status::test_status_kTestStatusInBootRomHalt,
    InTest = bindgen::test_status::test_status_kTestStatusInTest,
    InWfi = bindgen::test_status::test_status_kTestStatusInWfi,
    Passed = bindgen::test_status::test_status_kTestStatusPassed,
    Failed = bindgen::test_status::test_status_kTestStatusFailed,
}

impl TestStatus {
    // Return a string describing the pattern that can be expected on the output
    // console when the device code calls `test_set_status(status)`. This pattern
    // can be used to wait until the device has printed this message.
    //
    // Note that `InBootRom` never reaches the console: the test ROM sets it
    // before bringing up the UART, so the device side deliberately skips the
    // log and only writes the status to `kDeviceTestStatusAddress`. Waiting on
    // its pattern will always time out.
    pub fn wait_pattern(&self) -> String {
        match self {
            TestStatus::Passed => "PASS!".into(),
            TestStatus::Failed => "FAIL!".into(),
            x => format!("test_status_set to 0x{:x}", *x as u32),
        }
    }
}
