// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_aon_timer.h"
#include "sw/device/lib/dif/dif_lc_ctrl.h"
#include "sw/device/lib/dif/dif_pwrmgr.h"
#include "sw/device/lib/runtime/hart.h"
#include "sw/device/lib/testing/aon_timer_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

OTTF_DEFINE_TEST_CONFIG();

#define LC_TOKEN_SIZE 16
static const uint8_t kLcExitToken[LC_TOKEN_SIZE] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
};

static dif_lc_ctrl_t lc_ctrl;
static dif_aon_timer_t aon;

bool test_main(void) {
  // static const dt_aon_timer_t kAonTimerDt = 0;
  //CHECK_DIF_OK(dif_aon_timer_init_from_dt(kAonTimerDt, &aon));
  mmio_region_t base_addr = mmio_region_from_addr(TOP_EARLGREY_AON_TIMER_AON_BASE_ADDR);
  CHECK_DIF_OK(dif_aon_timer_init(base_addr, &aon));

  // dif_pwrmgr_t pwrmgr;
  // static const dt_pwrmgr_t kPwrmgrDt = 0;
  // CHECK_DIF_OK(dif_pwrmgr_init_from_dt(kPwrmgrDt, &pwrmgr));
  // CHECK_DIF_OK(dif_pwrmgr_init(mmio_region_from_addr(TOP_EARLGREY_PWRMGR_AON_BASE_ADDR),
  //                     &pwrmgr));
  // dif_pwrmgr_request_sources_t reset_sources;
  // CHECK_DIF_OK(dif_pwrmgr_find_request_source(
  //     &pwrmgr, kDifPwrmgrReqTypeReset, dt_aon_timer_instance_id(kAonTimerDt),
  //     kDtAonTimerResetReqAonTimer, &reset_sources));
  // CHECK_DIF_OK(dif_pwrmgr_set_request_sources(
  //     &pwrmgr, kDifPwrmgrReqTypeReset, reset_sources, kDifToggleEnabled));

  CHECK_DIF_OK(dif_lc_ctrl_init(
      mmio_region_from_addr(TOP_EARLGREY_LC_CTRL_BASE_ADDR), &lc_ctrl));

  // CHECK_DIF_OK(dif_lc_ctrl_init(
  //     mmio_region_from_addr(TOP_EARLGREY_LC_CTRL_REGS_BASE_ADDR), &lc_ctrl));

  dif_lc_ctrl_state_t lc_state = kDifLcCtrlStateInvalid;
  CHECK_DIF_OK(dif_lc_ctrl_get_state(&lc_ctrl, &lc_state));
  LOG_INFO("LC CTRL state = %d (kDifLcCtrlStateTestUnlocked1 == %d)\n", lc_state, kDifLcCtrlStateTestUnlocked1);
  if (lc_state == kDifLcCtrlStateProd) {
    return true;
  }
  uint8_t count;
  CHECK_DIF_OK(dif_lc_ctrl_get_attempts(&lc_ctrl, &count));
  LOG_INFO("count = %u", count);
  dif_lc_ctrl_status_t status;
  CHECK_DIF_OK(dif_lc_ctrl_get_status(&lc_ctrl, &status));
  LOG_INFO("status = %u", status);
  CHECK_DIF_OK(dif_lc_ctrl_mutex_try_acquire(&lc_ctrl));
  dif_lc_ctrl_token_t token;
  for (int i = 0; i < LC_TOKEN_SIZE; i++) {
    token.data[i] = kLcExitToken[i];
  }
  CHECK_DIF_OK(dif_lc_ctrl_configure(&lc_ctrl, kDifLcCtrlStateProd, false, &token));
  uint32_t bark_cycles = 0;
  uint32_t bite_cycles = 20000;
  // CHECK_STATUS_OK(aon_timer_testutils_get_aon_cycles_32_from_us(120 * 1000000,
  //                                                               &bark_cycles));
  // CHECK_STATUS_OK(aon_timer_testutils_get_aon_cycles_32_from_us(5 * 1000000,
  //                                                               &bite_cycles));
  CHECK_DIF_OK(dif_aon_timer_watchdog_start(&aon, bark_cycles, bite_cycles,
    false /* pause_in_sleep */, false /* lock */));
  LOG_INFO("performing transition\n");
  CHECK_DIF_OK(dif_lc_ctrl_transition(&lc_ctrl));
  while(1) {}
  LOG_INFO("transitioned\n");
  CHECK_DIF_OK(dif_lc_ctrl_get_state(&lc_ctrl, &lc_state));
  LOG_INFO("LC CTRL state = %d\n", lc_state);
  return true;
}
