# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(generate_setup_nsi)
  set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
  set(abs_top_builddir ${PROJECT_BINARY_DIR})
  set(CLIENT_URL ${PROJECT_HOMEPAGE_URL})
  # Register the btx: URI scheme. Do not claim bitcoin: — that handler belongs
  # to Bitcoin Core.
  set(CLIENT_TARNAME "btx")
  set(BTX_GUI_NAME "btx-qt")
  set(BTX_DAEMON_NAME "btxd")
  set(BTX_CLI_NAME "btx-cli")
  set(BTX_TX_NAME "btx-tx")
  set(BTX_WALLET_TOOL_NAME "btx-wallet")
  set(BTX_TEST_NAME "test_btx")
  set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
  configure_file(${PROJECT_SOURCE_DIR}/share/setup.nsi.in ${PROJECT_BINARY_DIR}/btx-win64-setup.nsi USE_SOURCE_PERMISSIONS @ONLY)
endfunction()
