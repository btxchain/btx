# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

set(CMAKE_AUTOMOC_MOC_OPTIONS "-p${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(test_btx-qt
  apptests.cpp
  optiontests.cpp
  rpcnestedtests.cpp
  test_main.cpp
  uritests.cpp
  util.cpp
  ../../init/bitcoin-qt.cpp
)

target_link_libraries(test_btx-qt
  core_interface
  bitcoinqt
  test_util
  bitcoin_node
  Boost::headers
  "Qt${WITH_QT_VERSION}::Test"
)

import_plugins(test_btx-qt)

if(ENABLE_WALLET)
  target_sources(test_btx-qt
    PRIVATE
      addressbooktests.cpp
      wallettests.cpp
      ../../wallet/test/wallet_test_fixture.cpp
  )
endif()

add_test(NAME test_btx-qt
  COMMAND test_btx-qt
)
if(WIN32 AND VCPKG_TARGET_TRIPLET)
  # On Windows, vcpkg configures Qt with `-opengl dynamic`, which makes
  # the "minimal" platform plugin unusable due to internal Qt bugs.
  set_tests_properties(test_btx-qt PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=windows"
  )
endif()

install_binary_component(test_btx-qt)

# Keep backward-compatible CMake build target name for existing automation.
add_custom_target(test_bitcoin-qt DEPENDS test_btx-qt)
# Keep legacy executable name available for existing CI and packaging scripts.
add_legacy_binary_alias(test_btx-qt test_bitcoin-qt)
