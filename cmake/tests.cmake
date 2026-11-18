# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(TARGET btx-util AND TARGET btx-tx AND PYTHON_COMMAND)
  add_test(NAME util_test_runner
    COMMAND ${CMAKE_COMMAND} -E env BITCOINUTIL=$<TARGET_FILE:btx-util> BITCOINTX=$<TARGET_FILE:btx-tx> ${PYTHON_COMMAND} ${PROJECT_BINARY_DIR}/test/util/test_runner.py
  )
endif()

if(PYTHON_COMMAND)
  add_test(NAME util_rpcauth_test
    COMMAND ${PYTHON_COMMAND} ${PROJECT_BINARY_DIR}/test/util/rpcauth-test.py
  )
  if(UNIX)
    add_test(NAME matmul_v4_full_benchmark_wrapper
      COMMAND ${PYTHON_COMMAND} ${PROJECT_SOURCE_DIR}/contrib/matmul-v4/test_run_full_benchmark.py
    )
  endif()
endif()

if(BUILD_TESTS AND PYTHON_COMMAND
    AND CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_NAME STREQUAL "Linux"
    AND NOT CMAKE_CROSSCOMPILING AND CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$"
    AND (CMAKE_GENERATOR STREQUAL "Unix Makefiles" OR CMAKE_GENERATOR STREQUAL "Ninja"))
  add_test(NAME util_install_binary_component_runpath_test
    COMMAND ${PYTHON_COMMAND} ${PROJECT_SOURCE_DIR}/test/util/install_binary_component_runpath_test.py
      --cmake "${CMAKE_COMMAND}" --compiler "${CMAKE_CXX_COMPILER}"
      --generator "${CMAKE_GENERATOR}"
      --output-dir "${PROJECT_BINARY_DIR}/test/util/runpath-regression"
  )
  set_tests_properties(util_install_binary_component_runpath_test PROPERTIES
    TIMEOUT 120 PROCESSORS 1 LABELS "release;build"
  )
endif()
