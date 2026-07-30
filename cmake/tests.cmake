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
endif()

# The parser suite is a POSIX shell test. Register it whenever the standalone
# report target is part of a test-enabled Unix build so CI/CTest exercises the
# exact built binary rather than relying on a manual contrib invocation.
if(BUILD_TESTS AND UNIX AND TARGET matmul-v4-report)
  add_test(NAME matmul_v4_report_cli
    COMMAND ${PROJECT_SOURCE_DIR}/contrib/matmul-v4/test-report-cli.sh $<TARGET_FILE:matmul-v4-report>
  )
endif()
