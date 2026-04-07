# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(POLICY CMP0011)
  cmake_policy(SET CMP0011 NEW)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/CoverageInclude.cmake)

set(functional_test_runner test/functional/test_runner.py)
if(EXTENDED_FUNCTIONAL_TESTS)
  list(APPEND functional_test_runner --extended)
endif()
if(DEFINED JOBS)
  list(APPEND CMAKE_CTEST_COMMAND -j ${JOBS})
  list(APPEND functional_test_runner -j ${JOBS})
endif()
if(COVERAGE_BACKEND STREQUAL "gcovr")
  coverage_reset_gcov_data()
endif()

execute_process(
  COMMAND ${CMAKE_CTEST_COMMAND} --build-config Coverage
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
if(COVERAGE_BACKEND STREQUAL "lcov")
  execute_process(
    COMMAND ${LCOV_COMMAND} --capture --directory src --test-name test_btx --output-file test_btx.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --zerocounters --directory src
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_FILTER_COMMAND} test_btx.info test_btx_filtered.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --add-tracefile test_btx_filtered.info --output-file test_btx_filtered.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --add-tracefile baseline_filtered.info --add-tracefile test_btx_filtered.info --output-file test_btx_coverage.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${GENHTML_COMMAND} test_btx_coverage.info --output-directory test_btx.coverage
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
else()
  set(test_btx_tracefile "${CMAKE_CURRENT_LIST_DIR}/test_btx.trace.json")
  set(functional_tracefile "${CMAKE_CURRENT_LIST_DIR}/functional_test.trace.json")

  coverage_capture_gcovr_trace("${test_btx_tracefile}")
  coverage_write_gcovr_report("${CMAKE_CURRENT_LIST_DIR}/test_btx.coverage/index.html" "${test_btx_tracefile}")
  coverage_reset_gcov_data()
endif()

execute_process(
  COMMAND ${functional_test_runner}
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
if(COVERAGE_BACKEND STREQUAL "lcov")
  execute_process(
    COMMAND ${LCOV_COMMAND} --capture --directory src --test-name functional-tests --output-file functional_test.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --zerocounters --directory src
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_FILTER_COMMAND} functional_test.info functional_test_filtered.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --add-tracefile functional_test_filtered.info --output-file functional_test_filtered.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --add-tracefile baseline_filtered.info --add-tracefile test_btx_filtered.info --add-tracefile functional_test_filtered.info --output-file total_coverage.info
    COMMAND ${GREP_EXECUTABLE} "%"
    COMMAND ${AWK_EXECUTABLE} "{ print substr($3,2,50) \"/\" $5 }"
    OUTPUT_FILE coverage_percent.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${GENHTML_COMMAND} total_coverage.info --output-directory total.coverage
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
else()
  coverage_capture_gcovr_trace("${functional_tracefile}")
  coverage_write_gcovr_report("${CMAKE_CURRENT_LIST_DIR}/total.coverage/index.html" "${test_btx_tracefile}" "${functional_tracefile}")
  coverage_write_gcovr_summary("${CMAKE_CURRENT_LIST_DIR}/coverage_percent.txt" "${test_btx_tracefile}" "${functional_tracefile}")
  coverage_reset_gcov_data()
endif()
