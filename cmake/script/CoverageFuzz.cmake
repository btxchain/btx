# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(POLICY CMP0011)
  cmake_policy(SET CMP0011 NEW)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/CoverageInclude.cmake)

if(NOT DEFINED FUZZ_CORPORA_DIR)
  set(FUZZ_CORPORA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/qa-assets/fuzz_corpora)
endif()

set(fuzz_test_runner test/fuzz/test_runner.py ${FUZZ_CORPORA_DIR})
if(DEFINED JOBS)
  list(APPEND fuzz_test_runner -j ${JOBS})
endif()
if(COVERAGE_BACKEND STREQUAL "gcovr")
  coverage_reset_gcov_data()
endif()

execute_process(
  COMMAND ${fuzz_test_runner} --loglevel DEBUG
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  COMMAND_ERROR_IS_FATAL ANY
)
if(COVERAGE_BACKEND STREQUAL "lcov")
  execute_process(
    COMMAND ${LCOV_COMMAND} --capture --directory src --test-name fuzz-tests --output-file fuzz.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --zerocounters --directory src
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_FILTER_COMMAND} fuzz.info fuzz_filtered.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --add-tracefile fuzz_filtered.info --output-file fuzz_filtered.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${LCOV_COMMAND} --add-tracefile baseline_filtered.info --add-tracefile fuzz_filtered.info --output-file fuzz_coverage.info
    COMMAND ${GREP_EXECUTABLE} "%"
    COMMAND ${AWK_EXECUTABLE} "{ print substr($3,2,50) \"/\" $5 }"
    OUTPUT_FILE coverage_percent.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${GENHTML_COMMAND} fuzz_coverage.info --output-directory fuzz.coverage
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
else()
  set(fuzz_tracefile "${CMAKE_CURRENT_LIST_DIR}/fuzz.trace.json")
  coverage_capture_gcovr_trace("${fuzz_tracefile}")
  coverage_write_gcovr_report("${CMAKE_CURRENT_LIST_DIR}/fuzz.coverage/index.html" "${fuzz_tracefile}")
  coverage_write_gcovr_summary("${CMAKE_CURRENT_LIST_DIR}/coverage_percent.txt" "${fuzz_tracefile}")
  coverage_reset_gcov_data()
endif()
