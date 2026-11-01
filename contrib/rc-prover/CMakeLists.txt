# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.22)
  project(BTXRCTransportTest LANGUAGES CXX)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  enable_testing()
else()
  add_executable(btx-rc-prover btx-rc-prover.cpp)
  target_link_libraries(btx-rc-prover core_interface)
  target_link_btx_linux_archive_group(btx-rc-prover ${BTX_BASE_ARCHIVES})
  add_executable(btx-rc-replay-policy-test replay_policy_test.cpp)
  target_link_libraries(btx-rc-replay-policy-test PRIVATE core_interface)
  add_test(NAME btx_rc_replay_policy COMMAND btx-rc-replay-policy-test)
  add_executable(btx-rc-request-protocol-test request_protocol_test.cpp
    ${PROJECT_SOURCE_DIR}/src/arith_uint256.cpp
    ${PROJECT_SOURCE_DIR}/src/uint256.cpp
    ${PROJECT_SOURCE_DIR}/src/util/strencodings.cpp
    ${PROJECT_SOURCE_DIR}/src/crypto/hex_base.cpp
    ${PROJECT_SOURCE_DIR}/src/support/cleanse.cpp)
  target_link_libraries(btx-rc-request-protocol-test PRIVATE core_interface univalue)
  add_test(NAME btx_rc_request_protocol COMMAND btx-rc-request-protocol-test)
  if(WIN32)
    target_link_libraries(btx-rc-prover ws2_32 advapi32)
  endif()
endif()
add_executable(btx-rc-socket-test socket_io_test.cpp)
add_executable(btx-rc-listener-test request_listener_test.cpp)
add_executable(btx-rc-token-file-test token_file_test.cpp)
if(WIN32)
  target_link_libraries(btx-rc-socket-test PRIVATE ws2_32)
  target_link_libraries(btx-rc-listener-test PRIVATE ws2_32)
  target_link_libraries(btx-rc-token-file-test PRIVATE advapi32)
endif()
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME btx_rc_socket_transport
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_socket_io.py $<TARGET_FILE:btx-rc-socket-test>)
  add_test(NAME btx_rc_request_listener
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_request_listener.py $<TARGET_FILE:btx-rc-listener-test>)
  add_test(NAME btx_rc_token_file
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_token_file.py $<TARGET_FILE:btx-rc-token-file-test>)
  set_tests_properties(btx_rc_socket_transport btx_rc_request_listener btx_rc_token_file PROPERTIES TIMEOUT 30)
endif()
