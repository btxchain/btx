cmake_minimum_required(VERSION 3.22)
project(BTXModelSecurityComponents LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(BTX_SOURCE_ROOT "" CACHE PATH "BTX PR245 source checkout")
set(BTX_SECURITY_OVERLAY "" CACHE PATH "Changeset overlay root; empty when applied")
if(NOT BTX_SOURCE_ROOT)
  get_filename_component(BTX_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
endif()
if(NOT BTX_SECURITY_OVERLAY)
  set(BTX_SECURITY_OVERLAY "${BTX_SOURCE_ROOT}")
endif()
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)
set(PQC "${BTX_SOURCE_ROOT}/src/libbitcoinpqc")
add_library(btx_security_crypto STATIC
  ${BTX_SOURCE_ROOT}/src/crypto/sha384.cpp
  ${PQC}/src/ml_dsa/utils.c ${PQC}/src/ml_dsa/keygen.c
  ${PQC}/src/ml_dsa/sign.c ${PQC}/src/ml_dsa/verify.c
  ${PQC}/dilithium/ref/sign.c ${PQC}/dilithium/ref/packing.c
  ${PQC}/dilithium/ref/polyvec.c ${PQC}/dilithium/ref/poly.c
  ${PQC}/dilithium/ref/ntt.c ${PQC}/dilithium/ref/reduce.c
  ${PQC}/dilithium/ref/rounding.c ${PQC}/dilithium/ref/fips202.c
  ${PQC}/dilithium/ref/symmetric-shake.c ${PQC}/dilithium/ref/randombytes_custom.c)
target_include_directories(btx_security_crypto PUBLIC ${BTX_SOURCE_ROOT}/src ${PQC}/include ${PQC}/dilithium/ref)
target_compile_definitions(btx_security_crypto PRIVATE DILITHIUM_MODE=2 CUSTOM_RANDOMBYTES=1 randombytes=btx_mldsa_randombytes)
add_library(btx_security_json STATIC
  ${BTX_SOURCE_ROOT}/src/univalue/lib/univalue.cpp
  ${BTX_SOURCE_ROOT}/src/univalue/lib/univalue_get.cpp
  ${BTX_SOURCE_ROOT}/src/univalue/lib/univalue_read.cpp
  ${BTX_SOURCE_ROOT}/src/univalue/lib/univalue_write.cpp)
target_include_directories(btx_security_json PUBLIC ${BTX_SOURCE_ROOT}/src/univalue/include)
file(GLOB SECURITY_SOURCES CONFIGURE_DEPENDS "${BTX_SECURITY_OVERLAY}/src/modelnet/security_v2/*.cpp")
list(FILTER SECURITY_SOURCES EXCLUDE REGEX "/(native|main)\\.cpp$")
add_library(btx_model_security STATIC ${SECURITY_SOURCES})
target_include_directories(btx_model_security PUBLIC ${BTX_SECURITY_OVERLAY}/src ${BTX_SOURCE_ROOT}/src)
target_link_libraries(btx_model_security PUBLIC btx_security_crypto btx_security_json SQLite::SQLite3 Threads::Threads)
if(MSVC)
  target_compile_options(btx_model_security PRIVATE /W4 /WX)
  target_link_libraries(btx_model_security PUBLIC bcrypt advapi32)
else()
  target_compile_options(btx_model_security PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
add_executable(security-tests security_tests.cpp)
target_link_libraries(security-tests PRIVATE btx_model_security)
if(EXISTS "${BTX_SECURITY_OVERLAY}/src/modelnet/security_v2/main.cpp")
  add_executable(btx-security ${BTX_SECURITY_OVERLAY}/src/modelnet/security_v2/main.cpp)
  target_link_libraries(btx-security PRIVATE btx_model_security)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(security-probe sandbox_probe.c)
  target_link_options(security-probe PRIVATE -static)
endif()
enable_testing()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_test(NAME security-core COMMAND security-tests $<TARGET_FILE:security-probe>)
else()
  add_test(NAME security-core COMMAND security-tests)
endif()

# Test the actual PR245 supervisor and guard after applying integration edits.
set(BTX_INTEGRATED_SOURCE "${BTX_SOURCE_ROOT}" CACHE PATH "Tree containing integration-edited native files")
if(EXISTS "${BTX_INTEGRATED_SOURCE}/src/btx-guardd.cpp")
  add_executable(btx-guardd-security
    ${BTX_INTEGRATED_SOURCE}/src/btx-guardd.cpp
    ${BTX_SOURCE_ROOT}/src/modelnet/guard_machine.cpp)
  target_compile_definitions(btx-guardd-security PRIVATE BTX_MODEL_SECURITY_V2=1)
  target_link_libraries(btx-guardd-security PRIVATE btx_model_security)
  add_executable(security-native-ipc native_ipc_tests.cpp
    ${BTX_INTEGRATED_SOURCE}/src/modelnet/guard_supervisor.cpp
    ${BTX_SOURCE_ROOT}/src/modelnet/guard_machine.cpp)
  target_include_directories(security-native-ipc BEFORE PRIVATE ${BTX_INTEGRATED_SOURCE}/src)
  target_compile_definitions(security-native-ipc PRIVATE BTX_MODEL_SECURITY_V2=1)
  target_link_libraries(security-native-ipc PRIVATE btx_model_security)
  add_test(NAME security-native-ipc COMMAND security-native-ipc $<TARGET_FILE:btx-guardd-security>)
endif()
