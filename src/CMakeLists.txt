# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(AddWindowsResources)

configure_file(${PROJECT_SOURCE_DIR}/cmake/bitcoin-build-config.h.in bitcoin-build-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

if(APPLE)
  option(BTX_ENABLE_METAL "Enable optional Metal acceleration helpers for BTX utilities" ON)
  function(find_btx_apple_framework out_var framework_name)
    set(framework_hints)
    if(CMAKE_OSX_SYSROOT)
      list(APPEND framework_hints
        "${CMAKE_OSX_SYSROOT}/System/Library/Frameworks"
        "${CMAKE_OSX_SYSROOT}/Library/Frameworks"
      )
    endif()
    if(CMAKE_FRAMEWORK_PATH)
      list(APPEND framework_hints ${CMAKE_FRAMEWORK_PATH})
    endif()
    if(CMAKE_SYSTEM_FRAMEWORK_PATH)
      list(APPEND framework_hints ${CMAKE_SYSTEM_FRAMEWORK_PATH})
    endif()
    list(REMOVE_DUPLICATES framework_hints)

    foreach(framework_dir IN LISTS framework_hints)
      set(framework_bundle "${framework_dir}/${framework_name}.framework")
      if(EXISTS "${framework_bundle}")
        set(${out_var} "${framework_bundle}" CACHE FILEPATH "Path to ${framework_name}.framework" FORCE)
        set(${out_var} "${framework_bundle}" PARENT_SCOPE)
        return()
      endif()
    endforeach()

    if(framework_hints)
      find_library(${out_var} NAMES ${framework_name} HINTS ${framework_hints} NO_DEFAULT_PATH)
    endif()
    if(NOT EXISTS "${${out_var}}")
      find_library(${out_var} NAMES ${framework_name})
    endif()
    if(EXISTS "${${out_var}}")
      set(${out_var} "${${out_var}}" PARENT_SCOPE)
      return()
    endif()

    if(NOT EXISTS "${${out_var}}")
      list(JOIN framework_hints ", " searched_framework_hints)
      if(searched_framework_hints)
        message(FATAL_ERROR "Unable to locate ${framework_name}.framework. Searched SDK/framework hints: ${searched_framework_hints}")
      else()
        message(FATAL_ERROR "Unable to locate ${framework_name}.framework.")
      endif()
    endif()
  endfunction()
else()
  option(BTX_ENABLE_METAL "Enable optional Metal acceleration helpers for BTX utilities" OFF)
endif()
option(BTX_ENABLE_CUDA_EXPERIMENTAL "Enable experimental CUDA backend scaffolding for BTX miner integration" OFF)
set(BTX_CUDA_ARCHITECTURES "" CACHE STRING "Semicolon-separated CUDA SM architectures for the experimental MatMul backend (for example 120)")
set(BTX_CUDA_RUNTIME_LIBRARY_DEFAULT "Shared")
if(DEFINED CMAKE_CUDA_RUNTIME_LIBRARY AND NOT CMAKE_CUDA_RUNTIME_LIBRARY STREQUAL "")
  set(BTX_CUDA_RUNTIME_LIBRARY_DEFAULT "${CMAKE_CUDA_RUNTIME_LIBRARY}")
endif()
set(BTX_CUDA_RUNTIME_LIBRARY_ALLOWED_VALUES Shared Static)
set(BTX_CUDA_RUNTIME_LIBRARY "${BTX_CUDA_RUNTIME_LIBRARY_DEFAULT}" CACHE STRING "CUDA runtime library linkage for the experimental CUDA backend: Shared or Static")
set_property(CACHE BTX_CUDA_RUNTIME_LIBRARY PROPERTY STRINGS Shared Static)

if(BTX_ENABLE_CUDA_EXPERIMENTAL)
  if(BTX_CUDA_ARCHITECTURES STREQUAL "" AND DEFINED CMAKE_CUDA_ARCHITECTURES AND NOT CMAKE_CUDA_ARCHITECTURES STREQUAL "")
    set(BTX_CUDA_ARCHITECTURES "${CMAKE_CUDA_ARCHITECTURES}" CACHE STRING "Semicolon-separated CUDA SM architectures for the experimental MatMul backend (for example 120)" FORCE)
  endif()
  if(BTX_CUDA_ARCHITECTURES STREQUAL "")
    message(FATAL_ERROR "BTX_ENABLE_CUDA_EXPERIMENTAL=ON requires BTX_CUDA_ARCHITECTURES to be set explicitly.")
  endif()
  set(CMAKE_CUDA_ARCHITECTURES "${BTX_CUDA_ARCHITECTURES}" CACHE STRING "CUDA architectures for compiler detection and BTX CUDA targets" FORCE)
  if(NOT BTX_CUDA_RUNTIME_LIBRARY IN_LIST BTX_CUDA_RUNTIME_LIBRARY_ALLOWED_VALUES)
    message(FATAL_ERROR "BTX_CUDA_RUNTIME_LIBRARY must be Shared or Static")
  endif()
  enable_language(CUDA)
  if(CMAKE_CUDA_COMPILER_ID STREQUAL "NVIDIA"
      AND CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL 12.0
      AND (NOT DEFINED CMAKE_CUDA20_STANDARD_COMPILE_OPTION OR CMAKE_CUDA20_STANDARD_COMPILE_OPTION STREQUAL ""))
    set(CMAKE_CUDA20_STANDARD_COMPILE_OPTION "-std=c++20")
    set(CMAKE_CUDA20_EXTENSION_COMPILE_OPTION "-std=c++20")
    set(CMAKE_CUDA20_COMPILE_FEATURES cuda_std_20)
    list(APPEND CMAKE_CUDA_COMPILE_FEATURES cuda_std_20)
  endif()
  find_package(CUDAToolkit REQUIRED)
  if(BTX_CUDA_RUNTIME_LIBRARY STREQUAL "Static" AND NOT TARGET CUDA::cudart_static)
    message(FATAL_ERROR "BTX_CUDA_RUNTIME_LIBRARY=Static requires CUDA::cudart_static from the selected CUDA toolkit.")
  endif()
endif()

# AMD ROCm/HIP backend for the MatMul v4 digest (src/hip/matmul_v4_accel.hip).
# Mirrors the experimental CUDA backend above but targets AMD CDNA (MFMA)
# accelerators via hipcc. Requires an explicit AMD GPU arch list (e.g. gfx942
# for MI300, gfx90a for MI200, gfx908 for MI100).
option(BTX_ENABLE_HIP "Enable experimental AMD ROCm/HIP MatMul v4 backend (requires ROCm/hipcc)" OFF)
set(BTX_HIP_ARCHITECTURES "" CACHE STRING "Semicolon-separated AMD GPU archs for the HIP MatMul backend (for example gfx942)")

if(BTX_ENABLE_HIP)
  if(BTX_HIP_ARCHITECTURES STREQUAL "" AND DEFINED CMAKE_HIP_ARCHITECTURES AND NOT CMAKE_HIP_ARCHITECTURES STREQUAL "")
    set(BTX_HIP_ARCHITECTURES "${CMAKE_HIP_ARCHITECTURES}" CACHE STRING "Semicolon-separated AMD GPU archs for the HIP MatMul backend (for example gfx942)" FORCE)
  endif()
  if(BTX_HIP_ARCHITECTURES STREQUAL "")
    message(FATAL_ERROR "BTX_ENABLE_HIP=ON requires BTX_HIP_ARCHITECTURES to be set explicitly (for example gfx942).")
  endif()
  set(CMAKE_HIP_ARCHITECTURES "${BTX_HIP_ARCHITECTURES}" CACHE STRING "AMD GPU architectures for BTX HIP targets" FORCE)
  enable_language(HIP)
  find_package(hip REQUIRED)
endif()

#=============================
# Subprojects
#=============================
# Subprojects include subdirectories that do or could have tests
# and/or benchmark binaries, such as all subtrees and univalue.
# These need to be included before CMAKE_*_OUTPUT_DIRECTORY variables
# are set, so output locations of subproject tests and libraries are
# not overridden.
if(NOT WITH_SYSTEM_LEVELDB)
include(../cmake/crc32c.cmake)
include(../cmake/leveldb.cmake)
endif()  # WITH_SYSTEM_LEVELDB

add_subdirectory(univalue)

if(NOT WITH_SYSTEM_LIBSECP256K1)
#=============================
# secp256k1 subtree
#=============================
message("")
message("Configuring secp256k1 subtree...")
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS ${BUILD_TESTS} CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS ${BUILD_TESTS} CACHE BOOL "" FORCE)
if(NOT BUILD_TESTS)
  # Always skip the ctime tests, if we are building no other tests.
  # Otherwise, they are built if Valgrind is available. See SECP256K1_VALGRIND.
  set(SECP256K1_BUILD_CTIME_TESTS ${BUILD_TESTS} CACHE BOOL "" FORCE)
endif()
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
include(GetTargetInterface)
# -fsanitize and related flags apply to both C++ and C,
# so we can pass them down to libsecp256k1 as CFLAGS and LDFLAGS.
get_target_interface(SECP256K1_APPEND_CFLAGS "" sanitize_interface COMPILE_OPTIONS)
string(STRIP "${SECP256K1_APPEND_CFLAGS} ${APPEND_CPPFLAGS}" SECP256K1_APPEND_CFLAGS)
string(STRIP "${SECP256K1_APPEND_CFLAGS} ${APPEND_CFLAGS}" SECP256K1_APPEND_CFLAGS)
set(SECP256K1_APPEND_CFLAGS ${SECP256K1_APPEND_CFLAGS} CACHE STRING "" FORCE)
get_target_interface(SECP256K1_APPEND_LDFLAGS "" sanitize_interface LINK_OPTIONS)
string(STRIP "${SECP256K1_APPEND_LDFLAGS} ${APPEND_LDFLAGS}" SECP256K1_APPEND_LDFLAGS)
set(SECP256K1_APPEND_LDFLAGS ${SECP256K1_APPEND_LDFLAGS} CACHE STRING "" FORCE)
# We want to build libsecp256k1 with the most tested RelWithDebInfo configuration.
enable_language(C)
foreach(config IN LISTS CMAKE_BUILD_TYPE CMAKE_CONFIGURATION_TYPES)
  if(config STREQUAL "")
    continue()
  endif()
  string(TOUPPER "${config}" config)
  set(CMAKE_C_FLAGS_${config} "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
endforeach()
# If the CFLAGS environment variable is defined during building depends
# and configuring this build system, its content might be duplicated.
if(DEFINED ENV{CFLAGS})
  deduplicate_flags(CMAKE_C_FLAGS)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS OFF)
add_subdirectory(secp256k1)
set_target_properties(secp256k1 PROPERTIES
  EXCLUDE_FROM_ALL TRUE
)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()  # WITH_SYSTEM_LIBSECP256K1

if(WITH_SYSTEM_LIBBITCOINPQC)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(libbitcoinpqc REQUIRED IMPORTED_TARGET libbitcoinpqc)
  add_library(bitcoinpqc ALIAS PkgConfig::libbitcoinpqc)
else()
  #=============================
  # libbitcoinpqc subtree
  #=============================
  message("")
  message("Configuring libbitcoinpqc subtree...")
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  add_subdirectory(libbitcoinpqc)
  set_target_properties(bitcoinpqc PROPERTIES
    EXCLUDE_FROM_ALL TRUE
  )
endif()

# Set top-level target output locations.
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()

add_custom_target(generate_build_info
  BYPRODUCTS ${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h
  COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
  COMMENT "Generating bitcoin-build-info.h"
  VERBATIM
)
add_library(bitcoin_clientversion STATIC EXCLUDE_FROM_ALL
  clientversion.cpp
)
target_link_libraries(bitcoin_clientversion
  PRIVATE
    core_interface
)
add_dependencies(bitcoin_clientversion generate_build_info)

add_subdirectory(crypto)
add_subdirectory(util)
if(WITH_MULTIPROCESS)
  add_subdirectory(ipc)
endif()

add_library(bitcoin_db STATIC EXCLUDE_FROM_ALL
  dbwrapper.cpp
)
target_link_libraries(bitcoin_db
  PRIVATE
    core_interface
    bitcoin_util
    leveldb
)

add_library(bitcoin_consensus STATIC EXCLUDE_FROM_ALL
  arith_uint256.cpp
  consensus/merkle.cpp
  consensus/tx_check.cpp
  hash.cpp
  primitives/block.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/interpreter.cpp
  script/pqm.cpp
  script/script.cpp
  script/script_error.cpp
  shielded/bundle.cpp
  uint256.cpp
)
target_link_libraries(bitcoin_consensus
  PRIVATE
    core_interface
    bitcoin_crypto
    bitcoinpqc
    secp256k1
    # shielded/bundle.cpp uses secure_allocator (LockedPoolManager) and
    # bitcoin_crypto uses GetStrongRandBytes — both from bitcoin_util.
    bitcoin_util
)

if(WITH_ZMQ)
  add_subdirectory(zmq)
endif()

# Home for common functionality shared by different executables and libraries.
# Similar to `bitcoin_util` library, but higher-level.
add_library(bitcoin_common STATIC EXCLUDE_FROM_ALL
  addresstype.cpp
  base58.cpp
  bech32.cpp
  chain.cpp
  chainparams.cpp
  chainparamsbase.cpp
  codex32.cpp
  coins.cpp
  common/args.cpp
  common/bloom.cpp
  common/config.cpp
  common/init.cpp
  common/interfaces.cpp
  common/messages.cpp
  common/netif.cpp
  common/pcp.cpp
  common/run_command.cpp
  common/settings.cpp
  common/signmessage.cpp
  common/system.cpp
  common/url.cpp
  compressor.cpp
  core_read.cpp
  core_write.cpp
  deploymentinfo.cpp
  external_signer.cpp
  init/common.cpp
  kernel/chainparams.cpp
  key.cpp
  key_io.cpp
  merkleblock.cpp
  matmul/field.cpp
  matmul/freivalds.cpp
  matmul/int8_field.cpp
  matmul/matrix.cpp
  matmul/matmul_v4.cpp
  matmul/matmul_v4_batch.cpp
  matmul/matmul_v4_bmx4.cpp
  matmul/matmul_v4_bmx4_batch.cpp
  matmul/matmul_sketch_cache.cpp
  matmul/matmul_v4_exact_float.cpp
  matmul/accel_v4.cpp
  matmul/backend_capabilities_v4.cpp
  matmul/noise.cpp
  matmul/pow_v4.cpp
  matmul/solver_runtime.cpp
  matmul/matmul_pow.cpp
  matmul/transcript.cpp
  matmul/accelerated_solver.cpp
  net_permissions.cpp
  net_types.cpp
  netaddress.cpp
  netbase.cpp
  outputtype.cpp
  pq/pq_keyderivation.cpp
  pqkey.cpp
  policy/coin_age_priority.cpp
  policy/feerate.cpp
  policy/policy.cpp
  pow.cpp
  protocol.cpp
  psbt.cpp
  rpc/rawtransaction_util.cpp
  rpc/request.cpp
  rpc/util.cpp
  scheduler.cpp
  shielded/bridge.cpp
  shielded/view_grant.cpp
  shielded/v2_bundle.cpp
  shielded/v2_types.cpp
  script/descriptor.cpp
  script/miniscript.cpp
  script/parsing.cpp
  script/sign.cpp
  script/signingprovider.cpp
  script/solver.cpp
)
target_link_libraries(bitcoin_common
  PUBLIC
    bitcoin_util
    univalue
  PRIVATE
    core_interface
    bitcoin_consensus
    bitcoin_db
    bitcoinpqc
    secp256k1
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<PLATFORM_ID:Windows>:ws2_32>
)
if(APPLE)
  find_btx_apple_framework(BTX_ACCELERATE_FRAMEWORK Accelerate)
  target_link_libraries(bitcoin_common PRIVATE ${BTX_ACCELERATE_FRAMEWORK})
endif()

# Shielded pool and proof implementation shared by node and wallet targets.
add_library(bitcoin_shielded STATIC EXCLUDE_FROM_ALL
  shielded/account_registry.cpp
  shielded/lattice/ntt.cpp
  shielded/lattice/poly.cpp
  shielded/lattice/polyvec.cpp
  shielded/lattice/sampling.cpp
  shielded/merkle_tree.cpp
  shielded/matrict_plus_backend.cpp
  shielded/note.cpp
  shielded/note_encryption.cpp
  shielded/nullifier.cpp
  shielded/spend_auth.cpp
  shielded/ringct/balance_proof.cpp
  shielded/ringct/commitment.cpp
  shielded/ringct/matrict.cpp
  shielded/ringct/range_proof.cpp
  shielded/ringct/ring_selection.cpp
  shielded/ringct/ring_signature.cpp
  shielded/smile2/poly.cpp
  shielded/smile2/ntt.cpp
  shielded/smile2/bdlop.cpp
  shielded/smile2/membership.cpp
  shielded/smile2/ct_proof.cpp
  shielded/smile2/public_account.cpp
  shielded/smile2/serialize.cpp
  shielded/smile2/verify_dispatch.cpp
  shielded/smile2/wallet_bridge.cpp
  shielded/recovery_exit.cpp
  shielded/turnstile.cpp
  shielded/unshield_velocity.cpp
  shielded/validation.cpp
  shielded/v2_egress.cpp
  shielded/v2_ingress.cpp
  shielded/v2_proof.cpp
  shielded/v2_send.cpp
)
target_link_libraries(bitcoin_shielded
  PRIVATE
    core_interface
    bitcoin_db
    bitcoin_common
    bitcoin_consensus
    bitcoin_crypto
    bitcoinpqc
    secp256k1
  PUBLIC
    leveldb
)

# Prevent FMA contraction in MatMul code to ensure cross-platform determinism
# of cblas_dgemm intermediate results.
set_source_files_properties(matmul/matmul_pow.cpp PROPERTIES
  COMPILE_FLAGS "-ffp-contract=off"
)

add_library(btx_matmul_backend STATIC EXCLUDE_FROM_ALL
  matmul/backend_capabilities.cpp
  matmul/accel_v4_stub.cpp
  cuda/cuda_scheduler.cpp
  metal/matmul_accel_env.cpp
)
if(APPLE AND BTX_ENABLE_METAL)
  enable_language(OBJCXX)
  target_compile_options(btx_matmul_backend PRIVATE
    $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>
  )
  target_sources(btx_matmul_backend PRIVATE
    metal/matmul_accel.mm
    metal/matmul_v4_accel.mm
    # External review (P1.5): the BMX4-C (v4.2) Metal device backend source was
    # never listed. With BTX_ENABLE_METAL defined the weak metal stub in
    # accel_v4_stub.cpp is compiled out, so without this the strong
    # matmul_v4::metal::ComputeDigestsBMX4CAccel had no definition -- a Metal
    # build suppressed the weak stub while providing no strong impl (link error /
    # silently unserved profile). Wire it in alongside its kernels metallib.
    metal/matmul_v4_bmx4_accel.mm
    metal/nonce_accel.mm
    metal/oracle_accel.mm
  )
  find_btx_apple_framework(BTX_FOUNDATION_FRAMEWORK Foundation)
  find_btx_apple_framework(BTX_IOKIT_FRAMEWORK IOKit)
  find_btx_apple_framework(BTX_METAL_FRAMEWORK Metal)
  option(BTX_MATMUL_METAL_PRECOMPILE_KERNELS "Precompile MatMul Metal kernels with xcrun metallib at build time" ON)
  find_program(BTX_XCRUN_EXECUTABLE xcrun)
  if(BTX_MATMUL_METAL_PRECOMPILE_KERNELS AND BTX_XCRUN_EXECUTABLE)
    set(BTX_MATMUL_METAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/metal/matmul_accel_kernels.metal)
    set(BTX_MATMUL_METAL_AIR ${CMAKE_CURRENT_BINARY_DIR}/matmul_accel_kernels.air)
    set(BTX_MATMUL_METALLIB ${CMAKE_CURRENT_BINARY_DIR}/matmul_accel_kernels.metallib)
    set(BTX_ORACLE_METAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/metal/oracle_accel_kernels.metal)
    set(BTX_ORACLE_METAL_AIR ${CMAKE_CURRENT_BINARY_DIR}/oracle_accel_kernels.air)
    set(BTX_ORACLE_METALLIB ${CMAKE_CURRENT_BINARY_DIR}/oracle_accel_kernels.metallib)
    set(BTX_MATMUL_V4_METAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/metal/matmul_v4_accel_kernels.metal)
    set(BTX_MATMUL_V4_METAL_AIR ${CMAKE_CURRENT_BINARY_DIR}/matmul_v4_accel_kernels.air)
    set(BTX_MATMUL_V4_METALLIB ${CMAKE_CURRENT_BINARY_DIR}/matmul_v4_accel_kernels.metallib)
    set(BTX_MATMUL_V4_BMX4_METAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/metal/matmul_v4_bmx4_accel_kernels.metal)
    set(BTX_MATMUL_V4_BMX4_METAL_AIR ${CMAKE_CURRENT_BINARY_DIR}/matmul_v4_bmx4_accel_kernels.air)
    set(BTX_MATMUL_V4_BMX4_METALLIB ${CMAKE_CURRENT_BINARY_DIR}/matmul_v4_bmx4_accel_kernels.metallib)
    add_custom_command(
      OUTPUT ${BTX_MATMUL_METALLIB}
      COMMAND ${BTX_XCRUN_EXECUTABLE} -sdk macosx metal -c ${BTX_MATMUL_METAL_SOURCE} -o ${BTX_MATMUL_METAL_AIR}
      COMMAND ${BTX_XCRUN_EXECUTABLE} -sdk macosx metallib ${BTX_MATMUL_METAL_AIR} -o ${BTX_MATMUL_METALLIB}
      DEPENDS ${BTX_MATMUL_METAL_SOURCE}
      COMMENT "Compiling prebuilt MatMul Metal kernels"
      VERBATIM
    )
    add_custom_command(
      OUTPUT ${BTX_ORACLE_METALLIB}
      COMMAND ${BTX_XCRUN_EXECUTABLE} -sdk macosx metal -c ${BTX_ORACLE_METAL_SOURCE} -o ${BTX_ORACLE_METAL_AIR}
      COMMAND ${BTX_XCRUN_EXECUTABLE} -sdk macosx metallib ${BTX_ORACLE_METAL_AIR} -o ${BTX_ORACLE_METALLIB}
      DEPENDS ${BTX_ORACLE_METAL_SOURCE}
      COMMENT "Compiling prebuilt Metal oracle kernels"
      VERBATIM
    )
    # The v4 kernels compile under the default (pre-Metal-4) language version:
    # the mpp::tensor_ops section is guarded by __METAL_VERSION__/__has_include
    # and the Metal 4 tensor pipeline is always runtime-compiled by the host
    # glue with an explicit metal4.0 language version (see matmul_v4_accel.mm).
    add_custom_command(
      OUTPUT ${BTX_MATMUL_V4_METALLIB}
      COMMAND ${BTX_XCRUN_EXECUTABLE} -sdk macosx metal -c ${BTX_MATMUL_V4_METAL_SOURCE} -o ${BTX_MATMUL_V4_METAL_AIR}
      COMMAND ${BTX_XCRUN_EXECUTABLE} -sdk macosx metallib ${BTX_MATMUL_V4_METAL_AIR} -o ${BTX_MATMUL_V4_METALLIB}
      DEPENDS ${BTX_MATMUL_V4_METAL_SOURCE}
      COMMENT "Compiling prebuilt MatMul v4 Metal kernels"
      VERBATIM
    )
    # BMX4-C (v4.2) kernels: same pre-Metal-4 language version as the v4 kernels;
    # the Metal 4 tensor pipeline is runtime-compiled by matmul_v4_bmx4_accel.mm.
    add_custom_command(
      OUTPUT ${BTX_MATMUL_V4_BMX4_METALLIB}
      COMMAND ${BTX_XCRUN_EXECUTABLE} -sdk macosx metal -c ${BTX_MATMUL_V4_BMX4_METAL_SOURCE} -o ${BTX_MATMUL_V4_BMX4_METAL_AIR}
      COMMAND ${BTX_XCRUN_EXECUTABLE} -sdk macosx metallib ${BTX_MATMUL_V4_BMX4_METAL_AIR} -o ${BTX_MATMUL_V4_BMX4_METALLIB}
      DEPENDS ${BTX_MATMUL_V4_BMX4_METAL_SOURCE}
      COMMENT "Compiling prebuilt MatMul v4 BMX4-C Metal kernels"
      VERBATIM
    )
    add_custom_target(btx_matmul_metallib DEPENDS ${BTX_MATMUL_METALLIB})
    add_custom_target(btx_oracle_metallib DEPENDS ${BTX_ORACLE_METALLIB})
    add_custom_target(btx_matmul_v4_metallib DEPENDS ${BTX_MATMUL_V4_METALLIB})
    add_custom_target(btx_matmul_v4_bmx4_metallib DEPENDS ${BTX_MATMUL_V4_BMX4_METALLIB})
    add_dependencies(btx_matmul_backend btx_matmul_metallib btx_oracle_metallib btx_matmul_v4_metallib btx_matmul_v4_bmx4_metallib)
    target_compile_definitions(btx_matmul_backend PRIVATE
      BTX_MATMUL_METALLIB_PATH=\"${BTX_MATMUL_METALLIB}\"
      BTX_ORACLE_METALLIB_PATH=\"${BTX_ORACLE_METALLIB}\"
      BTX_MATMUL_V4_METALLIB_PATH=\"${BTX_MATMUL_V4_METALLIB}\"
      BTX_MATMUL_V4_BMX4_METALLIB_PATH=\"${BTX_MATMUL_V4_BMX4_METALLIB}\"
    )
  else()
    if(BTX_MATMUL_METAL_PRECOMPILE_KERNELS)
      message(STATUS "xcrun not found; MatMul Metal backend will compile inline kernels at runtime")
    else()
      message(STATUS "BTX_MATMUL_METAL_PRECOMPILE_KERNELS=OFF; MatMul Metal backend will compile inline kernels at runtime")
    endif()
  endif()
  # PUBLIC so the define propagates through bitcoin_common (which PUBLIC-links
  # btx_matmul_backend) to consumers -- in particular the backend-determinism
  # test TU (src/test/matmul_v4_backend_determinism_tests.cpp) compiled into
  # test_btx, which #if-guards its Metal determinism row on BTX_ENABLE_METAL.
  # PRIVATE would silently compile that row out of the test even in a Metal build.
  target_compile_definitions(btx_matmul_backend PUBLIC BTX_ENABLE_METAL=1)
  target_link_libraries(btx_matmul_backend PRIVATE
    ${BTX_FOUNDATION_FRAMEWORK}
    ${BTX_IOKIT_FRAMEWORK}
    ${BTX_METAL_FRAMEWORK}
  )
else()
  target_sources(btx_matmul_backend PRIVATE
    metal/matmul_accel_stub.cpp
    metal/matmul_v4_accel_stub.cpp
    metal/matmul_v4_bmx4_accel_stub.cpp
    metal/nonce_accel_stub.cpp
    metal/oracle_accel_stub.cpp
  )
endif()
if(BTX_ENABLE_CUDA_EXPERIMENTAL)
  target_sources(btx_matmul_backend PRIVATE
    cuda/cuda_context.cpp
    cuda/matmul_accel.cu
    cuda/oracle_accel.cu
    cuda/matmul_v4_accel.cu
    # External review (vanities): the BMX4-C (v4.2) device backend source was
    # never listed, so the v4.2 accelerated path never linked. Wire it in so the
    # profile is dispatchable (it falls back to the INT8 path on NVIDIA, where the
    # MXFP4 native GEMM is currently unserved by cuBLASLt -- see the round-2
    # remediation doc). Compile-verified only on real CUDA toolchains.
    cuda/matmul_v4_bmx4_accel.cu
  )
  # PUBLIC so the define propagates to every consumer of btx_matmul_backend.
  # This subsumes the eligibility-classifier fix: CudaEligibility() lives in
  # matmul/backend_capabilities_v4.cpp, compiled into bitcoin_common (not
  # btx_matmul_backend); without the define visible there it takes the
  # #else -> DisabledByBuild() branch and the whole measurement run silently times
  # the CPU stub while reporting `compiled=no reason=disabled_by_build` -- so every
  # GPU number an operator would submit is really a CPU number unless they catch
  # that line. It also reaches the backend-determinism test TU compiled into
  # test_btx, whose CUDA determinism row #if-guards on BTX_ENABLE_CUDA_EXPERIMENTAL.
  # bitcoin_common PUBLIC-links btx_matmul_backend, so the INTERFACE define flows
  # transitively to bitcoin_common and on to test_btx.
  target_compile_definitions(btx_matmul_backend PUBLIC BTX_ENABLE_CUDA_EXPERIMENTAL=1)
  if(BTX_CUDA_RUNTIME_LIBRARY STREQUAL "Static")
    target_link_libraries(btx_matmul_backend PRIVATE CUDA::cudart_static)
  else()
    target_link_libraries(btx_matmul_backend PRIVATE CUDA::cudart)
  endif()
  # cuBLASLt provides the exact INT8->INT32 (CUDA_R_8I -> CUDA_R_32I,
  # CUBLAS_COMPUTE_32I) tensor-core GEMMs used by the MatMul v4 backend.
  target_link_libraries(btx_matmul_backend PRIVATE CUDA::cublasLt)
  # matmul_v4_accel.cu reuses the exact CPU derivation / serialization / digest
  # routines (matmul::v4::*, defined in bitcoin_common) to guarantee bit-exact
  # operands and digest. Both are STATIC libraries and bitcoin_common already
  # links btx_matmul_backend PUBLIC, so this closes a static-library cycle;
  # CMake resolves it with a linker group (cyclic deps among STATIC libs are
  # supported). If a cycle-free layout is preferred, move the ComputeDigestAccel
  # host orchestration into a bitcoin_common .cpp that calls a device-only entry.
  target_link_libraries(btx_matmul_backend PRIVATE bitcoin_common)
  set_target_properties(btx_matmul_backend PROPERTIES
    CUDA_ARCHITECTURES "${BTX_CUDA_ARCHITECTURES}"
    CUDA_RUNTIME_LIBRARY "${BTX_CUDA_RUNTIME_LIBRARY}"
    CUDA_STANDARD 20
    CUDA_STANDARD_REQUIRED ON
  )
else()
  target_sources(btx_matmul_backend PRIVATE
    cuda/matmul_accel_stub.cpp
    cuda/oracle_accel_stub.cpp
    cuda/matmul_v4_accel_stub.cpp
    cuda/matmul_v4_bmx4_accel_stub.cpp
  )
endif()
if(BTX_ENABLE_HIP)
  target_sources(btx_matmul_backend PRIVATE
    hip/matmul_v4_accel.hip
    # External review (P1.5): the BMX4-C (v4.2) HIP device backend source was
    # never listed, so the strong matmul_v4::hip::ComputeDigestsBMX4CAccel never
    # linked and the profile fell back to the (weak) stub on ROCm.
    hip/matmul_v4_bmx4_accel.hip
  )
  set_source_files_properties(
    hip/matmul_v4_accel.hip
    hip/matmul_v4_bmx4_accel.hip
    PROPERTIES LANGUAGE HIP)
  # PUBLIC so the define reaches the backend-determinism test TU (compiled into
  # test_btx), whose HIP determinism row #if-guards on BTX_ENABLE_HIP; PRIVATE
  # would silently drop that row even in a HIP build.
  target_compile_definitions(btx_matmul_backend PUBLIC BTX_ENABLE_HIP=1)
  target_link_libraries(btx_matmul_backend PRIVATE hip::device)
  # The HIP backend reuses the shared matmul::v4 host reference (operand
  # expansion, serialization, digest) from bitcoin_common so its output is
  # bit-identical to the CPU by construction. bitcoin_common PUBLIC-links
  # btx_matmul_backend, so this closes a STATIC<->STATIC cycle that CMake
  # resolves by repeating the archives at final link. The cycle only exists
  # when BTX_ENABLE_HIP=ON (the stub path stays self-contained).
  target_link_libraries(btx_matmul_backend PRIVATE bitcoin_common)
  set_target_properties(btx_matmul_backend PROPERTIES
    HIP_ARCHITECTURES "${BTX_HIP_ARCHITECTURES}"
    HIP_STANDARD 20
    HIP_STANDARD_REQUIRED ON
  )
else()
  target_sources(btx_matmul_backend PRIVATE
    hip/matmul_v4_accel_stub.cpp
    hip/matmul_v4_bmx4_accel_stub.cpp
  )
endif()
target_link_libraries(btx_matmul_backend PRIVATE core_interface)
target_link_libraries(bitcoin_common PUBLIC btx_matmul_backend)

include(InstallBinaryComponent)

# Build canonical BTX binary names while keeping legacy bitcoin-* command aliases.
function(add_legacy_binary_alias target_name legacy_binary)
  get_target_property(canonical_binary ${target_name} OUTPUT_NAME)
  if(NOT canonical_binary)
    set(canonical_binary ${target_name})
  endif()

  if(WIN32)
    add_custom_command(
      TARGET ${target_name} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:${target_name}>
        $<TARGET_FILE_DIR:${target_name}>/${legacy_binary}${CMAKE_EXECUTABLE_SUFFIX}
      VERBATIM
    )
    install(FILES $<TARGET_FILE:${target_name}>
      DESTINATION ${CMAKE_INSTALL_BINDIR}
      RENAME ${legacy_binary}${CMAKE_EXECUTABLE_SUFFIX}
      COMPONENT ${target_name}
    )
  else()
    add_custom_command(
      TARGET ${target_name} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E rm -f
        $<TARGET_FILE_DIR:${target_name}>/${legacy_binary}
      COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${canonical_binary}
        $<TARGET_FILE_DIR:${target_name}>/${legacy_binary}
      VERBATIM
    )
    install(CODE
      "execute_process(COMMAND \"${CMAKE_COMMAND}\" -E rm -f \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/${legacy_binary}\")\n"
      "execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink \"${canonical_binary}\" \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/${legacy_binary}\")\n"
    )
  endif()
endfunction()

# Provide backward-compatible legacy CMake build targets.
# Example: `cmake --build build --target bitcoind` builds canonical target `btxd`.
function(add_legacy_target_alias alias_name target_name)
  if(TARGET ${target_name} AND NOT TARGET ${alias_name})
    add_custom_target(${alias_name} DEPENDS ${target_name})
  endif()
endfunction()

function(target_link_btx_linux_archive_group target)
  if(UNIX AND NOT APPLE)
    target_link_libraries(${target}
      -Wl,--start-group
      ${ARGN}
      -Wl,--end-group
    )
  else()
    target_link_libraries(${target} ${ARGN})
  endif()
endfunction()

set(BTX_BASE_ARCHIVES
  bitcoin_common
  bitcoin_shielded
  bitcoin_db
  univalue
  btx_matmul_backend
  bitcoin_consensus
  bitcoin_util
  bitcoin_clientversion
  bitcoinpqc
  secp256k1
  bitcoin_crypto
  leveldb
  crc32c
)

set(BTX_NODE_ARCHIVES
  bitcoin_node
  ${BTX_BASE_ARCHIVES}
)

set(BTX_WALLET_ARCHIVES
  bitcoin_wallet
  ${BTX_BASE_ARCHIVES}
)

set(BTX_NODE_WALLET_ARCHIVES
  bitcoin_wallet
  ${BTX_NODE_ARCHIVES}
)

if(ENABLE_WALLET)
  add_subdirectory(wallet)

  if(BUILD_WALLET_TOOL)
    add_executable(btx-wallet
      bitcoin-wallet.cpp
      init/bitcoin-wallet.cpp
      wallet/wallettool.cpp
    )
    set_target_properties(btx-wallet PROPERTIES OUTPUT_NAME btx-wallet)
    add_windows_resources(btx-wallet bitcoin-wallet-res.rc)
    target_link_libraries(btx-wallet
      core_interface
      Boost::headers
    )
    if(UNIX AND NOT APPLE)
      target_link_btx_linux_archive_group(btx-wallet ${BTX_NODE_WALLET_ARCHIVES})
    else()
      target_link_libraries(btx-wallet bitcoin_wallet)
    endif()
    install_binary_component(btx-wallet HAS_MANPAGE)
    add_legacy_binary_alias(btx-wallet bitcoin-wallet)
    add_legacy_target_alias(bitcoin-wallet btx-wallet)
  endif()
endif()


# P2P and RPC server functionality used by `btxd` and `btx-qt` executables.
add_library(bitcoin_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  banman.cpp
  bip324.cpp
  blockencodings.cpp
  blockfilter.cpp
  consensus/tx_verify.cpp
  dandelion.cpp
  deploymentstatus.cpp
  flatfile.cpp
  headerssync.cpp
  httprpc.cpp
  httpserver.cpp
  i2p.cpp
  index/base.cpp
  index/blockfilterindex.cpp
  index/coinstatsindex.cpp
  index/txindex.cpp
  init.cpp
  kernel/chain.cpp
  kernel/checks.cpp
  kernel/coinstats.cpp
  kernel/context.cpp
  kernel/cs_main.cpp
  kernel/disconnected_transactions.cpp
  kernel/mempool_removal_reason.cpp
  mapport.cpp
  net.cpp
  net_processing.cpp
  netgroup.cpp
  node/autoupdate.cpp
  node/abort.cpp
  node/blockmanager_args.cpp
  node/blockstorage.cpp
  node/caches.cpp
  node/chainstate.cpp
  node/chainstatemanager_args.cpp
  node/coin.cpp
  node/coins_view_args.cpp
  node/connection_types.cpp
  node/context.cpp
  node/database_args.cpp
  node/eviction.cpp
  node/interface_ui.cpp
  node/interfaces.cpp
  node/kernel_notifications.cpp
  node/mining_guard.cpp
  node/mempool_args.cpp
  node/matmul_verify_worker.cpp
  node/mempool_persist.cpp
  node/mempool_persist_args.cpp
  node/miner.cpp
  node/mini_miner.cpp
  node/peerman_args.cpp
  node/psbt.cpp
  node/timeoffsets.cpp
  node/transaction.cpp
  node/txdownloadman_impl.cpp
  node/txreconciliation.cpp
  node/utxo_snapshot.cpp
  node/warnings.cpp
  noui.cpp
  policy/ephemeral_policy.cpp
  policy/fees.cpp
  policy/fees_args.cpp
  policy/packages.cpp
  policy/rbf.cpp
  policy/settings.cpp
  policy/truc_policy.cpp
  rest.cpp
  rpc/blockchain.cpp
  rpc/external_signer.cpp
  rpc/fees.cpp
  rpc/mempool.cpp
  rpc/mining.cpp
  rpc/net.cpp
  rpc/node.cpp
  rpc/output_script.cpp
  rpc/rawtransaction.cpp
  rpc/server.cpp
  rpc/server_util.cpp
  rpc/signmessage.cpp
  rpc/txoutproof.cpp
  script/sigcache.cpp
  signet.cpp
  stats/init.cpp
  stats/rpc_stats.cpp
  stats/stats.cpp
  torcontrol.cpp
  txdb.cpp
  txmempool.cpp
  txorphanage.cpp
  txrequest.cpp
  validation.cpp
  validationinterface.cpp
  versionbits.cpp
  $<$<TARGET_EXISTS:bitcoin_wallet>:wallet/init.cpp>
  $<$<NOT:$<TARGET_EXISTS:bitcoin_wallet>>:dummywallet.cpp>
)
target_link_libraries(bitcoin_node
  PUBLIC
    bitcoin_common
  PRIVATE
    core_interface
    bitcoin_db
    bitcoin_shielded
    $<TARGET_NAME_IF_EXISTS:bitcoin_zmq>
    leveldb
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:MiniUPnPc::MiniUPnPc>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)


# BTX daemon executable.
if(BUILD_DAEMON)
  add_executable(btxd
    bitcoind.cpp
    init/bitcoind.cpp
  )
  set_target_properties(btxd PROPERTIES OUTPUT_NAME btxd)
  add_windows_resources(btxd bitcoind-res.rc)
  target_link_libraries(btxd
    core_interface
  )
  if(UNIX AND NOT APPLE)
    if(TARGET bitcoin_wallet)
      target_link_btx_linux_archive_group(btxd ${BTX_NODE_WALLET_ARCHIVES})
    else()
      target_link_btx_linux_archive_group(btxd ${BTX_NODE_ARCHIVES})
    endif()
  else()
    target_link_libraries(btxd
      bitcoin_node
      $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
    )
  endif()
  install_binary_component(btxd HAS_MANPAGE)
  add_legacy_binary_alias(btxd bitcoind)
  add_legacy_target_alias(bitcoind btxd)
endif()
if(WITH_MULTIPROCESS AND BUILD_DAEMON)
  add_executable(btx-node
    bitcoind.cpp
    init/bitcoin-node.cpp
  )
  set_target_properties(btx-node PROPERTIES OUTPUT_NAME btx-node)
  target_link_libraries(btx-node
    core_interface
    bitcoin_ipc
  )
  if(UNIX AND NOT APPLE)
    if(TARGET bitcoin_wallet)
      target_link_btx_linux_archive_group(btx-node ${BTX_NODE_WALLET_ARCHIVES})
    else()
      target_link_btx_linux_archive_group(btx-node ${BTX_NODE_ARCHIVES})
    endif()
  else()
    target_link_libraries(btx-node
      bitcoin_node
      $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
    )
  endif()
  install_binary_component(btx-node)
  add_legacy_binary_alias(btx-node bitcoin-node)
  add_legacy_target_alias(bitcoin-node btx-node)
endif()

if(WITH_MULTIPROCESS AND BUILD_TESTS)
    # bitcoin_ipc_test library target is defined here in src/CMakeLists.txt
    # instead of src/test/CMakeLists.txt so capnp files in src/test/ are able to
    # reference capnp files in src/ipc/capnp/ by relative path. The Cap'n Proto
    # compiler only allows importing by relative path when the importing and
    # imported files are underneath the same compilation source prefix, so the
    # source prefix must be src/, not src/test/
    add_library(bitcoin_ipc_test STATIC EXCLUDE_FROM_ALL
      test/ipc_test.cpp
    )
    target_capnp_sources(bitcoin_ipc_test ${PROJECT_SOURCE_DIR}
      test/ipc_test.capnp
    )
    add_dependencies(bitcoin_ipc_test bitcoin_ipc_headers)
endif()


add_library(bitcoin_cli STATIC EXCLUDE_FROM_ALL
  compat/stdin.cpp
  rpc/client.cpp
)
target_link_libraries(bitcoin_cli
  PUBLIC
    core_interface
    univalue
)


# Bitcoin Core RPC client
if(BUILD_CLI)
  add_executable(btx-cli bitcoin-cli.cpp)
  set_target_properties(btx-cli PROPERTIES OUTPUT_NAME btx-cli)
  add_windows_resources(btx-cli bitcoin-cli-res.rc)
  target_link_libraries(btx-cli
    core_interface
    bitcoin_cli
    bitcoin_common
    libevent::core
    libevent::extra
  )
  install_binary_component(btx-cli HAS_MANPAGE)
  add_legacy_binary_alias(btx-cli bitcoin-cli)
  add_legacy_target_alias(bitcoin-cli btx-cli)
endif()


if(BUILD_TX)
  add_executable(btx-tx bitcoin-tx.cpp)
  set_target_properties(btx-tx PROPERTIES OUTPUT_NAME btx-tx)
  add_windows_resources(btx-tx bitcoin-tx-res.rc)
  target_include_directories(btx-tx PRIVATE
    $<TARGET_PROPERTY:univalue,INTERFACE_INCLUDE_DIRECTORIES>
  )
  target_link_libraries(btx-tx
    core_interface
  )
  if(UNIX AND NOT APPLE)
    target_link_btx_linux_archive_group(btx-tx ${BTX_BASE_ARCHIVES})
  else()
    target_link_libraries(btx-tx
      bitcoin_shielded
    )
  endif()
  install_binary_component(btx-tx HAS_MANPAGE)
  add_legacy_binary_alias(btx-tx bitcoin-tx)
  add_legacy_target_alias(bitcoin-tx btx-tx)
endif()


if(BUILD_UTIL)
  add_executable(btx-util bitcoin-util.cpp)
  set_target_properties(btx-util PROPERTIES OUTPUT_NAME btx-util)
  add_windows_resources(btx-util bitcoin-util-res.rc)
  target_link_libraries(btx-util
    core_interface
  )
  if(UNIX AND NOT APPLE)
    target_link_btx_linux_archive_group(btx-util ${BTX_BASE_ARCHIVES})
  else()
    target_link_libraries(btx-util
      bitcoin_shielded
    )
  endif()
  install_binary_component(btx-util HAS_MANPAGE)
  add_legacy_binary_alias(btx-util bitcoin-util)
  add_legacy_target_alias(bitcoin-util btx-util)

  add_executable(btx-matmul-backend-info btx-matmul-backend-info.cpp)
  target_link_libraries(btx-matmul-backend-info
    core_interface
  )
  if(UNIX AND NOT APPLE)
    target_link_btx_linux_archive_group(btx-matmul-backend-info ${BTX_BASE_ARCHIVES})
  else()
    target_link_libraries(btx-matmul-backend-info bitcoin_common)
  endif()
  install_binary_component(btx-matmul-backend-info)

  add_executable(btx-matmul-metal-bench btx-matmul-metal-bench.cpp)
  target_link_libraries(btx-matmul-metal-bench
    core_interface
  )
  if(UNIX AND NOT APPLE)
    target_link_btx_linux_archive_group(btx-matmul-metal-bench ${BTX_BASE_ARCHIVES})
  else()
    target_link_libraries(btx-matmul-metal-bench bitcoin_common)
  endif()
  install_binary_component(btx-matmul-metal-bench)

  add_executable(btx-matmul-solve-bench btx-matmul-solve-bench.cpp)
  target_include_directories(btx-matmul-solve-bench PRIVATE
    $<TARGET_PROPERTY:univalue,INTERFACE_INCLUDE_DIRECTORIES>
  )
  target_link_libraries(btx-matmul-solve-bench
    core_interface
  )
  if(UNIX AND NOT APPLE)
    target_link_btx_linux_archive_group(btx-matmul-solve-bench ${BTX_BASE_ARCHIVES})
  else()
    target_link_libraries(btx-matmul-solve-bench
      bitcoin_shielded
    )
  endif()
  install_binary_component(btx-matmul-solve-bench)

  add_executable(btx-matmul-cost-bench btx-matmul-cost-bench.cpp)
  target_include_directories(btx-matmul-cost-bench PRIVATE
    $<TARGET_PROPERTY:univalue,INTERFACE_INCLUDE_DIRECTORIES>
  )
  target_link_libraries(btx-matmul-cost-bench
    core_interface
  )
  if(UNIX AND NOT APPLE)
    target_link_btx_linux_archive_group(btx-matmul-cost-bench ${BTX_BASE_ARCHIVES})
  else()
    target_link_libraries(btx-matmul-cost-bench
      bitcoin_shielded
    )
  endif()
  install_binary_component(btx-matmul-cost-bench)

  # One-command MatMul v4.1 hardware measurement report (feeds activation
  # gates B1 / B2b / B2g). Standalone; drives matmul_v4::accel batched dispatch
  # and the CPU reference stage boundaries, emits JSON + a human summary.
  add_executable(matmul-v4-report matmul-v4-report.cpp)
  target_include_directories(matmul-v4-report PRIVATE
    $<TARGET_PROPERTY:univalue,INTERFACE_INCLUDE_DIRECTORIES>
  )
  target_link_libraries(matmul-v4-report
    core_interface
  )
  if(UNIX AND NOT APPLE)
    target_link_btx_linux_archive_group(matmul-v4-report ${BTX_BASE_ARCHIVES})
  else()
    target_link_libraries(matmul-v4-report
      bitcoin_shielded
    )
  endif()
  install_binary_component(matmul-v4-report)

  add_executable(btx-genesis btx-genesis.cpp)
  target_link_libraries(btx-genesis
    core_interface
  )
  if(UNIX AND NOT APPLE)
    target_link_btx_linux_archive_group(btx-genesis ${BTX_BASE_ARCHIVES})
  else()
    target_link_libraries(btx-genesis
      bitcoin_shielded
    )
  endif()
  install_binary_component(btx-genesis)
endif()


if(BUILD_GUI)
  add_subdirectory(qt)
endif()


if(BUILD_BITCOINCONSENSUS_LIB)
  add_subdirectory(consensus)
endif()

if(BUILD_KERNEL_LIB)
  add_subdirectory(kernel)
endif()

if(BUILD_UTIL_CHAINSTATE)
  add_executable(btx-chainstate
    bitcoin-chainstate.cpp
  )
  # TO-DO: The `SKIP_BUILD_RPATH` property setting can be deleted
  #       in the future after reordering Guix script commands to
  #       perform binary checks after the installation step.
  # Relevant discussions:
  # - https://github.com/hebasto/bitcoin/pull/236#issuecomment-2183120953
  # - https://github.com/bitcoin/bitcoin/pull/30312#issuecomment-2191235833
  set_target_properties(btx-chainstate PROPERTIES
    SKIP_BUILD_RPATH OFF
    OUTPUT_NAME btx-chainstate
  )
  target_link_libraries(btx-chainstate
    PRIVATE
      core_interface
      bitcoinkernel
  )
  add_legacy_target_alias(bitcoin-chainstate btx-chainstate)
endif()


add_subdirectory(test/util)
if(BUILD_BENCH)
  add_subdirectory(bench)
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(BUILD_FUZZ_BINARY)
  add_subdirectory(test/fuzz)
endif()
