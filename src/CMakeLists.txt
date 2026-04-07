# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(AddWindowsResources)

configure_file(${PROJECT_SOURCE_DIR}/cmake/bitcoin-build-config.h.in bitcoin-build-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

if(APPLE)
  option(BTX_ENABLE_METAL "Enable optional Metal acceleration helpers for BTX utilities" ON)
else()
  option(BTX_ENABLE_METAL "Enable optional Metal acceleration helpers for BTX utilities" OFF)
endif()
option(BTX_ENABLE_CUDA_EXPERIMENTAL "Enable experimental CUDA backend scaffolding for BTX miner integration" OFF)

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
  matmul/matrix.cpp
  matmul/noise.cpp
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
    bitcoinpqc
    secp256k1
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<PLATFORM_ID:Windows>:ws2_32>
)
if(APPLE)
  find_library(BTX_ACCELERATE_FRAMEWORK Accelerate REQUIRED)
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
  shielded/turnstile.cpp
  shielded/validation.cpp
  shielded/v2_egress.cpp
  shielded/v2_ingress.cpp
  shielded/v2_proof.cpp
  shielded/v2_send.cpp
)
target_link_libraries(bitcoin_shielded
  PRIVATE
    core_interface
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
)
if(APPLE AND BTX_ENABLE_METAL)
  enable_language(OBJCXX)
  target_compile_options(btx_matmul_backend PRIVATE
    $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>
  )
  target_sources(btx_matmul_backend PRIVATE
    metal/matmul_accel.mm
    metal/nonce_accel.mm
    metal/oracle_accel.mm
  )
  find_library(BTX_FOUNDATION_FRAMEWORK Foundation REQUIRED)
  find_library(BTX_METAL_FRAMEWORK Metal REQUIRED)
  option(BTX_MATMUL_METAL_PRECOMPILE_KERNELS "Precompile MatMul Metal kernels with xcrun metallib at build time" ON)
  find_program(BTX_XCRUN_EXECUTABLE xcrun)
  if(BTX_MATMUL_METAL_PRECOMPILE_KERNELS AND BTX_XCRUN_EXECUTABLE)
    set(BTX_MATMUL_METAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/metal/matmul_accel_kernels.metal)
    set(BTX_MATMUL_METAL_AIR ${CMAKE_CURRENT_BINARY_DIR}/matmul_accel_kernels.air)
    set(BTX_MATMUL_METALLIB ${CMAKE_CURRENT_BINARY_DIR}/matmul_accel_kernels.metallib)
    set(BTX_ORACLE_METAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/metal/oracle_accel_kernels.metal)
    set(BTX_ORACLE_METAL_AIR ${CMAKE_CURRENT_BINARY_DIR}/oracle_accel_kernels.air)
    set(BTX_ORACLE_METALLIB ${CMAKE_CURRENT_BINARY_DIR}/oracle_accel_kernels.metallib)
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
    add_custom_target(btx_matmul_metallib DEPENDS ${BTX_MATMUL_METALLIB})
    add_custom_target(btx_oracle_metallib DEPENDS ${BTX_ORACLE_METALLIB})
    add_dependencies(btx_matmul_backend btx_matmul_metallib btx_oracle_metallib)
    target_compile_definitions(btx_matmul_backend PRIVATE
      BTX_MATMUL_METALLIB_PATH=\"${BTX_MATMUL_METALLIB}\"
      BTX_ORACLE_METALLIB_PATH=\"${BTX_ORACLE_METALLIB}\"
    )
  else()
    if(BTX_MATMUL_METAL_PRECOMPILE_KERNELS)
      message(STATUS "xcrun not found; MatMul Metal backend will compile inline kernels at runtime")
    else()
      message(STATUS "BTX_MATMUL_METAL_PRECOMPILE_KERNELS=OFF; MatMul Metal backend will compile inline kernels at runtime")
    endif()
  endif()
  target_compile_definitions(btx_matmul_backend PRIVATE BTX_ENABLE_METAL=1)
  target_link_libraries(btx_matmul_backend PRIVATE
    ${BTX_FOUNDATION_FRAMEWORK}
    ${BTX_METAL_FRAMEWORK}
  )
else()
  target_sources(btx_matmul_backend PRIVATE
    metal/matmul_accel_stub.cpp
    metal/nonce_accel_stub.cpp
    metal/oracle_accel_stub.cpp
  )
endif()
if(BTX_ENABLE_CUDA_EXPERIMENTAL)
  target_compile_definitions(btx_matmul_backend PRIVATE BTX_ENABLE_CUDA_EXPERIMENTAL=1)
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

# Provide canonical BTX CMake build targets while preserving legacy target names.
# Example: `cmake --build build --target btxd` builds legacy target `bitcoind`.
function(add_btx_target_alias alias_name target_name)
  if(TARGET ${target_name} AND NOT TARGET ${alias_name})
    add_custom_target(${alias_name} DEPENDS ${target_name})
  endif()
endfunction()

if(ENABLE_WALLET)
  add_subdirectory(wallet)

  if(BUILD_WALLET_TOOL)
    add_executable(bitcoin-wallet
      bitcoin-wallet.cpp
      init/bitcoin-wallet.cpp
      wallet/wallettool.cpp
    )
    set_target_properties(bitcoin-wallet PROPERTIES OUTPUT_NAME btx-wallet)
    add_windows_resources(bitcoin-wallet bitcoin-wallet-res.rc)
    target_link_libraries(bitcoin-wallet
      core_interface
      bitcoin_wallet
      Boost::headers
    )
    install_binary_component(bitcoin-wallet HAS_MANPAGE)
    add_legacy_binary_alias(bitcoin-wallet bitcoin-wallet)
    add_btx_target_alias(btx-wallet bitcoin-wallet)
  endif()
endif()


# P2P and RPC server functionality used by `bitcoind` and `bitcoin-qt` executables.
add_library(bitcoin_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  banman.cpp
  bip324.cpp
  blockencodings.cpp
  blockfilter.cpp
  consensus/tx_verify.cpp
  dandelion.cpp
  dbwrapper.cpp
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


# Bitcoin Core bitcoind.
if(BUILD_DAEMON)
  add_executable(bitcoind
    bitcoind.cpp
    init/bitcoind.cpp
  )
  set_target_properties(bitcoind PROPERTIES OUTPUT_NAME btxd)
  add_windows_resources(bitcoind bitcoind-res.rc)
  target_link_libraries(bitcoind
    core_interface
    bitcoin_node
    $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
  )
  install_binary_component(bitcoind HAS_MANPAGE)
  add_legacy_binary_alias(bitcoind bitcoind)
  add_btx_target_alias(btxd bitcoind)
endif()
if(WITH_MULTIPROCESS AND BUILD_DAEMON)
  add_executable(bitcoin-node
    bitcoind.cpp
    init/bitcoin-node.cpp
  )
  set_target_properties(bitcoin-node PROPERTIES OUTPUT_NAME btx-node)
  target_link_libraries(bitcoin-node
    core_interface
    bitcoin_node
    bitcoin_ipc
    $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
  )
  install_binary_component(bitcoin-node)
  add_btx_target_alias(btx-node bitcoin-node)
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
  add_executable(bitcoin-cli bitcoin-cli.cpp)
  set_target_properties(bitcoin-cli PROPERTIES OUTPUT_NAME btx-cli)
  add_windows_resources(bitcoin-cli bitcoin-cli-res.rc)
  target_link_libraries(bitcoin-cli
    core_interface
    bitcoin_cli
    bitcoin_common
    libevent::core
    libevent::extra
  )
  install_binary_component(bitcoin-cli HAS_MANPAGE)
  add_legacy_binary_alias(bitcoin-cli bitcoin-cli)
  add_btx_target_alias(btx-cli bitcoin-cli)
endif()


if(BUILD_TX)
  add_executable(bitcoin-tx bitcoin-tx.cpp)
  set_target_properties(bitcoin-tx PROPERTIES OUTPUT_NAME btx-tx)
  add_windows_resources(bitcoin-tx bitcoin-tx-res.rc)
  target_link_libraries(bitcoin-tx
    core_interface
    bitcoin_common
    bitcoin_shielded
  )
  if(APPLE)
    target_link_options(bitcoin-tx PRIVATE -Wl,-no_warn_duplicate_libraries)
  endif()
  install_binary_component(bitcoin-tx HAS_MANPAGE)
  add_legacy_binary_alias(bitcoin-tx bitcoin-tx)
  add_btx_target_alias(btx-tx bitcoin-tx)
endif()


if(BUILD_UTIL)
  add_executable(bitcoin-util bitcoin-util.cpp)
  set_target_properties(bitcoin-util PROPERTIES OUTPUT_NAME btx-util)
  add_windows_resources(bitcoin-util bitcoin-util-res.rc)
  target_link_libraries(bitcoin-util
    core_interface
    bitcoin_common
    bitcoin_shielded
  )
  if(APPLE)
    target_link_options(bitcoin-util PRIVATE -Wl,-no_warn_duplicate_libraries)
  endif()
  install_binary_component(bitcoin-util HAS_MANPAGE)
  add_legacy_binary_alias(bitcoin-util bitcoin-util)
  add_btx_target_alias(btx-util bitcoin-util)

  add_executable(btx-matmul-backend-info btx-matmul-backend-info.cpp)
  target_link_libraries(btx-matmul-backend-info
    core_interface
    bitcoin_common
  )
  install_binary_component(btx-matmul-backend-info)

  add_executable(btx-matmul-metal-bench btx-matmul-metal-bench.cpp)
  target_link_libraries(btx-matmul-metal-bench
    core_interface
    bitcoin_common
  )
  install_binary_component(btx-matmul-metal-bench)

  add_executable(btx-matmul-solve-bench btx-matmul-solve-bench.cpp)
  target_link_libraries(btx-matmul-solve-bench
    core_interface
    bitcoin_common
    bitcoin_shielded
  )
  if(APPLE)
    target_link_options(btx-matmul-solve-bench PRIVATE -Wl,-no_warn_duplicate_libraries)
  endif()
  install_binary_component(btx-matmul-solve-bench)

  add_executable(btx-genesis btx-genesis.cpp)

  # btx-genesis pulls in several static libs with circular dependencies
  # (e.g. util <-> crypto <-> consensus). GNU ld on Linux is sensitive to
  # archive order, so wrap the full static set in a group to avoid undefined refs.
  if(UNIX AND NOT APPLE)
    target_link_libraries(btx-genesis PRIVATE
      -Wl,--start-group
      core_interface
      btx_matmul_backend
      bitcoin_common
      bitcoin_shielded
      bitcoin_util
      bitcoin_clientversion
      bitcoin_consensus
      bitcoin_crypto
      bitcoinpqc
      secp256k1
      -Wl,--end-group
    )
  else()
    target_link_libraries(btx-genesis PRIVATE
      core_interface
      bitcoin_common
      bitcoin_shielded
    )
  endif()
  if(APPLE)
    target_link_options(btx-genesis PRIVATE -Wl,-no_warn_duplicate_libraries)
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
  add_executable(bitcoin-chainstate
    bitcoin-chainstate.cpp
  )
  # TO-DO: The `SKIP_BUILD_RPATH` property setting can be deleted
  #       in the future after reordering Guix script commands to
  #       perform binary checks after the installation step.
  # Relevant discussions:
  # - https://github.com/hebasto/bitcoin/pull/236#issuecomment-2183120953
  # - https://github.com/bitcoin/bitcoin/pull/30312#issuecomment-2191235833
  set_target_properties(bitcoin-chainstate PROPERTIES
    SKIP_BUILD_RPATH OFF
    OUTPUT_NAME btx-chainstate
  )
  target_link_libraries(bitcoin-chainstate
    PRIVATE
      core_interface
      bitcoinkernel
  )
  add_btx_target_alias(btx-chainstate bitcoin-chainstate)
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
