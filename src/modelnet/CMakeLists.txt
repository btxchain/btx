# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(NOT WITH_MODELNET)
  return()
endif()

find_package(OpenSSL REQUIRED)

add_library(bitcoin_modelnet STATIC
  types.cpp
  crypto.cpp
  resource_uri.cpp
  records.cpp
  policy.cpp
  firstrun.cpp
  protocol.cpp
  store.cpp
  swarm.cpp
  free_grant.cpp
  router.cpp
  transport_pq.cpp
  bridge.cpp
  transfer.cpp
  funding.cpp
  release.cpp
  economy.cpp
  feed.cpp
  qualification.cpp
  identity.cpp
  acl.cpp
  access_policy.cpp
  community.cpp
  reciprocity.cpp
  http_bridge.cpp
  cores.cpp
  catalog.cpp
  helper.cpp
  pq1_runtime.cpp
  piece_picker.cpp
  provider_exchange.cpp
  model_nat.cpp
  auto_storage.cpp
  piece_ranges.cpp
  supervisor.cpp
  reachability.cpp
  relay_reserve.cpp
  provider_route.cpp
  search.cpp
  canonical_codec.cpp
  bounty.cpp
  bounty_eval.cpp
)
target_link_libraries(bitcoin_modelnet
  PUBLIC
    core_interface
    bitcoin_crypto
    bitcoin_util
    bitcoin_common
    univalue
    bitcoinpqc
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)
target_include_directories(bitcoin_modelnet
  PUBLIC
    ${PROJECT_SOURCE_DIR}/src
)

add_executable(btx-modeld ../modeld.cpp)
set_target_properties(btx-modeld PROPERTIES OUTPUT_NAME btx-modeld)
target_link_libraries(btx-modeld core_interface)
target_link_btx_linux_archive_group(btx-modeld bitcoin_modelnet ${BTX_BASE_ARCHIVES})

add_executable(btx-modelcheck ../modelcheck.cpp)
set_target_properties(btx-modelcheck PROPERTIES OUTPUT_NAME btx-modelcheck)
target_link_libraries(btx-modelcheck core_interface)
target_link_btx_linux_archive_group(btx-modelcheck bitcoin_modelnet ${BTX_BASE_ARCHIVES})

add_executable(btx-open ../btx-open.cpp)
set_target_properties(btx-open PROPERTIES OUTPUT_NAME btx-open)
target_link_libraries(btx-open core_interface)
target_link_btx_linux_archive_group(btx-open bitcoin_modelnet ${BTX_BASE_ARCHIVES})

install(TARGETS btx-modeld btx-modelcheck btx-open RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
