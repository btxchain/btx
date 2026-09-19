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
  piece_store.cpp
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
  file_stream.cpp
  direct_seed.cpp
  profile.cpp
  event_journal.cpp
  model_watch.cpp
  subscription_mandate.cpp
  cloud_layout.cpp
  s3_client.cpp
  s3_store.cpp
  verified_manifest.cpp
  transfer_session.cpp
  import_plan.cpp
  package_bundle.cpp
  erasure_store.cpp
  erasure_manifest.cpp
  package_export.cpp
  package_pjson.cpp
  package_core.cpp
  package_documents.cpp
  package_acquisition.cpp
  package_install.cpp
  package_runtime.cpp
  package_channel.cpp
  package_economy.cpp
  package_execute.cpp
  upload_scheduler.cpp
  upload_scheduler_drr.cpp
  bootstrap_distributor.cpp
  origin_broker.cpp
  metadata_gossip.cpp
  query_router.cpp
  index_reconcile.cpp
  source_local.cpp
  import_coordinator.cpp
  source_huggingface.cpp
  source_xet.cpp
  source_torrent.cpp
  object_layout.cpp
  subpiece.cpp
  bulk_controller.cpp
  io_executor.cpp
  hello_caps.cpp
  helper_network02.cpp
  source_policy.cpp
  residency_state.cpp
  multipart_journal.cpp
  operation_budget.cpp
  physical_dedup.cpp
  selective_files.cpp
  lan_discovery.cpp
  capability_types.cpp
  capability_core.cpp
  capability_residency.cpp
  capability_bytes.cpp
  capability_exec.cpp
  capability_control.cpp
  capability_fuse.cpp
  capability_runtime.cpp
  capability_compose.cpp
  capability_prefetch.cpp
  capability_ensure.cpp
  capability_peer.cpp
  capability_moe.cpp
  capability_sdk.cpp
  hcp_codec.cpp
    hcp_cr11.cpp
    hcp_crl12.cpp
    hcp_engine.cpp
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

set(_btx_crl12_schema "${PROJECT_SOURCE_DIR}/contrib/modelnet/crl12/schemas/CognitiveReserveLayer.schema.json")
set(_btx_crl12_ops "${PROJECT_SOURCE_DIR}/contrib/modelnet/crl12/schemas/operations-v1.2.json")
set(_btx_cr11_schema "${PROJECT_SOURCE_DIR}/contrib/modelnet/crl12/compatibility/v1_1/schemas/CognitiveReserve.schema.json")
set(_btx_cr11_ops "${PROJECT_SOURCE_DIR}/contrib/modelnet/crl12/compatibility/v1_1/schemas/operations-v1.1.json")
if(EXISTS "${_btx_crl12_schema}")
  file(SHA384 "${_btx_crl12_schema}" BTX_CRL12_SCHEMA_SHA384)
  target_compile_definitions(bitcoin_modelnet PRIVATE BTX_CRL12_SCHEMA_SHA384="${BTX_CRL12_SCHEMA_SHA384}")
endif()
if(EXISTS "${_btx_crl12_ops}")
  file(SHA384 "${_btx_crl12_ops}" BTX_CRL12_OPERATIONS_SHA384)
  target_compile_definitions(bitcoin_modelnet PRIVATE BTX_CRL12_OPERATIONS_SHA384="${BTX_CRL12_OPERATIONS_SHA384}")
endif()
if(EXISTS "${_btx_cr11_schema}")
  file(SHA384 "${_btx_cr11_schema}" BTX_CR11_SCHEMA_SHA384)
  target_compile_definitions(bitcoin_modelnet PRIVATE BTX_CR11_SCHEMA_SHA384="${BTX_CR11_SCHEMA_SHA384}")
endif()
if(EXISTS "${_btx_cr11_ops}")
  file(SHA384 "${_btx_cr11_ops}" BTX_CR11_OPERATIONS_SHA384)
  target_compile_definitions(bitcoin_modelnet PRIVATE BTX_CR11_OPERATIONS_SHA384="${BTX_CR11_OPERATIONS_SHA384}")
endif()

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

add_executable(btx-capabilityd ../capabilityd.cpp)
set_target_properties(btx-capabilityd PROPERTIES OUTPUT_NAME btx-capabilityd)
target_link_libraries(btx-capabilityd core_interface)
target_link_btx_linux_archive_group(btx-capabilityd bitcoin_modelnet ${BTX_BASE_ARCHIVES})

add_executable(btx-capability ../btx-capability.cpp)
set_target_properties(btx-capability PROPERTIES OUTPUT_NAME btx-capability)
target_link_libraries(btx-capability core_interface)
target_link_btx_linux_archive_group(btx-capability bitcoin_modelnet ${BTX_BASE_ARCHIVES})

add_executable(btx-hcpd ../hcpd.cpp)
set_target_properties(btx-hcpd PROPERTIES OUTPUT_NAME btx-hcpd)
target_link_libraries(btx-hcpd core_interface)
target_link_btx_linux_archive_group(btx-hcpd bitcoin_modelnet ${BTX_BASE_ARCHIVES})

add_executable(btx-hosted ../hosted.cpp)
set_target_properties(btx-hosted PROPERTIES OUTPUT_NAME btx-hosted)
target_link_libraries(btx-hosted core_interface)
target_link_btx_linux_archive_group(btx-hosted bitcoin_modelnet ${BTX_BASE_ARCHIVES})

install(TARGETS btx-modeld btx-modelcheck btx-open btx-capabilityd btx-capability btx-hcpd btx-hosted RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
