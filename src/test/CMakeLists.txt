# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.
add_executable(test_btx
  main.cpp
  addrman_tests.cpp
  allocator_tests.cpp
  amount_tests.cpp
  argsman_tests.cpp
  arith_uint256_tests.cpp
  banman_tests.cpp
  base32_tests.cpp
  base58_tests.cpp
  base64_tests.cpp
  bech32_tests.cpp
  bip32_tests.cpp
  bip324_tests.cpp
  blockchain_tests.cpp
  blockencodings_tests.cpp
  blockfilter_index_tests.cpp
  blockfilter_tests.cpp
  blockmanager_tests.cpp
  bloom_tests.cpp
  bswap_tests.cpp
  chainstate_write_tests.cpp
  checkqueue_tests.cpp
  cluster_linearize_tests.cpp
  codex32_tests.cpp
  coins_tests.cpp
  coinscachepair_tests.cpp
  coinstatsindex_tests.cpp
  common_url_tests.cpp
  compilerbug_tests.cpp
  compress_tests.cpp
  crypto_tests.cpp
  cuckoocache_tests.cpp
  dbwrapper_tests.cpp
  dandelion_tests.cpp
  denialofservice_tests.cpp
  descriptor_tests.cpp
  disconnected_transactions.cpp
  feefrac_tests.cpp
  flatfile_tests.cpp
  fs_tests.cpp
  getarg_tests.cpp
  hash_tests.cpp
  headers_sync_chainwork_tests.cpp
  httpserver_tests.cpp
  i2p_tests.cpp
  interfaces_tests.cpp
  kawpow_tests.cpp
  key_io_tests.cpp
  key_tests.cpp
  logging_tests.cpp
  mempool_tests.cpp
  merkle_tests.cpp
  merkleblock_tests.cpp
  matmul_field_tests.cpp
  matmul_freivalds_tests.cpp
  matmul_params_tests.cpp
  matmul_header_tests.cpp
  matmul_block_capacity_tests.cpp
  matmul_matrix_tests.cpp
  matmul_noise_tests.cpp
  matmul_pow_tests.cpp
  matmul_accelerated_solver_tests.cpp
  matmul_backend_capabilities_tests.cpp
  matmul_metal_tests.cpp
  matmul_transcript_tests.cpp
  matmul_validation_tests.cpp
  matmul_trust_model_tests.cpp
  matmul_dgw_tests.cpp
  matmul_subsidy_tests.cpp
  matmul_mining_tests.cpp
  mining_chain_guard_tests.cpp
  mining_crash_guard_tests.cpp
  pq_crypto_tests.cpp
  pq_merkle_tests.cpp
  pq_address_tests.cpp
  pq_consensus_tests.cpp
  pq_multisig_tests.cpp
  pq_descriptor_tests.cpp
  pq_multisig_descriptor_tests.cpp
  script_htlc_templates_tests.cpp
  pq_keyderivation_tests.cpp
  descriptor_pqhd_tests.cpp
  pq_phase4_tests.cpp
  pq_policy_tests.cpp
  pq_genesis_tests.cpp
  pq_timing_tests.cpp
  pq_mining_template_tests.cpp
  miner_tests.cpp
  miniminer_tests.cpp
  miniscript_tests.cpp
  multisig_tests.cpp
  net_peer_connection_tests.cpp
  net_peer_eviction_tests.cpp
  net_tests.cpp
  netbase_tests.cpp
  node_warnings_tests.cpp
  orphanage_tests.cpp
  pcp_tests.cpp
  peerman_tests.cpp
  pmt_tests.cpp
  policy_fee_tests.cpp
  policyestimator_tests.cpp
  pool_tests.cpp
  pow_tests.cpp
  prevector_tests.cpp
  raii_event_tests.cpp
  random_tests.cpp
  rbf_tests.cpp
  rest_tests.cpp
  result_tests.cpp
  reverselock_tests.cpp
  rpc_tests.cpp
  sanity_tests.cpp
  scheduler_tests.cpp
  script_p2sh_tests.cpp
  script_parse_tests.cpp
  script_segwit_tests.cpp
  script_standard_tests.cpp
  script_tests.cpp
  scriptnum_tests.cpp
  serfloat_tests.cpp
  serialize_tests.cpp
  settings_tests.cpp
  ml_kem_tests.cpp
  lattice_poly_tests.cpp
  lattice_polyvec_tests.cpp
  note_encryption_tests.cpp
  shielded_merkle_serialization_tests.cpp
  shielded_merkle_tests.cpp
  shielded_transaction_tests.cpp
  shielded_tx_check_tests.cpp
  shielded_tx_verify_tests.cpp
  shielded_note_tests.cpp
  shielded_proof_adversarial_tests.cpp
  shielded_mempool_tests.cpp
  shielded_turnstile_tests.cpp
  shielded_validation_checks_tests.cpp
  shielded_matrict_plus_tests.cpp
  shielded_matrict_runtime_report.cpp
  shielded_matrict_runtime_report_tests.cpp
  shielded_ingress_runtime_report.cpp
  shielded_ingress_runtime_report_tests.cpp
  shielded_ingress_proof_runtime_report.cpp
  shielded_ingress_proof_runtime_report_tests.cpp
  shielded_kat_tests.cpp
  shielded_audit_compliance_tests.cpp
  shielded_stress_tests.cpp
  shielded_hardening_tests.cpp
  shielded_audit_regression_tests.cpp
  shielded_bridge_tests.cpp
  shielded_account_registry_tests.cpp
  shielded_v2_bundle_tests.cpp
  shielded_v2_egress_tests.cpp
  shielded_v2_egress_runtime_report.cpp
  shielded_v2_egress_runtime_report_tests.cpp
  shielded_v2_adversarial_proof_corpus.cpp
  shielded_v2_adversarial_proof_corpus_tests.cpp
  shielded_v2_ingress_tests.cpp
  shielded_v2_chain_growth_projection_report.cpp
  shielded_v2_chain_growth_projection_report_tests.cpp
  shielded_v2_netting_capacity_report.cpp
  shielded_v2_netting_capacity_report_tests.cpp
  shielded_v2_proof_tests.cpp
  shielded_v2_send_tests.cpp
  shielded_v2_send_runtime_report.cpp
  shielded_v2_send_runtime_report_tests.cpp
  shielded_v2_wire_tests.cpp
  shielded_wallet_privacy_tests.cpp
  shielded_wallet_chunk_discovery_tests.cpp
  shielded_chunk_runtime_report.cpp
  shielded_chunk_runtime_report_tests.cpp
  shielded_scan_hint_runtime_report.cpp
  shielded_scan_hint_runtime_report_tests.cpp
  shielded_relay_fixture_builder.cpp
  shielded_relay_fixture_builder_tests.cpp
  btx_launch_readiness_tests.cpp
  nullifier_set_tests.cpp
  ringct_commitment_tests.cpp
  ringct_range_proof_tests.cpp
  ringct_balance_proof_tests.cpp
  ring_selection_tests.cpp
  ringct_ring_signature_tests.cpp
  ringct_matrict_tests.cpp
  smile2_poly_tests.cpp
  smile2_bdlop_tests.cpp
  smile2_membership_tests.cpp
  smile2_ct_tests.cpp
  smile2_proof_redesign_harness.cpp
  smile2_proof_redesign_framework_tests.cpp
  smile2_integration_tests.cpp
  smile2_audit_tests.cpp
  smile2_wallet_bridge_tests.cpp
  smile2_adversarial_tests.cpp
  smile2_deep_adversarial_tests.cpp
  smile2_extreme_adversarial_tests.cpp
  smile2_edge_case_tests.cpp
  smile2_comprehensive_gap_tests.cpp
  smile2_realworld_attack_tests.cpp
  matrict_adversarial_tests.cpp
  sighash_tests.cpp
  sigopcount_tests.cpp
  skiplist_tests.cpp
  sock_tests.cpp
  span_tests.cpp
  streams_tests.cpp
  sync_tests.cpp
  system_tests.cpp
  timeoffsets_tests.cpp
  torcontrol_tests.cpp
  transaction_tests.cpp
  translation_tests.cpp
  txdownload_tests.cpp
  txindex_tests.cpp
  txpackage_tests.cpp
  txreconciliation_tests.cpp
  txrequest_tests.cpp
  txvalidation_tests.cpp
  txvalidationcache_tests.cpp
  uint256_tests.cpp
  util_string_tests.cpp
  util_tests.cpp
  util_threadnames_tests.cpp
  util_trace_tests.cpp
  validation_block_tests.cpp
  validation_chainstate_tests.cpp
  validation_chainstatemanager_tests.cpp
  validation_flush_tests.cpp
  validation_tests.cpp
  validationinterface_tests.cpp
  versionbits_tests.cpp
  ../stats/test/stats_tests.cpp
)

include(TargetDataSources)
target_json_data_sources(test_btx
  data/base58_encode_decode.json
  data/bip341_wallet_vectors.json
  data/blockfilters.json
  data/key_io_invalid.json
  data/key_io_valid.json
  data/script_tests.json
  data/sighash.json
  data/tx_invalid.json
  data/tx_valid.json
)
target_raw_data_sources(test_btx NAMESPACE test::data
  data/asmap.raw
)
target_include_directories(test_btx PRIVATE
  $<TARGET_PROPERTY:secp256k1,INTERFACE_INCLUDE_DIRECTORIES>
)
target_compile_definitions(test_btx PRIVATE
  BTX_REFERENCE_TEST_VECTORS_PATH=\"${PROJECT_SOURCE_DIR}/test/reference/shielded_test_vectors.json\"
)

target_link_libraries(test_btx
  core_interface
  test_util
  $<TARGET_NAME_IF_EXISTS:bitcoinconsensus>
  bitcoin_cli
  bitcoin_node
  Boost::headers
  libevent::extra
)

add_library(test_translation_stub OBJECT
  util/translation_stub.cpp
)

function(add_test_translation_stub target)
  target_sources(${target} PRIVATE $<TARGET_OBJECTS:test_translation_stub>)
endfunction()

add_executable(generate_shielded_matrict_plus_vectors
  generate_shielded_matrict_plus_vectors.cpp
)
set_target_properties(generate_shielded_matrict_plus_vectors PROPERTIES
  OUTPUT_NAME gen_shielded_matrict_plus_vectors
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_matrict_plus_vectors)
target_link_libraries(generate_shielded_matrict_plus_vectors
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_matrict_plus_runtime_report
  generate_shielded_matrict_plus_runtime_report.cpp
  shielded_matrict_runtime_report.cpp
)
set_target_properties(generate_shielded_matrict_plus_runtime_report PROPERTIES
  OUTPUT_NAME gen_shielded_matrict_plus_runtime_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
target_compile_definitions(generate_shielded_matrict_plus_runtime_report PRIVATE
  BTX_REFERENCE_TEST_VECTORS_PATH=\"${PROJECT_SOURCE_DIR}/test/reference/shielded_test_vectors.json\"
)
add_test_translation_stub(generate_shielded_matrict_plus_runtime_report)
target_link_libraries(generate_shielded_matrict_plus_runtime_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_matrict_plus_transcript_corpus
  generate_shielded_matrict_plus_transcript_corpus.cpp
)
set_target_properties(generate_shielded_matrict_plus_transcript_corpus PROPERTIES
  OUTPUT_NAME gen_shielded_matrict_plus_transcript_corpus
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_matrict_plus_transcript_corpus)
target_link_libraries(generate_shielded_matrict_plus_transcript_corpus
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_ingress_runtime_report
  generate_shielded_ingress_runtime_report.cpp
  shielded_ingress_runtime_report.cpp
)
set_target_properties(generate_shielded_ingress_runtime_report PROPERTIES
  OUTPUT_NAME gen_shielded_ingress_runtime_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_ingress_runtime_report)
target_link_libraries(generate_shielded_ingress_runtime_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_ingress_proof_runtime_report
  generate_shielded_ingress_proof_runtime_report.cpp
  shielded_ingress_proof_runtime_report.cpp
)
set_target_properties(generate_shielded_ingress_proof_runtime_report PROPERTIES
  OUTPUT_NAME gen_shielded_ingress_proof_runtime_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_ingress_proof_runtime_report)
target_link_libraries(generate_shielded_ingress_proof_runtime_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_scan_hint_runtime_report
  generate_shielded_scan_hint_runtime_report.cpp
  shielded_scan_hint_runtime_report.cpp
)
set_target_properties(generate_shielded_scan_hint_runtime_report PROPERTIES
  OUTPUT_NAME gen_shielded_scan_hint_runtime_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_scan_hint_runtime_report)
target_link_libraries(generate_shielded_scan_hint_runtime_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_chunk_runtime_report
  generate_shielded_chunk_runtime_report.cpp
  shielded_chunk_runtime_report.cpp
)
set_target_properties(generate_shielded_chunk_runtime_report PROPERTIES
  OUTPUT_NAME gen_shielded_chunk_runtime_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_chunk_runtime_report)
target_link_libraries(generate_shielded_chunk_runtime_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_v2_send_runtime_report
  generate_shielded_v2_send_runtime_report.cpp
  shielded_v2_send_runtime_report.cpp
)
set_target_properties(generate_shielded_v2_send_runtime_report PROPERTIES
  OUTPUT_NAME gen_shielded_v2_send_runtime_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_v2_send_runtime_report)
target_link_libraries(generate_shielded_v2_send_runtime_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_v2_egress_runtime_report
  generate_shielded_v2_egress_runtime_report.cpp
  shielded_v2_egress_runtime_report.cpp
)
set_target_properties(generate_shielded_v2_egress_runtime_report PROPERTIES
  OUTPUT_NAME gen_shielded_v2_egress_runtime_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_v2_egress_runtime_report)
target_link_libraries(generate_shielded_v2_egress_runtime_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_v2_netting_capacity_report
  generate_shielded_v2_netting_capacity_report.cpp
  shielded_v2_netting_capacity_report.cpp
)
set_target_properties(generate_shielded_v2_netting_capacity_report PROPERTIES
  OUTPUT_NAME gen_shielded_v2_netting_capacity_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_v2_netting_capacity_report)
target_link_libraries(generate_shielded_v2_netting_capacity_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_v2_chain_growth_projection_report
  generate_shielded_v2_chain_growth_projection_report.cpp
  shielded_v2_chain_growth_projection_report.cpp
  shielded_v2_send_runtime_report.cpp
  shielded_ingress_proof_runtime_report.cpp
  shielded_v2_egress_runtime_report.cpp
  shielded_v2_netting_capacity_report.cpp
)
set_target_properties(generate_shielded_v2_chain_growth_projection_report PROPERTIES
  OUTPUT_NAME gen_shielded_v2_chain_growth_projection_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_v2_chain_growth_projection_report)
target_link_libraries(generate_shielded_v2_chain_growth_projection_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_smile2_proof_redesign_report
  generate_smile2_proof_redesign_report.cpp
  smile2_proof_redesign_harness.cpp
  shielded_v2_send_runtime_report.cpp
  shielded_ingress_proof_runtime_report.cpp
)
set_target_properties(generate_smile2_proof_redesign_report PROPERTIES
  OUTPUT_NAME gen_smile2_proof_redesign_report
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_smile2_proof_redesign_report)
target_link_libraries(generate_smile2_proof_redesign_report
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_relay_fixture_tx
  generate_shielded_relay_fixture_tx.cpp
  shielded_relay_fixture_builder.cpp
)
set_target_properties(generate_shielded_relay_fixture_tx PROPERTIES
  OUTPUT_NAME gen_shielded_relay_fixture_tx
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_relay_fixture_tx)
target_link_libraries(generate_shielded_relay_fixture_tx
  PRIVATE
    core_interface
    bitcoin_node
)

add_executable(generate_shielded_v2_adversarial_proof_corpus
  generate_shielded_v2_adversarial_proof_corpus.cpp
  shielded_v2_adversarial_proof_corpus.cpp
)
set_target_properties(generate_shielded_v2_adversarial_proof_corpus PROPERTIES
  OUTPUT_NAME gen_shielded_v2_adversarial_proof_corpus
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_test_translation_stub(generate_shielded_v2_adversarial_proof_corpus)
target_link_libraries(generate_shielded_v2_adversarial_proof_corpus
  PRIVATE
    core_interface
    bitcoin_node
)

if(ENABLE_WALLET)
  add_subdirectory(${PROJECT_SOURCE_DIR}/src/wallet/test wallet)
endif()

if(WITH_MULTIPROCESS)
  target_link_libraries(bitcoin_ipc_test
    PRIVATE
      core_interface
      univalue
  )

  target_sources(test_btx
    PRIVATE
      ipc_tests.cpp
  )
  target_link_libraries(test_btx bitcoin_ipc_test bitcoin_ipc)
endif()

# Keep backward-compatible CMake build target name for existing automation.
add_custom_target(test_bitcoin DEPENDS test_btx)
# Keep legacy executable name available for existing CI and packaging scripts.
add_legacy_binary_alias(test_btx test_bitcoin)

function(add_boost_test source_file)
  if(NOT EXISTS ${source_file})
    return()
  endif()

  file(READ "${source_file}" source_file_content)
  string(REGEX
    MATCH "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(([A-Za-z0-9_]+)"
    test_suite_macro "${source_file_content}"
  )
  string(REGEX
    REPLACE "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(" ""
    test_suite_name "${test_suite_macro}"
  )
  if(test_suite_name)
    add_test(NAME ${test_suite_name}
      COMMAND test_btx --run_test=${test_suite_name} --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT
    )
    set_property(TEST ${test_suite_name} PROPERTY
      SKIP_REGULAR_EXPRESSION "no test cases matching filter"
    )
  endif()
endfunction()

function(add_all_test_targets)
  get_target_property(test_source_dir test_btx SOURCE_DIR)
  get_target_property(test_sources test_btx SOURCES)
  foreach(test_source ${test_sources})
    cmake_path(IS_RELATIVE test_source result)
    if(result)
      cmake_path(APPEND test_source_dir ${test_source} OUTPUT_VARIABLE test_source)
    endif()
    add_boost_test(${test_source})
  endforeach()
endfunction()

add_all_test_targets()

# Timing-variance checks are sensitive to host contention; run this suite
# without concurrent ctest jobs to avoid false negatives under -j.
set_tests_properties(pq_timing_tests PROPERTIES RUN_SERIAL TRUE)

make_libbitcoinconsensus_dll_available(test_btx)
install_binary_component(test_btx)
