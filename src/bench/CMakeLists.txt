# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_executable(bench_bitcoin
  bench_bitcoin.cpp
  bench.cpp
  nanobench.cpp
# Benchmarks:
  addrman.cpp
  base58.cpp
  bech32.cpp
  bip324_ecdh.cpp
  block_assemble.cpp
  bridge_batch_bench.cpp
  ccoins_caching.cpp
  chacha20.cpp
  checkblock.cpp
  checkblockindex.cpp
  checkqueue.cpp
  cluster_linearize.cpp
  crypto_hash.cpp
  descriptors.cpp
  disconnected_transactions.cpp
  duplicate_inputs.cpp
  ellswift.cpp
  examples.cpp
  gcs_filter.cpp
  hashpadding.cpp
  index_blockfilter.cpp
  load_external.cpp
  lockedpool.cpp
  logging.cpp
  matmul_genesis_calibration.cpp
  matmul_batch_tuning_bench.cpp
  matmul_freivalds_bench.cpp
  matmul_metal_bench.cpp
  matmul_prehash_bench.cpp
  matmul_reuse_bench.cpp
  matmul_solve_bench.cpp
  mempool_ephemeral_spends.cpp
  mempool_eviction.cpp
  mempool_stress.cpp
  merkle_root.cpp
  ml_kem_bench.cpp
  parse_hex.cpp
  peer_eviction.cpp
  poly1305.cpp
  pool.cpp
  prevector.cpp
  pq_verify.cpp
  random.cpp
  readwriteblock.cpp
  rollingbloom.cpp
  rpc_blockchain.cpp
  rpc_mempool.cpp
  sign_transaction.cpp
  shielded_matrict_bench.cpp
  shielded_merkle_bench.cpp
  shielded_note_bench.cpp
  shielded_ring_signature_bench.cpp
  shielded_turnstile_bench.cpp
  streams_findbyte.cpp
  strencodings.cpp
  util_time.cpp
  verify_script.cpp
  xor.cpp
)
set_target_properties(bench_bitcoin PROPERTIES OUTPUT_NAME bench_btx)

include(TargetDataSources)
target_raw_data_sources(bench_bitcoin NAMESPACE benchmark::data
  data/block413567.raw
)

target_link_libraries(bench_bitcoin
  core_interface
  $<TARGET_NAME_IF_EXISTS:bitcoinconsensus>
  Boost::headers
)
if(UNIX AND NOT APPLE)
  if(ENABLE_WALLET)
    target_link_btx_linux_archive_group(bench_bitcoin
      test_util
      ${BTX_NODE_WALLET_ARCHIVES}
    )
  else()
    target_link_btx_linux_archive_group(bench_bitcoin
      test_util
      ${BTX_NODE_ARCHIVES}
    )
  endif()
else()
  target_link_libraries(bench_bitcoin
    test_util
    bitcoin_node
    $<$<BOOL:${ENABLE_WALLET}>:bitcoin_wallet>
  )
endif()

if(ENABLE_WALLET)
  target_sources(bench_bitcoin
    PRIVATE
      coin_selection.cpp
      wallet_balance.cpp
      wallet_create.cpp
      wallet_create_tx.cpp
      wallet_loading.cpp
      wallet_ismine.cpp
      wallet_migration.cpp
  )
endif()

# Canonical BTX build target name while preserving legacy bench_bitcoin target.
add_custom_target(bench_btx DEPENDS bench_bitcoin)
# Keep legacy executable name as a symlink/copy to bench_btx for compatibility.
add_legacy_binary_alias(bench_bitcoin bench_bitcoin)

add_test(NAME bench_sanity_check_high_priority
  COMMAND bench_bitcoin -sanity-check -priority-level=high
)

make_libbitcoinconsensus_dll_available(bench_bitcoin)
install_binary_component(bench_bitcoin)
