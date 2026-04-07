# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.
target_sources(test_btx
  PRIVATE
    init_test_fixture.cpp
    wallet_test_fixture.cpp
    db_tests.cpp
    coinselector_tests.cpp
    feebumper_tests.cpp
    group_outputs_tests.cpp
    init_tests.cpp
    ismine_tests.cpp
    bridge_wallet_tests.cpp
    psbt_wallet_tests.cpp
    pq_multisig_wallet_tests.cpp
    pq_wallet_tests.cpp
    shielded_fee_tests.cpp
    scriptpubkeyman_tests.cpp
    spend_tests.cpp
    wallet_crypto_tests.cpp
    wallet_rpc_tests.cpp
    wallet_tests.cpp
    wallet_transaction_tests.cpp
    walletdb_tests.cpp
    walletload_tests.cpp
    ../../test/shielded_coin_selection_tests.cpp
    ../../test/shielded_wallet_address_tests.cpp
)
target_link_libraries(test_btx bitcoin_wallet)
