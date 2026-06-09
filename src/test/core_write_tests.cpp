// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Regression test for the `getblock <hash> 2` / TxToUniv "Internal bug detected: MoneyRange(fee)"
// crash on shielded transactions. For a shielded unshield, transparent outputs can legitimately
// exceed transparent inputs (the difference flows out of the shielded pool), so the transparent-only
// fee (in - out) goes negative and tripped CHECK_NONFATAL(MoneyRange(fee)). The serializer must
// account for the shielded value_balance -- exactly as consensus (CheckTxInputs) does.

#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <univalue.h>
#include <util/transaction_identifier.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(core_write_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(txtouniv_shielded_unshield_fee_stays_in_money_range)
{
    // A shielded unshield: 1 BTX transparent input, 100 BTX transparent output (99 of it funded from
    // the shielded pool), with value_balance = 99.5 BTX flowing OUT of the pool. The real fee is
    // 1 + 99.5 - 100 = 0.5 BTX. Before the fix, TxToUniv computed fee = transparent_in - transparent_out
    // = 1 - 100 = -99 BTX and aborted with MoneyRange(fee) when called via `getblock <hash> 2`.
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});  // non-null -> not a coinbase
    mtx.vout.emplace_back(100 * COIN, CScript() << OP_TRUE);
    mtx.shielded_bundle.value_balance = 99 * COIN + COIN / 2;  // 99.5 BTX out of the pool

    const CTransaction tx{mtx};
    BOOST_REQUIRE(tx.HasShieldedBundle());

    // Whole-block serializer supplies the spent prevout via the undo data (this is the path that broke).
    CTxUndo undo;
    undo.vprevout.emplace_back(CTxOut{1 * COIN, CScript() << OP_TRUE}, /*nHeightIn=*/1, /*fCoinBaseIn=*/false);

    UniValue entry(UniValue::VOBJ);
    BOOST_REQUIRE_NO_THROW(
        TxToUniv(tx, /*block_hash=*/uint256::ZERO, entry, /*include_hex=*/false, &undo,
                 TxVerbosity::SHOW_DETAILS));

    // fee = transparent_in + value_balance - transparent_out = 1 + 99.5 - 100 = 0.5 BTX.
    BOOST_REQUIRE(entry.exists("fee"));
    BOOST_CHECK_EQUAL(entry["fee"].getValStr(), "0.50000000");
}

BOOST_AUTO_TEST_CASE(txtouniv_transparent_only_fee_unchanged)
{
    // Sanity: a plain transparent tx (no shielded bundle) still reports the ordinary fee.
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(99 * COIN, CScript() << OP_TRUE);  // 1 BTX fee

    const CTransaction tx{mtx};
    BOOST_REQUIRE(!tx.HasShieldedBundle());

    CTxUndo undo;
    undo.vprevout.emplace_back(CTxOut{100 * COIN, CScript() << OP_TRUE}, /*nHeightIn=*/1, /*fCoinBaseIn=*/false);

    UniValue entry(UniValue::VOBJ);
    BOOST_REQUIRE_NO_THROW(
        TxToUniv(tx, /*block_hash=*/uint256::ZERO, entry, /*include_hex=*/false, &undo,
                 TxVerbosity::SHOW_DETAILS));
    BOOST_CHECK_EQUAL(entry["fee"].getValStr(), "1.00000000");
}

BOOST_AUTO_TEST_SUITE_END()
