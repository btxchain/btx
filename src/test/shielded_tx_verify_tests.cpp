// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <shielded/lattice/params.h>
#include <shielded/v2_bundle.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_v2_egress_fixture.h>
#include <test/util/shielded_smile_test_util.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shielded_tx_verify_tests, BasicTestingSetup)

namespace {

} // namespace

BOOST_AUTO_TEST_CASE(checktxinputs_allows_unshield_value_balance)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(5 * COIN, CScript{} << OP_TRUE);
    mtx.shielded_bundle.value_balance = 5 * COIN;
    CShieldedInput in;
    in.nullifier = GetRandHash();
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        in.ring_positions.push_back(i);
    }
    mtx.shielded_bundle.shielded_inputs.push_back(in);
    mtx.shielded_bundle.proof = {0x01};

    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(out);

    CCoinsView view;
    CCoinsViewCache cache(&view);

    CAmount fee{0};
    TxValidationState state;
    BOOST_CHECK(Consensus::CheckTxInputs(CTransaction(mtx), state, cache, /*nSpendHeight=*/1, fee));
    BOOST_CHECK_EQUAL(fee, 0);
}

BOOST_AUTO_TEST_CASE(checktxinputs_rejects_missing_shielded_balance)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(5 * COIN, CScript{} << OP_TRUE);

    CCoinsView view;
    CCoinsViewCache cache(&view);

    CAmount fee{0};
    TxValidationState state;
    BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, /*nSpendHeight=*/1, fee));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-in-belowout");
}

BOOST_AUTO_TEST_CASE(checktxinputs_allows_shield_value_balance)
{
    CMutableTransaction mtx;
    const COutPoint prevout{Txid::FromUint256(GetRandHash()), 0};
    mtx.vin.emplace_back(prevout);

    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(out);
    mtx.shielded_bundle.value_balance = -4 * COIN;

    CCoinsView view;
    CCoinsViewCache cache(&view);
    cache.AddCoin(prevout, Coin{CTxOut{5 * COIN, CScript{} << OP_TRUE}, /*height=*/1, /*coinbase=*/false}, /*possible_overwrite=*/false);

    CAmount fee{0};
    TxValidationState state;
    BOOST_CHECK(Consensus::CheckTxInputs(CTransaction(mtx), state, cache, /*nSpendHeight=*/2, fee));
    BOOST_CHECK_EQUAL(fee, 1 * COIN);
}

BOOST_AUTO_TEST_CASE(checktxinputs_uses_v2_send_fee_as_explicit_shielded_balance)
{
    using namespace shielded::v2;

    const ShieldedNote note = test::shielded::MakeDeterministicSmileNote(/*seed=*/0x65, /*value=*/5000);
    const auto output_account = test::shielded::MakeDeterministicCompactPublicAccount(/*seed=*/0x66, /*value=*/4000);
    const uint256 output_note_commitment = smile2::ComputeCompactPublicAccountHash(output_account);
    const auto account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
        note,
        output_note_commitment,
        shielded::registry::MakeDirectSendAccountLeafHint());
    BOOST_REQUIRE(account_leaf_commitment.has_value());
    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    BOOST_REQUIRE(input_account.has_value());
    const auto account_registry_witness = test::shielded::MakeSingleLeafRegistryWitness(
        output_note_commitment,
        *input_account);
    BOOST_REQUIRE(account_registry_witness.has_value());

    SpendDescription spend;
    spend.nullifier = uint256{0x61};
    spend.merkle_anchor = uint256{0x62};
    spend.account_leaf_commitment = *account_leaf_commitment;
    spend.account_registry_proof = account_registry_witness->second;
    spend.note_commitment = uint256{0x63};
    spend.value_commitment = uint256{0x64};

    OutputDescription output;
    output.note_class = NoteClass::USER;
    output.smile_account = output_account;
    output.note_commitment = output_note_commitment;
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output_account.public_coin);
    output.encrypted_note.scan_domain = ScanDomain::USER;
    output.encrypted_note.scan_hint.fill(0x41);
    output.encrypted_note.ciphertext = {0x51, 0x52};
    output.encrypted_note.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{output.encrypted_note.ciphertext.data(), output.encrypted_note.ciphertext.size()});

    SendPayload payload;
    payload.spend_anchor = uint256{0x67};
    payload.account_registry_anchor = account_registry_witness->first;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = 1 * COIN;
    payload.value_balance = payload.fee;

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = TransactionFamily::V2_SEND;
    tx_bundle.header.proof_envelope.proof_kind = ProofKind::DIRECT_MATRICT;
    tx_bundle.header.proof_envelope.membership_proof_kind = ProofComponentKind::MATRICT;
    tx_bundle.header.proof_envelope.amount_proof_kind = ProofComponentKind::RANGE;
    tx_bundle.header.proof_envelope.balance_proof_kind = ProofComponentKind::BALANCE;
    tx_bundle.header.proof_envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    tx_bundle.header.proof_envelope.statement_digest = uint256{0x68};
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    tx_bundle.payload = payload;
    tx_bundle.proof_payload = {0x71, 0x72};

    CMutableTransaction mtx;
    mtx.shielded_bundle.v2_bundle = tx_bundle;

    CCoinsView view;
    CCoinsViewCache cache(&view);

    CAmount fee{0};
    TxValidationState state;
    BOOST_CHECK(Consensus::CheckTxInputs(CTransaction(mtx), state, cache, /*nSpendHeight=*/1, fee));
    BOOST_CHECK_EQUAL(fee, 1 * COIN);
}

BOOST_AUTO_TEST_CASE(checktxinputs_uses_zero_explicit_balance_for_bridge_mint_families)
{
    {
        const auto fixture = test::shielded::BuildV2EgressReceiptFixture();
        CCoinsView view;
        CCoinsViewCache cache(&view);

        CAmount fee{0};
        TxValidationState state;
        BOOST_CHECK(Consensus::CheckTxInputs(CTransaction(fixture.tx), state, cache, /*nSpendHeight=*/1, fee));
        BOOST_CHECK_EQUAL(fee, 0);
    }

    {
        const auto fixture = test::shielded::BuildV2RebalanceFixture();
        CCoinsView view;
        CCoinsViewCache cache(&view);

        CAmount fee{0};
        TxValidationState state;
        BOOST_CHECK(Consensus::CheckTxInputs(CTransaction(fixture.tx), state, cache, /*nSpendHeight=*/1, fee));
        BOOST_CHECK_EQUAL(fee, 0);
    }
}

// R5-507 regression: CheckTxInputs must return Invalid (not crash) on spent coin.
BOOST_AUTO_TEST_CASE(checktxinputs_rejects_spent_coin_gracefully)
{
    CMutableTransaction mtx;
    const COutPoint prevout{Txid::FromUint256(GetRandHash()), 0};
    mtx.vin.emplace_back(prevout);
    mtx.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);

    // Use empty CCoinsViewCache — prevout won't be found, simulating spent coin.
    CCoinsView view;
    CCoinsViewCache cache(&view);
    // Do NOT add the coin — AccessCoin will return a spent sentinel.

    CAmount fee{0};
    TxValidationState state;
    // Previously this would assert(!coin.IsSpent()) and crash.
    // After R5-507 fix, it should gracefully return false with proper error.
    BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, /*nSpendHeight=*/2, fee));
    BOOST_CHECK(!state.IsValid());
}

// R5-501 regression: CheckTxInputs must handle overflow without UB.
BOOST_AUTO_TEST_CASE(checktxinputs_rejects_overflow_input_values)
{
    CMutableTransaction mtx;
    // Create two inputs with values that would overflow when summed
    const COutPoint prevout1{Txid::FromUint256(GetRandHash()), 0};
    const COutPoint prevout2{Txid::FromUint256(GetRandHash()), 0};
    mtx.vin.emplace_back(prevout1);
    mtx.vin.emplace_back(prevout2);
    mtx.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);

    CCoinsView view;
    CCoinsViewCache cache(&view);
    // MAX_MONEY + MAX_MONEY would overflow int64_t
    cache.AddCoin(prevout1, Coin{CTxOut{MAX_MONEY, CScript{} << OP_TRUE}, 1, false}, false);
    cache.AddCoin(prevout2, Coin{CTxOut{MAX_MONEY, CScript{} << OP_TRUE}, 1, false}, false);

    CAmount fee{0};
    TxValidationState state;
    BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 2, fee));
    BOOST_CHECK(!state.IsValid());
}

// R6-320: value_balance boundary values must not cause UB in fee calculation.
BOOST_AUTO_TEST_CASE(checktxinputs_rejects_extreme_value_balance)
{
    // Test INT64_MAX value_balance — should be rejected by MoneyRange check.
    {
        CMutableTransaction mtx;
        mtx.shielded_bundle.value_balance = std::numeric_limits<int64_t>::max();
        CShieldedInput in;
        in.nullifier = GetRandHash();
        for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
            in.ring_positions.push_back(i);
        }
        mtx.shielded_bundle.shielded_inputs.push_back(in);
        mtx.shielded_bundle.proof = {0x01};
        CShieldedOutput out;
        out.note_commitment = GetRandHash();
        out.merkle_anchor = GetRandHash();
        mtx.shielded_bundle.shielded_outputs.push_back(out);
        mtx.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);

        CCoinsView view;
        CCoinsViewCache cache(&view);
        CAmount fee{0};
        TxValidationState state;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 1, fee));
    }

    // Test INT64_MIN value_balance — should also be rejected.
    {
        CMutableTransaction mtx;
        mtx.shielded_bundle.value_balance = std::numeric_limits<int64_t>::min();
        CShieldedInput in;
        in.nullifier = GetRandHash();
        for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
            in.ring_positions.push_back(i);
        }
        mtx.shielded_bundle.shielded_inputs.push_back(in);
        mtx.shielded_bundle.proof = {0x01};
        CShieldedOutput out;
        out.note_commitment = GetRandHash();
        out.merkle_anchor = GetRandHash();
        mtx.shielded_bundle.shielded_outputs.push_back(out);

        CCoinsView view;
        CCoinsViewCache cache(&view);
        CAmount fee{0};
        TxValidationState state;
        BOOST_CHECK(!Consensus::CheckTxInputs(CTransaction(mtx), state, cache, 1, fee));
    }
}

BOOST_AUTO_TEST_SUITE_END()
