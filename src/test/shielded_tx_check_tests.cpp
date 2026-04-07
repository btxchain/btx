// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <crypto/chacha20poly1305.h>
#include <primitives/transaction.h>
#include <random.h>
#include <shielded/lattice/params.h>
#include <shielded/v2_bundle.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>
#include <test/util/shielded_v2_egress_fixture.h>

#include <boost/test/unit_test.hpp>

namespace {

CShieldedBundle BuildValidShieldedBundle()
{
    CShieldedBundle bundle;

    CShieldedInput in;
    in.nullifier = GetRandHash();
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        in.ring_positions.push_back(i);
    }
    bundle.shielded_inputs.push_back(in);
    bundle.proof = {0x01};

    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    out.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    bundle.shielded_outputs.push_back(out);

    bundle.value_balance = 0;
    return bundle;
}

CShieldedBundle BuildValidV2ShieldedBundle()
{
    using namespace shielded::v2;

    const auto spend_account = test::shielded::MakeDeterministicCompactPublicAccount(0x53);
    const uint256 spend_note_commitment = uint256{0x56};
    const auto registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(spend_note_commitment, spend_account);
    BOOST_REQUIRE(registry_witness.has_value());

    EncryptedNotePayload encrypted_note;
    encrypted_note.scan_domain = ScanDomain::USER;
    encrypted_note.scan_hint.fill(0x52);
    encrypted_note.ciphertext = {0x10, 0x11, 0x12};
    encrypted_note.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{encrypted_note.ciphertext.data(), encrypted_note.ciphertext.size()});

    SpendDescription spend;
    spend.nullifier = uint256{0x54};
    spend.merkle_anchor = uint256{0x55};
    spend.account_leaf_commitment = registry_witness->second.account_leaf_commitment;
    spend.account_registry_proof = registry_witness->second;
    spend.note_commitment = spend_note_commitment;
    spend.value_commitment = uint256{0x57};

    OutputDescription output;
    output.note_class = NoteClass::USER;
    output.smile_account = test::shielded::MakeDeterministicCompactPublicAccount(0x58);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin);
    output.encrypted_note = encrypted_note;

    SendPayload payload;
    payload.spend_anchor = uint256{0x5a};
    payload.account_registry_anchor = registry_witness->first;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = 1;
    payload.value_balance = payload.fee;

    ProofEnvelope envelope;
    envelope.proof_kind = ProofKind::DIRECT_SMILE;
    envelope.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    envelope.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    envelope.statement_digest = uint256{0x5b};

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = TransactionFamily::V2_SEND;
    tx_bundle.header.proof_envelope = envelope;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    tx_bundle.payload = payload;
    tx_bundle.proof_payload = {0x01, 0x02};

    CShieldedBundle bundle;
    bundle.v2_bundle = tx_bundle;
    return bundle;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_tx_check_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(checktransaction_accepts_fully_shielded_bundle)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_v2_bundle_for_contextual_validation)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidV2ShieldedBundle();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_v2_egress_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_hybrid_v2_egress_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2EgressHybridReceiptFixture();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_v2_settlement_anchor_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_receipt_adapter_backed_v2_settlement_anchor_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorAdapterReceiptFixture();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_hybrid_v2_settlement_anchor_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorHybridReceiptFixture();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_multi_receipt_hybrid_v2_settlement_anchor_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorHybridReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2);

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_multi_receipt_v2_settlement_anchor_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture(
        /*output_count=*/2,
        /*proof_receipt_count=*/2,
        /*required_receipts=*/2);

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_reserve_bound_v2_settlement_anchor_bundle_for_contextual_validation)
{
    auto fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    test::shielded::AttachSettlementAnchorReserveBinding(fixture.tx);

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_v2_rebalance_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2RebalanceFixture();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_fee_bearing_v2_rebalance_with_witness_roundtrip)
{
    auto fixture = test::shielded::BuildV2RebalanceFixture();
    fixture.tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{0xa6}), 0}, CScript{});
    fixture.tx.vout.emplace_back(10'000, CScript{} << OP_TRUE);
    fixture.tx.vin[0].scriptWitness.stack = {{0x30, 0x01}, {0x51}};

    DataStream stream;
    stream << TX_WITH_WITNESS(fixture.tx);

    CMutableTransaction decoded;
    stream >> TX_WITH_WITNESS(decoded);

    BOOST_REQUIRE(decoded.HasShieldedBundle());
    BOOST_REQUIRE(decoded.HasWitness());
    BOOST_REQUIRE(decoded.GetShieldedBundle().HasV2Bundle());
    BOOST_CHECK(decoded.GetShieldedBundle().CheckStructure());

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(decoded), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_claim_backed_v2_settlement_anchor_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorClaimFixture();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_adapter_backed_v2_settlement_anchor_bundle_for_contextual_validation)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorAdapterClaimFixture();

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(fixture.tx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_shielded_output_with_negative_value_balance)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(GetRandHash()), 0});

    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    out.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    mtx.shielded_bundle.shielded_outputs.push_back(out);
    mtx.shielded_bundle.value_balance = -1 * COIN;

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_unshield_without_shielded_spend)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(GetRandHash()), 0});
    mtx.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);
    mtx.shielded_bundle.value_balance = 1 * COIN;

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-shielded-bundle");
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_zero_balance_one_sided_bundle)
{
    CMutableTransaction inputs_only;
    inputs_only.vin.emplace_back(COutPoint{Txid::FromUint256(GetRandHash()), 0});
    inputs_only.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);
    CShieldedInput in;
    in.nullifier = GetRandHash();
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        in.ring_positions.push_back(i);
    }
    inputs_only.shielded_bundle.shielded_inputs.push_back(in);
    inputs_only.shielded_bundle.proof = {0x01};
    inputs_only.shielded_bundle.value_balance = 0;

    TxValidationState inputs_only_state;
    BOOST_CHECK(!CheckTransaction(CTransaction(inputs_only), inputs_only_state));
    BOOST_CHECK_EQUAL(inputs_only_state.GetRejectReason(), "bad-shielded-bundle");

    CMutableTransaction outputs_only;
    outputs_only.vin.emplace_back(COutPoint{Txid::FromUint256(GetRandHash()), 0});
    outputs_only.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);
    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    out.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    outputs_only.shielded_bundle.shielded_outputs.push_back(out);
    outputs_only.shielded_bundle.value_balance = 0;

    TxValidationState outputs_only_state;
    BOOST_CHECK(!CheckTransaction(CTransaction(outputs_only), outputs_only_state));
    BOOST_CHECK_EQUAL(outputs_only_state.GetRejectReason(), "bad-shielded-bundle");
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_duplicate_shielded_nullifier)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();

    CShieldedInput dup;
    dup.nullifier = mtx.shielded_bundle.shielded_inputs[0].nullifier;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        dup.ring_positions.push_back(i);
    }
    mtx.shielded_bundle.shielded_inputs.push_back(dup);

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    // Duplicate nullifier is now caught early in CheckStructure() (intra-bundle dedup).
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-shielded-bundle");
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_duplicate_note_commitment)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();

    CShieldedOutput dup = mtx.shielded_bundle.shielded_outputs[0];
    dup.merkle_anchor = GetRandHash();
    mtx.shielded_bundle.shielded_outputs.push_back(dup);

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-shielded-bundle");
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_underflow_encrypted_note_ciphertext)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();
    mtx.shielded_bundle.shielded_outputs[0].encrypted_note.aead_ciphertext.resize(
        AEADChaCha20Poly1305::EXPANSION - 1, 0x00);

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-shielded-bundle");
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_coinbase_with_shielded_bundle)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript{} << OP_1 << OP_1;
    mtx.vout.emplace_back(5000000000, CScript{} << OP_TRUE);
    mtx.shielded_bundle = BuildValidShieldedBundle();

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-shielded");
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_spend_without_bundle_proof)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();
    mtx.shielded_bundle.proof.clear();

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-shielded-bundle");
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_oversized_shielded_proof)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();
    mtx.shielded_bundle.proof.resize(MAX_SHIELDED_PROOF_BYTES + 1, 0xAB);

    BOOST_CHECK_THROW((void)CTransaction{mtx}, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_oversized_shielded_tx_weight)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(GetRandHash()), 0});
    const size_t oversized_script_size =
        static_cast<size_t>(MAX_SHIELDED_TX_WEIGHT / WITNESS_SCALE_FACTOR) + 4096;
    std::vector<unsigned char> oversized_script(oversized_script_size, 0x51);
    mtx.vin[0].scriptSig = CScript(oversized_script.begin(), oversized_script.end());
    mtx.shielded_bundle = BuildValidShieldedBundle();

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-shielded-oversize");
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_nonempty_legacy_output_range_proof)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();
    mtx.shielded_bundle.shielded_outputs[0].range_proof = {0x03};

    BOOST_CHECK_THROW((void)CTransaction{mtx}, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_oversized_view_grant_payload)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();

    CViewGrant view_grant;
    view_grant.kem_ct.fill(0x11);
    view_grant.nonce.fill(0x22);
    view_grant.encrypted_data.resize(MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE + 1, 0x33);
    mtx.shielded_bundle.view_grants.push_back(view_grant);

    BOOST_CHECK_THROW((void)CTransaction{mtx}, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_too_many_shielded_spends)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle.value_balance = 1;
    mtx.shielded_bundle.proof = {0x01};
    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    out.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    mtx.shielded_bundle.shielded_outputs.push_back(out);
    for (size_t i = 0; i <= MAX_SHIELDED_SPENDS_PER_TX; ++i) {
        CShieldedInput in;
        in.nullifier = GetRandHash();
        for (size_t j = 0; j < shielded::lattice::RING_SIZE; ++j) {
            in.ring_positions.push_back(j);
        }
        mtx.shielded_bundle.shielded_inputs.push_back(in);
    }

    BOOST_CHECK_THROW((void)CTransaction{mtx}, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_too_many_shielded_outputs)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(GetRandHash()), 0});
    mtx.shielded_bundle.value_balance = -1;
    for (size_t i = 0; i <= MAX_SHIELDED_OUTPUTS_PER_TX; ++i) {
        CShieldedOutput out;
        out.note_commitment = GetRandHash();
        out.merkle_anchor = GetRandHash();
        out.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
        mtx.shielded_bundle.shielded_outputs.push_back(out);
    }

    BOOST_CHECK_THROW((void)CTransaction{mtx}, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_zero_fee_shielded_tx)
{
    // A fully-shielded transaction where all value stays in the shielded pool
    // (fee == 0, value_balance == 0) must not crash and must be accepted by
    // CheckTransaction.  Policy-level fee enforcement happens later; the
    // consensus check should be clean.
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();
    // Explicitly set value_balance to 0 (no transparent value movement, zero fee).
    mtx.shielded_bundle.value_balance = 0;

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_zero_fee_shield_operation)
{
    // Shield operation: transparent input funds a shielded output.
    // value_balance < 0 means value enters the shielded pool.
    // With fee == 0 the entire transparent input goes to the shielded output.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(GetRandHash()), 0});

    CShieldedOutput out;
    out.note_commitment = GetRandHash();
    out.merkle_anchor = GetRandHash();
    out.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    mtx.shielded_bundle.shielded_outputs.push_back(out);
    // No proof needed for output-only (shielding) bundles — proof is for ring sig.

    // value_balance == -(shielded_output_sum), fee == 0 means
    // transparent_in == |value_balance| exactly.
    mtx.shielded_bundle.value_balance = -1 * COIN;

    TxValidationState state;
    bool ok = CheckTransaction(CTransaction(mtx), state);
    BOOST_CHECK_MESSAGE(ok, "CheckTransaction failed: " + state.GetRejectReason());
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(checktransaction_accepts_zero_fee_unshield_operation)
{
    // Unshield operation: shielded input funds a transparent output.
    // value_balance > 0 means value leaves the shielded pool.
    // With fee == 0 the entire value_balance goes to a transparent output.
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildValidShieldedBundle();
    mtx.shielded_bundle.value_balance = 1 * COIN;
    mtx.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
