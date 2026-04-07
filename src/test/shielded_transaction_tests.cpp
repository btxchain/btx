// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <kernel/mempool_options.h>
#include <policy/policy.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/ml_kem.h>
#include <shielded/lattice/params.h>
#include <shielded/view_grant.h>
#include <shielded/v2_bundle.h>
#include <streams.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_smile_test_util.h>
#include <test/util/shielded_v2_egress_fixture.h>

#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <stdexcept>

namespace {

smile2::CompactPublicAccount MakeSmileAccount(uint32_t seed)
{
    return test::shielded::MakeDeterministicCompactPublicAccount(seed);
}

CMutableTransaction BuildBaseTx()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0), CScript{});
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    return mtx;
}

CMutableTransaction BuildStandardBaseTx()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256{2}), 0), CScript{});
    std::vector<unsigned char> witness_program(32, 0x42);
    mtx.vout.emplace_back(1000, CScript{} << OP_2 << witness_program);
    return mtx;
}

CShieldedBundle BuildNonEmptyBundle()
{
    CShieldedBundle bundle;

    CShieldedInput in;
    in.nullifier = uint256{2};
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        in.ring_positions.push_back(i);
    }
    bundle.shielded_inputs.push_back(in);

    CShieldedOutput out;
    out.note_commitment = uint256{3};
    out.merkle_anchor = uint256{4};
    out.encrypted_note.aead_nonce.fill(0xAB);
    out.encrypted_note.aead_ciphertext = {0x01, 0x02, 0x03};
    out.encrypted_note.view_tag = 0x11;
    bundle.shielded_outputs.push_back(out);

    bundle.proof = {0xC1, 0xC2, 0xC3};
    bundle.value_balance = -1000;
    return bundle;
}

CShieldedBundle BuildNonEmptyV2Bundle()
{
    using namespace shielded::v2;

    const auto spend_account = MakeSmileAccount(0x60);
    const uint256 spend_note_commitment = uint256{0x63};
    const auto registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(spend_note_commitment, spend_account);
    BOOST_REQUIRE(registry_witness.has_value());

    EncryptedNotePayload encrypted_note;
    encrypted_note.scan_domain = ScanDomain::USER;
    encrypted_note.scan_hint.fill(0x42);
    encrypted_note.ciphertext = {0x01, 0x02, 0x03, 0x04};
    encrypted_note.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{encrypted_note.ciphertext.data(), encrypted_note.ciphertext.size()});

    SpendDescription spend;
    spend.nullifier = uint256{0x61};
    spend.merkle_anchor = uint256{0x62};
    spend.account_leaf_commitment = registry_witness->second.account_leaf_commitment;
    spend.account_registry_proof = registry_witness->second;
    spend.note_commitment = spend_note_commitment;
    spend.value_commitment = uint256{0x64};

    OutputDescription output;
    output.note_class = NoteClass::USER;
    output.smile_account = MakeSmileAccount(0x65);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin);
    output.encrypted_note = encrypted_note;

    SendPayload payload;
    payload.spend_anchor = uint256{0x67};
    payload.account_registry_anchor = registry_witness->first;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = 5;
    payload.value_balance = payload.fee;

    ProofEnvelope envelope;
    envelope.proof_kind = ProofKind::DIRECT_SMILE;
    envelope.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    envelope.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    envelope.statement_digest = uint256{0x68};

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = TransactionFamily::V2_SEND;
    tx_bundle.header.proof_envelope = envelope;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    tx_bundle.payload = payload;
    tx_bundle.proof_payload = {0x11, 0x22, 0x33};

    CShieldedBundle bundle;
    bundle.v2_bundle = tx_bundle;
    return bundle;
}

CShieldedBundle BuildLargeV2EgressBundle(const size_t output_count)
{
    return test::shielded::BuildV2EgressReceiptFixture(output_count).tx.shielded_bundle;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(shielded_bundle_roundtrip)
{
    CMutableTransaction mtx = BuildBaseTx();
    mtx.shielded_bundle = BuildNonEmptyBundle();

    DataStream ss{};
    ss << TX_WITH_WITNESS(mtx);

    CMutableTransaction decoded;
    ss >> TX_WITH_WITNESS(decoded);

    BOOST_CHECK(decoded.HasShieldedBundle());
    BOOST_CHECK_EQUAL(decoded.shielded_bundle.shielded_inputs.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.shielded_bundle.shielded_outputs.size(), 1U);
    BOOST_CHECK(decoded.shielded_bundle.shielded_inputs[0].ring_positions ==
                mtx.shielded_bundle.shielded_inputs[0].ring_positions);
    BOOST_CHECK(decoded.shielded_bundle.proof == mtx.shielded_bundle.proof);
    BOOST_CHECK_EQUAL(decoded.shielded_bundle.value_balance, -1000);
}

BOOST_AUTO_TEST_CASE(txid_and_wtxid_commit_to_shielded_bundle)
{
    CMutableTransaction base = BuildBaseTx();
    CMutableTransaction with_bundle = base;
    with_bundle.shielded_bundle = BuildNonEmptyBundle();

    const CTransaction tx_base(base);
    const CTransaction tx_bundle(with_bundle);

    BOOST_CHECK(!tx_base.HasShieldedBundle());
    BOOST_CHECK(tx_bundle.HasShieldedBundle());

    BOOST_CHECK(tx_base.GetHash() != tx_bundle.GetHash());
    BOOST_CHECK(tx_base.GetWitnessHash() != tx_bundle.GetWitnessHash());
    BOOST_CHECK(tx_bundle.GetHash().ToUint256() == tx_bundle.GetWitnessHash().ToUint256());
}

BOOST_AUTO_TEST_CASE(v2_bundle_roundtrip)
{
    CMutableTransaction mtx = BuildBaseTx();
    mtx.shielded_bundle = BuildNonEmptyV2Bundle();

    DataStream ss{};
    ss << TX_WITH_WITNESS(mtx);

    CMutableTransaction decoded;
    ss >> TX_WITH_WITNESS(decoded);

    BOOST_REQUIRE(decoded.HasShieldedBundle());
    BOOST_REQUIRE(decoded.shielded_bundle.HasV2Bundle());
    BOOST_CHECK(!decoded.shielded_bundle.HasLegacyDirectSpendData());
    BOOST_CHECK_EQUAL(decoded.shielded_bundle.GetShieldedInputCount(), 1U);
    BOOST_CHECK_EQUAL(decoded.shielded_bundle.GetShieldedOutputCount(), 1U);
    BOOST_CHECK_EQUAL(decoded.shielded_bundle.GetProofSize(), 3U);
    BOOST_REQUIRE(decoded.shielded_bundle.GetTransactionFamily().has_value());
    BOOST_CHECK_EQUAL(*decoded.shielded_bundle.GetTransactionFamily(), shielded::v2::TransactionFamily::V2_SEND);
    BOOST_CHECK(decoded.shielded_bundle.GetV2Bundle()->IsValid());
}

BOOST_AUTO_TEST_CASE(legacy_shielded_outputs_do_not_create_account_registry_leaves)
{
    const CShieldedBundle bundle = BuildNonEmptyBundle();

    BOOST_REQUIRE_EQUAL(bundle.GetShieldedOutputCount(), 1U);
    const auto account_leaf_commitments = CollectShieldedOutputAccountLeafCommitments(bundle);
    BOOST_REQUIRE(account_leaf_commitments.has_value());
    BOOST_CHECK(account_leaf_commitments->empty());
}

BOOST_AUTO_TEST_CASE(txid_and_wtxid_commit_to_v2_bundle)
{
    CMutableTransaction base = BuildBaseTx();
    CMutableTransaction with_bundle = base;
    with_bundle.shielded_bundle = BuildNonEmptyV2Bundle();

    const CTransaction tx_base(base);
    const CTransaction tx_bundle(with_bundle);

    BOOST_CHECK(tx_base.GetHash() != tx_bundle.GetHash());
    BOOST_CHECK(tx_base.GetWitnessHash() != tx_bundle.GetWitnessHash());

    CMutableTransaction different = with_bundle;
    different.shielded_bundle.v2_bundle->proof_payload[0] ^= 0x01;
    const CTransaction tx_different(different);
    BOOST_CHECK(tx_different.GetHash() != tx_bundle.GetHash());
    BOOST_CHECK(tx_different.GetWitnessHash() != tx_bundle.GetWitnessHash());
}

BOOST_AUTO_TEST_CASE(v2_egress_standardness_tracks_scan_pressure)
{
    constexpr size_t output_count{150};
    CMutableTransaction mtx = BuildStandardBaseTx();
    mtx.shielded_bundle = BuildLargeV2EgressBundle(output_count);
    const CTransaction tx{mtx};

    const auto usage = GetShieldedResourceUsage(tx.GetShieldedBundle());
    BOOST_CHECK_GT(usage.scan_units, output_count);
    BOOST_CHECK_GT(GetShieldedPolicyWeight(tx), MAX_STANDARD_TX_WEIGHT);
    BOOST_CHECK_LE(GetShieldedPolicyWeight(tx), MAX_STANDARD_SHIELDED_POLICY_WEIGHT);

    kernel::MemPoolOptions opts;
    std::string reason;
    BOOST_CHECK(IsStandardTx(tx, opts, reason));
    BOOST_CHECK(reason.empty());
}

BOOST_AUTO_TEST_CASE(v2_settlement_anchor_without_transparent_outputs_is_standard)
{
    const auto fixture = test::shielded::BuildV2SettlementAnchorClaimFixture();
    const CTransaction tx{fixture.tx};

    kernel::MemPoolOptions opts;
    std::string reason;
    BOOST_CHECK(IsStandardTx(tx, opts, reason));
    BOOST_CHECK(reason.empty());
}

BOOST_AUTO_TEST_CASE(shielded_bundle_is_nonwitness_weight)
{
    CMutableTransaction with_bundle = BuildBaseTx();
    with_bundle.shielded_bundle = BuildNonEmptyBundle();
    const CTransaction tx_bundle(with_bundle);

    const int64_t non_witness_size = ::GetSerializeSize(TX_NO_WITNESS_WITH_SHIELDED(tx_bundle));
    const int64_t full_size = ::GetSerializeSize(TX_WITH_WITNESS(tx_bundle));

    BOOST_CHECK_EQUAL(non_witness_size, full_size);
    BOOST_CHECK_EQUAL(GetTransactionWeight(tx_bundle), full_size * WITNESS_SCALE_FACTOR);
}

BOOST_AUTO_TEST_CASE(tx_no_witness_with_shielded_retains_bundle_bytes)
{
    CMutableTransaction with_bundle = BuildBaseTx();
    with_bundle.shielded_bundle = BuildNonEmptyBundle();
    const CTransaction tx_bundle(with_bundle);

    BOOST_CHECK(::GetSerializeSize(TX_NO_WITNESS_WITH_SHIELDED(tx_bundle)) >
                ::GetSerializeSize(TX_NO_WITNESS(tx_bundle)));

    DataStream ss{};
    ss << TX_NO_WITNESS_WITH_SHIELDED(tx_bundle);

    CMutableTransaction decoded_with_shielded;
    ss >> TX_NO_WITNESS_WITH_SHIELDED(decoded_with_shielded);
    BOOST_CHECK(decoded_with_shielded.HasShieldedBundle());

    DataStream legacy_ss{};
    legacy_ss << TX_NO_WITNESS_WITH_SHIELDED(tx_bundle);
    CMutableTransaction decoded_legacy;
    legacy_ss >> TX_NO_WITNESS(decoded_legacy);
    BOOST_CHECK(!decoded_legacy.HasShieldedBundle());
    BOOST_CHECK(!legacy_ss.empty());
}

BOOST_AUTO_TEST_CASE(superfluous_empty_shielded_bundle_rejected)
{
    DataStream ss{};

    const uint32_t version = CTransaction::CURRENT_VERSION;
    const unsigned char flags = 2;
    const uint32_t locktime = 0;

    std::vector<CTxIn> empty_vin;
    std::vector<CTxOut> empty_vout;
    CShieldedBundle empty_bundle;

    ss << version;
    ss << empty_vin; // dummy
    ss << flags;
    ss << empty_vin;
    ss << empty_vout;
    ss << empty_bundle;
    ss << locktime;

    CMutableTransaction decoded;
    BOOST_CHECK_THROW(ss >> TX_WITH_WITNESS(decoded), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(mixed_legacy_and_v2_bundle_not_serializable)
{
    CShieldedBundle bundle = BuildNonEmptyBundle();
    bundle.v2_bundle = *BuildNonEmptyV2Bundle().GetV2Bundle();

    DataStream ss{};
    BOOST_CHECK_THROW(ss << bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(nonempty_legacy_output_range_proof_not_serializable)
{
    CMutableTransaction mtx = BuildBaseTx();
    mtx.shielded_bundle = BuildNonEmptyBundle();
    mtx.shielded_bundle.shielded_outputs[0].range_proof = {0xAA};

    DataStream ss{};
    BOOST_CHECK_THROW(ss << TX_WITH_WITNESS(mtx), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_nonempty_legacy_output_range_proof)
{
    CShieldedOutput out;
    out.note_commitment = uint256{3};
    out.merkle_anchor = uint256{4};

    DataStream ss{};
    ss << out.note_commitment;
    ss << out.encrypted_note;
    WriteCompactSize(ss, static_cast<uint64_t>(1));
    ss << static_cast<uint8_t>(0xCC);
    ss << out.merkle_anchor;

    CShieldedOutput decoded;
    BOOST_CHECK_THROW(ss >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(view_grant_encrypted_data_bounded_in_serializer)
{
    CViewGrant grant;
    grant.kem_ct.fill(0x11);
    grant.nonce.fill(0x22);
    grant.encrypted_data.resize(MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE + 1, 0x33);

    DataStream ss{};
    BOOST_CHECK_THROW(ss << grant, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_bundle_serialize_rejects_oversized_inputs)
{
    CShieldedBundle bundle;
    bundle.shielded_inputs.resize(MAX_SHIELDED_SPENDS_PER_TX + 1);

    DataStream ss{};
    BOOST_CHECK_THROW(ss << bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_bundle_serialize_rejects_oversized_outputs)
{
    CShieldedBundle bundle;
    bundle.shielded_outputs.resize(MAX_SHIELDED_OUTPUTS_PER_TX + 1);

    DataStream ss{};
    BOOST_CHECK_THROW(ss << bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_bundle_serialize_rejects_oversized_view_grants)
{
    CShieldedBundle bundle;
    bundle.view_grants.resize(MAX_VIEW_GRANTS_PER_TX + 1);

    DataStream ss{};
    BOOST_CHECK_THROW(ss << bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_bundle_serialize_rejects_oversized_proof)
{
    CShieldedBundle bundle;
    bundle.proof.resize(MAX_SHIELDED_PROOF_BYTES + 1, 0x42);

    DataStream ss{};
    BOOST_CHECK_THROW(ss << bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_bundle_unserialize_rejects_oversized_inputs)
{
    DataStream ss{};
    WriteCompactSize(ss, static_cast<uint64_t>(CShieldedBundle::SERIALIZED_V2_BUNDLE_TAG + 1));

    CShieldedBundle bundle;
    BOOST_CHECK_THROW(ss >> bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_input_serialize_rejects_oversized_ring_positions)
{
    CShieldedInput input;
    input.nullifier = uint256{1};
    input.ring_positions.resize(shielded::lattice::MAX_RING_SIZE + 1, 0);

    DataStream ss{};
    BOOST_CHECK_THROW(ss << input, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_input_unserialize_rejects_oversized_ring_positions)
{
    CShieldedInput input;
    DataStream ss{};
    ss << uint256{1};
    WriteCompactSize(ss, static_cast<uint64_t>(shielded::lattice::MAX_RING_SIZE + 1));

    BOOST_CHECK_THROW(ss >> input, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_bundle_unserialize_rejects_oversized_outputs)
{
    DataStream ss{};
    WriteCompactSize(ss, static_cast<uint64_t>(0));
    WriteCompactSize(ss, static_cast<uint64_t>(MAX_SHIELDED_OUTPUTS_PER_TX + 1));

    CShieldedBundle bundle;
    BOOST_CHECK_THROW(ss >> bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_bundle_unserialize_rejects_oversized_view_grants)
{
    DataStream ss{};
    WriteCompactSize(ss, static_cast<uint64_t>(0));
    WriteCompactSize(ss, static_cast<uint64_t>(0));
    WriteCompactSize(ss, static_cast<uint64_t>(MAX_VIEW_GRANTS_PER_TX + 1));

    CShieldedBundle bundle;
    BOOST_CHECK_THROW(ss >> bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(shielded_bundle_unserialize_rejects_oversized_proof)
{
    DataStream ss{};
    WriteCompactSize(ss, static_cast<uint64_t>(0));
    WriteCompactSize(ss, static_cast<uint64_t>(0));
    WriteCompactSize(ss, static_cast<uint64_t>(0));
    WriteCompactSize(ss, static_cast<uint64_t>(MAX_SHIELDED_PROOF_BYTES + 1));

    CShieldedBundle bundle;
    BOOST_CHECK_THROW(ss >> bundle, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(view_grant_roundtrip_encrypt_decrypt)
{
    const auto keypair = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32);
    for (size_t i = 0; i < view_key.size(); ++i) {
        view_key[i] = static_cast<uint8_t>(0x40 + i);
    }

    const CViewGrant grant = CViewGrant::Create(view_key, keypair.pk);
    const auto decrypted = grant.Decrypt(keypair.sk);
    BOOST_REQUIRE(decrypted.has_value());
    BOOST_CHECK_EQUAL_COLLECTIONS(decrypted->begin(), decrypted->end(), view_key.begin(), view_key.end());
}

BOOST_AUTO_TEST_CASE(view_grant_create_rejects_oversized_view_key)
{
    const auto keypair = mlkem::KeyGen();
    const size_t oversized_key_len = MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE - AEADChaCha20Poly1305::EXPANSION + 1;
    std::vector<uint8_t> oversized_view_key(oversized_key_len, 0xAA);
    BOOST_CHECK_THROW((void)CViewGrant::Create(oversized_view_key, keypair.pk), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(view_grant_create_accepts_max_sized_view_key)
{
    const auto keypair = mlkem::KeyGen();
    const size_t max_key_len = MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE - AEADChaCha20Poly1305::EXPANSION;
    std::vector<uint8_t> max_sized_view_key(max_key_len, 0x5A);
    const CViewGrant grant = CViewGrant::Create(max_sized_view_key, keypair.pk);
    BOOST_CHECK_EQUAL(grant.encrypted_data.size(), MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE);
    const auto decrypted = grant.Decrypt(keypair.sk);
    BOOST_REQUIRE(decrypted.has_value());
    BOOST_CHECK_EQUAL_COLLECTIONS(decrypted->begin(), decrypted->end(),
                                  max_sized_view_key.begin(), max_sized_view_key.end());
}

BOOST_AUTO_TEST_CASE(structured_view_grant_payload_roundtrip)
{
    shielded::viewgrants::StructuredDisclosurePayload payload;
    payload.disclosure_flags = static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                                    shielded::viewgrants::DISCLOSE_RECIPIENT |
                                                    shielded::viewgrants::DISCLOSE_MEMO |
                                                    shielded::viewgrants::DISCLOSE_SENDER);
    payload.amount = 5 * COIN;
    payload.recipient_pk_hash = uint256{0x91};
    payload.memo = {'a', 'u', 'd', 'i', 't'};
    payload.sender.bridge_id = uint256{0x92};
    payload.sender.operation_id = uint256{0x93};

    const auto bytes = shielded::viewgrants::SerializeStructuredDisclosurePayload(payload);
    BOOST_REQUIRE(!bytes.empty());

    const auto decoded = shielded::viewgrants::DecodeStructuredDisclosurePayload(
        Span<const uint8_t>{bytes.data(), bytes.size()});
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->disclosure_flags, payload.disclosure_flags);
    BOOST_CHECK_EQUAL(decoded->amount, payload.amount);
    BOOST_CHECK(decoded->recipient_pk_hash == payload.recipient_pk_hash);
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded->memo.begin(), decoded->memo.end(),
                                  payload.memo.begin(), payload.memo.end());
    BOOST_CHECK(decoded->sender.bridge_id == payload.sender.bridge_id);
    BOOST_CHECK(decoded->sender.operation_id == payload.sender.operation_id);
}

BOOST_AUTO_TEST_CASE(structured_view_grant_payload_rejects_invalid_flags)
{
    shielded::viewgrants::StructuredDisclosurePayload payload;
    BOOST_CHECK(!payload.IsValid());
    BOOST_CHECK(shielded::viewgrants::SerializeStructuredDisclosurePayload(payload).empty());
}

BOOST_AUTO_TEST_CASE(view_grant_roundtrip_encrypt_decrypt_structured_payload)
{
    const auto keypair = mlkem::KeyGen();
    shielded::viewgrants::StructuredDisclosurePayload payload;
    payload.disclosure_flags = static_cast<uint8_t>(shielded::viewgrants::DISCLOSE_AMOUNT |
                                                    shielded::viewgrants::DISCLOSE_RECIPIENT |
                                                    shielded::viewgrants::DISCLOSE_SENDER);
    payload.amount = 7 * COIN;
    payload.recipient_pk_hash = uint256{0x94};
    payload.sender.bridge_id = uint256{0x95};
    payload.sender.operation_id = uint256{0x96};

    const auto view_key = shielded::viewgrants::SerializeStructuredDisclosurePayload(payload);
    BOOST_REQUIRE(!view_key.empty());

    const CViewGrant grant = CViewGrant::Create(
        Span<const uint8_t>{view_key.data(), view_key.size()}, keypair.pk);
    const auto decrypted = grant.Decrypt(keypair.sk);
    BOOST_REQUIRE(decrypted.has_value());
    const auto decoded = shielded::viewgrants::DecodeStructuredDisclosurePayload(
        Span<const uint8_t>{decrypted->data(), decrypted->size()});
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->amount, payload.amount);
    BOOST_CHECK(decoded->recipient_pk_hash == payload.recipient_pk_hash);
    BOOST_CHECK(decoded->sender.bridge_id == payload.sender.bridge_id);
    BOOST_CHECK(decoded->sender.operation_id == payload.sender.operation_id);
}

BOOST_AUTO_TEST_CASE(view_grant_decrypt_rejects_oversized_runtime_payload)
{
    const auto keypair = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32);
    for (size_t i = 0; i < view_key.size(); ++i) {
        view_key[i] = static_cast<uint8_t>(0x70 + i);
    }

    CViewGrant grant = CViewGrant::Create(view_key, keypair.pk);
    grant.encrypted_data.resize(MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE + 1, 0x55);
    BOOST_CHECK(!grant.Decrypt(keypair.sk).has_value());
}

BOOST_AUTO_TEST_CASE(view_grant_decrypt_rejects_underflow_payload)
{
    const auto keypair = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32);
    for (size_t i = 0; i < view_key.size(); ++i) {
        view_key[i] = static_cast<uint8_t>(0x10 + i);
    }

    CViewGrant grant = CViewGrant::Create(view_key, keypair.pk);
    grant.encrypted_data.assign(AEADChaCha20Poly1305::EXPANSION - 1, 0x77);
    BOOST_CHECK(!grant.Decrypt(keypair.sk).has_value());
}

BOOST_AUTO_TEST_CASE(view_grant_decrypt_rejects_tampered_ciphertext)
{
    const auto keypair = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32);
    for (size_t i = 0; i < view_key.size(); ++i) {
        view_key[i] = static_cast<uint8_t>(0x20 + i);
    }

    CViewGrant grant = CViewGrant::Create(view_key, keypair.pk);
    BOOST_REQUIRE(!grant.encrypted_data.empty());
    grant.encrypted_data[0] ^= 0x01;
    BOOST_CHECK(!grant.Decrypt(keypair.sk).has_value());
}

BOOST_AUTO_TEST_CASE(view_grant_decrypt_rejects_wrong_secret_key)
{
    const auto owner = mlkem::KeyGen();
    const auto wrong = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32);
    for (size_t i = 0; i < view_key.size(); ++i) {
        view_key[i] = static_cast<uint8_t>(0x30 + i);
    }

    const CViewGrant grant = CViewGrant::Create(view_key, owner.pk);
    BOOST_CHECK(!grant.Decrypt(wrong.sk).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
