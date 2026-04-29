// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/amount.h>
#include <chainparams.h>
#include <crypto/chacha20poly1305.h>
#include <hash.h>
#include <pqkey.h>
#include <random.h>
#include <shielded/account_registry.h>
#include <shielded/lattice/params.h>
#include <shielded/ringct/matrict.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/spend_auth.h>
#include <shielded/v2_proof.h>
#include <serialize.h>
#include <streams.h>
#include <test/shielded_spend_path_recovery_fixture_builder.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <map>
#include <string>
#include <vector>

namespace {

using namespace shielded::ringct;
namespace v2proof = shielded::v2::proof;

std::vector<std::vector<uint256>> BuildRingMembers(const CShieldedBundle& bundle)
{
    std::vector<std::vector<uint256>> ring_members;
    ring_members.reserve(bundle.shielded_inputs.size());
    for (const auto& spend : bundle.shielded_inputs) {
        std::vector<uint256> ring;
        ring.reserve(spend.ring_positions.size());
        for (const uint64_t pos : spend.ring_positions) {
            HashWriter hw;
            hw << std::string{"BTX_Shielded_RingMember_V1"};
            hw << pos;
            ring.push_back(hw.GetSHA256());
        }
        ring_members.push_back(std::move(ring));
    }
    return ring_members;
}

CShieldedBundle BuildProofBundle(CAmount value_balance = 0, const uint256& tx_binding_hash = uint256{})
{
    CShieldedBundle bundle;
    const std::vector<unsigned char> spending_key(32, 0x42);
    bundle.value_balance = value_balance;

    CShieldedInput spend;
    spend.ring_positions.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        spend.ring_positions.push_back(i);
    }

    ShieldedNote in_note;
    in_note.value = 5000;
    in_note.recipient_pk_hash = GetRandHash();
    in_note.rho = GetRandHash();
    in_note.rcm = GetRandHash();

    ShieldedNote out_note;
    out_note.value = 5000 - value_balance;
    out_note.recipient_pk_hash = GetRandHash();
    out_note.rho = GetRandHash();
    out_note.rcm = GetRandHash();

    CShieldedOutput out;
    out.note_commitment = out_note.GetCommitment();
    out.merkle_anchor = GetRandHash();
    out.encrypted_note.aead_ciphertext.assign(AEADChaCha20Poly1305::EXPANSION, 0x00);
    bundle.shielded_outputs.push_back(out);
    bundle.shielded_inputs.push_back(spend);

    std::vector<ShieldedNote> input_notes{in_note};
    std::vector<ShieldedNote> output_notes{out_note};

    const auto ring_members = BuildRingMembers(bundle);
    BOOST_REQUIRE(ring_members.size() == 1);
    BOOST_REQUIRE(ring_members[0].size() == shielded::lattice::RING_SIZE);
    BOOST_REQUIRE(DeriveInputNullifierForNote(bundle.shielded_inputs[0].nullifier,
                                              spending_key,
                                              in_note,
                                              ring_members[0][0]));
    std::vector<Nullifier> input_nullifiers;
    input_nullifiers.reserve(bundle.shielded_inputs.size());
    for (const auto& in : bundle.shielded_inputs) {
        input_nullifiers.push_back(in.nullifier);
    }
    const std::vector<size_t> real_indices{0};

    uint256 effective_binding_hash = tx_binding_hash;
    if (effective_binding_hash.IsNull()) {
        CMutableTransaction binding_tx;
        binding_tx.shielded_bundle = bundle;
        effective_binding_hash = shielded::ringct::ComputeMatRiCTBindingHash(binding_tx);
    }

    MatRiCTProof proof;
    const bool created = CreateMatRiCTProof(proof,
                                            input_notes,
                                            output_notes,
                                            input_nullifiers,
                                            ring_members,
                                            real_indices,
                                            spending_key,
                                            value_balance,
                                            effective_binding_hash);
    BOOST_REQUIRE(created);

    DataStream ds;
    ds << proof;
    const auto* begin = reinterpret_cast<const unsigned char*>(ds.data());
    bundle.proof.assign(begin, begin + ds.size());
    return bundle;
}

shielded::ShieldedMerkleTree BuildTree()
{
    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        HashWriter hw;
        hw << std::string{"BTX_Shielded_RingMember_V1"};
        hw << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }
    return tree;
}

std::vector<uint256> BuildRingMembersFromPositions(const shielded::ShieldedMerkleTree& tree,
                                                   const std::vector<uint64_t>& ring_positions)
{
    std::vector<uint256> ring_members;
    ring_members.reserve(ring_positions.size());
    for (const uint64_t pos : ring_positions) {
        const auto commitment = tree.CommitmentAt(pos);
        BOOST_REQUIRE(commitment.has_value());
        ring_members.push_back(*commitment);
    }
    return ring_members;
}

struct V2SendFixture {
    CMutableTransaction tx;
    shielded::ShieldedMerkleTree tree;
};

struct SmileV2SendFixture {
    CMutableTransaction tx;
    shielded::ShieldedMerkleTree tree;
    std::map<uint256, smile2::CompactPublicAccount> public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    std::vector<uint256> serial_hashes;
    size_t real_index{0};
};

struct SpendPathRecoveryFixture {
    CMutableTransaction tx;
    shielded::ShieldedMerkleTree tree;
    uint256 input_note_commitment;
};

[[maybe_unused]] V2SendFixture BuildV2SendFixture(CAmount fee = 0)
{
    using namespace shielded::v2;

    V2SendFixture fixture;
    fixture.tree = BuildTree();

    const std::vector<unsigned char> spending_key(32, 0x42);
    const std::vector<uint64_t> ring_positions = [] {
        std::vector<uint64_t> positions;
        positions.reserve(shielded::lattice::RING_SIZE);
        for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
            positions.push_back(i);
        }
        return positions;
    }();
    const std::vector<std::vector<uint256>> ring_members{
        BuildRingMembersFromPositions(fixture.tree, ring_positions)};

    ShieldedNote in_note;
    in_note.value = 5000;
    in_note.recipient_pk_hash = GetRandHash();
    in_note.rho = GetRandHash();
    in_note.rcm = GetRandHash();

    ShieldedNote out_note;
    out_note.value = 5000 - fee;
    out_note.recipient_pk_hash = GetRandHash();
    out_note.rho = GetRandHash();
    out_note.rcm = GetRandHash();

    shielded::v2::SpendDescription spend;
    BOOST_REQUIRE(DeriveInputNullifierForNote(spend.nullifier,
                                              spending_key,
                                              in_note,
                                              ring_members[0][0]));
    spend.merkle_anchor = fixture.tree.Root();
    const auto account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
        in_note,
        ring_members[0][0],
        shielded::registry::MakeDirectSendAccountLeafHint());
    BOOST_REQUIRE(account_leaf_commitment.has_value());
    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        in_note);
    BOOST_REQUIRE(input_account.has_value());
    const auto account_registry_witness = test::shielded::MakeSingleLeafRegistryWitness(
        ring_members[0][0],
        *input_account);
    BOOST_REQUIRE(account_registry_witness.has_value());
    spend.account_leaf_commitment = *account_leaf_commitment;
    spend.account_registry_proof = account_registry_witness->second;

    shielded::v2::OutputDescription output;
    output.note_class = shielded::v2::NoteClass::USER;
    output.smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        out_note);
    BOOST_REQUIRE(output.smile_account.has_value());
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.encrypted_note.scan_domain = shielded::v2::ScanDomain::USER;
    output.encrypted_note.scan_hint.fill(0x31);
    output.encrypted_note.ciphertext = {0x51, 0x52, 0x53};
    output.encrypted_note.ephemeral_key = shielded::v2::ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{output.encrypted_note.ciphertext.data(), output.encrypted_note.ciphertext.size()});

    shielded::v2::SendPayload payload;
    payload.spend_anchor = fixture.tree.Root();
    payload.account_registry_anchor = account_registry_witness->first;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = fee;
    payload.value_balance = payload.fee;

    shielded::v2::TransactionBundle tx_bundle;
    tx_bundle.header.family_id = shielded::v2::TransactionFamily::V2_SEND;
    tx_bundle.header.proof_envelope.proof_kind = shielded::v2::ProofKind::DIRECT_MATRICT;
    tx_bundle.header.proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::MATRICT;
    tx_bundle.header.proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::RANGE;
    tx_bundle.header.proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::BALANCE;
    tx_bundle.header.proof_envelope.settlement_binding_kind = shielded::v2::SettlementBindingKind::NONE;
    tx_bundle.header.proof_envelope.statement_digest = uint256{0x01};
    tx_bundle.payload = payload;
    tx_bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    fixture.tx.shielded_bundle.v2_bundle = tx_bundle;

    std::vector<Nullifier> input_nullifiers{spend.nullifier};
    const std::vector<uint256> output_note_commitments{output.note_commitment};
    const std::vector<size_t> real_indices{0};

    const uint256 provisional_digest = v2proof::ComputeV2SendStatementDigest(CTransaction{fixture.tx});
    MatRiCTProof provisional_proof;
    BOOST_REQUIRE(CreateMatRiCTProof(provisional_proof,
                                     {in_note},
                                     {out_note},
                                     Span<const uint256>{output_note_commitments.data(),
                                                         output_note_commitments.size()},
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     fee,
                                     provisional_digest));

    spend.value_commitment = CommitmentHash(provisional_proof.input_commitments[0]);
    output.value_commitment = CommitmentHash(provisional_proof.output_commitments[0]);
    payload.spends = {spend};
    payload.outputs = {output};

    tx_bundle.payload = payload;
    tx_bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    fixture.tx.shielded_bundle.v2_bundle = tx_bundle;

    const uint256 statement_digest = v2proof::ComputeV2SendStatementDigest(CTransaction{fixture.tx});
    MatRiCTProof proof;
    BOOST_REQUIRE(CreateMatRiCTProof(proof,
                                     {in_note},
                                     {out_note},
                                     Span<const uint256>{output_note_commitments.data(),
                                                         output_note_commitments.size()},
                                     input_nullifiers,
                                     ring_members,
                                     real_indices,
                                     spending_key,
                                     fee,
                                     statement_digest));

    shielded::v2::proof::V2SendWitness witness;
    shielded::v2::proof::V2SendSpendWitness spend_witness;
    spend_witness.real_index = 0;
    spend_witness.ring_positions = ring_positions;
    witness.spends = {spend_witness};
    witness.native_proof = proof;

    DataStream witness_stream;
    witness_stream << witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    tx_bundle.header.proof_envelope.statement_digest = statement_digest;
    tx_bundle.proof_payload.assign(witness_begin, witness_begin + witness_stream.size());
    tx_bundle.payload = payload;
    tx_bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    fixture.tx.shielded_bundle.v2_bundle = tx_bundle;
    return fixture;
}

SmileV2SendFixture BuildSmileV2SendFixture(unsigned char seed_base = 0x61)
{
    using namespace shielded::v2;

    SmileV2SendFixture fixture;
    const size_t real_index = 3;
    fixture.real_index = real_index;
    const std::vector<uint64_t> ring_positions = [] {
        std::vector<uint64_t> positions;
        positions.reserve(shielded::lattice::RING_SIZE);
        for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
            positions.push_back(i);
        }
        return positions;
    }();

    ShieldedNote in_note;
    in_note.value = 5000;
    in_note.recipient_pk_hash = uint256{seed_base};
    in_note.rho = uint256{static_cast<unsigned char>(seed_base + 1)};
    in_note.rcm = uint256{static_cast<unsigned char>(seed_base + 2)};

    ShieldedNote out_note;
    out_note.value = 5000;
    out_note.recipient_pk_hash = uint256{static_cast<unsigned char>(seed_base + 3)};
    out_note.rho = uint256{static_cast<unsigned char>(seed_base + 4)};
    out_note.rcm = uint256{static_cast<unsigned char>(seed_base + 5)};

    std::vector<smile2::wallet::SmileRingMember> ring_members;
    ring_members.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        ShieldedNote ring_note;
        if (i == real_index) {
            ring_note = in_note;
        } else {
            ring_note.value = 4000 + static_cast<CAmount>(i);
            ring_note.recipient_pk_hash = uint256{static_cast<unsigned char>(0x80 + i)};
            ring_note.rho = uint256{static_cast<unsigned char>(0x90 + i)};
            ring_note.rcm = uint256{static_cast<unsigned char>(0xa0 + i)};
        }

        auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            ring_note);
        BOOST_REQUIRE(account.has_value());
        const uint256 ring_commitment = smile2::ComputeCompactPublicAccountHash(*account);
        const auto account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
            ring_note,
            ring_commitment,
            shielded::registry::MakeDirectSendAccountLeafHint());
        BOOST_REQUIRE(account_leaf_commitment.has_value());

        fixture.tree.Append(ring_commitment);
        fixture.public_accounts.emplace(ring_commitment, *account);
        fixture.account_leaf_commitments.emplace(ring_commitment, *account_leaf_commitment);

        std::optional<smile2::wallet::SmileRingMember> member;
        if (i == real_index) {
            member = smile2::wallet::BuildRingMemberFromNote(
                smile2::wallet::SMILE_GLOBAL_SEED,
                ring_note,
                ring_commitment,
                *account_leaf_commitment);
        } else {
            member = smile2::wallet::BuildRingMemberFromCompactPublicAccount(
                smile2::wallet::SMILE_GLOBAL_SEED,
                ring_commitment,
                *account,
                *account_leaf_commitment);
        }
        BOOST_REQUIRE(member.has_value());
        ring_members.push_back(std::move(*member));
    }

    smile2::wallet::SmileInputMaterial smile_input;
    smile_input.note = in_note;
    smile_input.note_commitment = ring_members[real_index].note_commitment;
    smile_input.account_leaf_commitment = ring_members[real_index].account_leaf_commitment;
    smile_input.ring_index = real_index;

    const std::vector<uint8_t> entropy(32, static_cast<unsigned char>(seed_base + 6));
    auto smile_result = smile2::wallet::CreateSmileProof(smile2::wallet::SMILE_GLOBAL_SEED,
                                                         {smile_input},
                                                         {out_note},
                                                         Span<const smile2::wallet::SmileRingMember>{
                                                             ring_members.data(), ring_members.size()},
                                                         Span<const uint8_t>(entropy),
                                                         fixture.serial_hashes);
    BOOST_REQUIRE(smile_result.has_value());
    BOOST_REQUIRE_EQUAL(fixture.serial_hashes.size(), 1U);

    SpendDescription spend;
    spend.nullifier = fixture.serial_hashes[0];
    spend.merkle_anchor = fixture.tree.Root();
    spend.account_leaf_commitment = ring_members[real_index].account_leaf_commitment;
    const auto account_registry_witness = test::shielded::MakeSingleLeafRegistryWitness(
        ring_members[real_index].note_commitment,
        fixture.public_accounts.at(ring_members[real_index].note_commitment));
    BOOST_REQUIRE(account_registry_witness.has_value());
    spend.account_registry_proof = account_registry_witness->second;
    spend.value_commitment = smile2::ComputeSmileDirectInputBindingHash(
        Span<const smile2::wallet::SmileRingMember>{ring_members.data(), ring_members.size()},
        fixture.tree.Root(),
        0,
        spend.nullifier);

    OutputDescription output;
    output.note_class = NoteClass::USER;
    output.smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        out_note);
    BOOST_REQUIRE(output.smile_account.has_value());
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin);
    output.encrypted_note.scan_domain = ScanDomain::USER;
    output.encrypted_note.scan_hint.fill(0x41);
    output.encrypted_note.ciphertext = {0x81, 0x82, 0x83};
    output.encrypted_note.ephemeral_key = ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{output.encrypted_note.ciphertext.data(), output.encrypted_note.ciphertext.size()});

    SendPayload payload;
    payload.spend_anchor = fixture.tree.Root();
    payload.account_registry_anchor = account_registry_witness->first;
    payload.output_encoding = SendOutputEncoding::SMILE_COMPACT;
    payload.output_note_class = NoteClass::USER;
    payload.output_scan_domain = ScanDomain::USER;
    payload.spends = {spend};
    payload.outputs = {output};
    payload.fee = 0;
    payload.value_balance = payload.fee;

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = TransactionFamily::V2_SEND;
    tx_bundle.header.proof_envelope.proof_kind = ProofKind::DIRECT_SMILE;
    tx_bundle.header.proof_envelope.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    tx_bundle.header.proof_envelope.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    tx_bundle.header.proof_envelope.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    tx_bundle.header.proof_envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    tx_bundle.payload = payload;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    fixture.tx.shielded_bundle.v2_bundle = tx_bundle;

    tx_bundle.header.proof_envelope.statement_digest =
        v2proof::ComputeV2SendStatementDigest(CTransaction{fixture.tx});

    v2proof::V2SendWitness witness;
    v2proof::V2SendSpendWitness spend_witness;
    spend_witness.real_index = 0;
    spend_witness.ring_positions = ring_positions;
    witness.spends = {spend_witness};
    witness.use_smile = true;
    witness.smile_proof_bytes = smile_result->proof_bytes;
    witness.smile_output_coins = smile_result->output_coins;

    DataStream witness_stream;
    witness_stream << witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    tx_bundle.proof_payload.assign(witness_begin, witness_begin + witness_stream.size());
    tx_bundle.payload = payload;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    fixture.tx.shielded_bundle.v2_bundle = tx_bundle;
    return fixture;
}

shielded::v2::TransactionBundle BuildPostforkGenericSmileSendBundle()
{
    using namespace shielded::v2;

    auto fixture = BuildSmileV2SendFixture();
    auto* bundle = fixture.tx.shielded_bundle.v2_bundle ? &*fixture.tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(bundle != nullptr);

    auto& payload = std::get<SendPayload>(bundle->payload);
    payload.output_encoding = SendOutputEncoding::SMILE_COMPACT_POSTFORK;
    payload.output_scan_domain = ScanDomain::OPAQUE;
    for (auto& output : payload.outputs) {
        output.encrypted_note.scan_domain = ScanDomain::OPAQUE;
    }

    const auto& consensus = Params().GetConsensus();
    const int32_t postfork_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(postfork_height >= 0);

    bundle->header.family_id = GetWireTransactionFamilyForValidationHeight(
        TransactionFamily::V2_SEND,
        &consensus,
        postfork_height);
    bundle->header.proof_envelope.proof_kind = GetWireProofKindForValidationHeight(
        TransactionFamily::V2_SEND,
        ProofKind::DIRECT_SMILE,
        &consensus,
        postfork_height);
    bundle->header.proof_envelope.membership_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_MEMBERSHIP,
                                                     &consensus,
                                                     postfork_height);
    bundle->header.proof_envelope.amount_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_BALANCE,
                                                     &consensus,
                                                     postfork_height);
    bundle->header.proof_envelope.balance_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_BALANCE,
                                                     &consensus,
                                                     postfork_height);
    bundle->header.proof_envelope.settlement_binding_kind =
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_SEND,
                                                        SettlementBindingKind::NONE,
                                                        &consensus,
                                                        postfork_height);
    bundle->header.payload_digest = ComputeSendPayloadDigest(payload);

    auto output_chunks = BuildDerivedGenericOutputChunks(bundle->payload);
    BOOST_REQUIRE(output_chunks.has_value());
    bundle->output_chunks = std::move(*output_chunks);
    bundle->header.output_chunk_root = bundle->output_chunks.empty()
        ? uint256::ZERO
        : ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{bundle->output_chunks.data(),
                                                                   bundle->output_chunks.size()});
    bundle->header.output_chunk_count = bundle->output_chunks.size();
    bundle->header.proof_envelope.statement_digest =
        v2proof::ComputeV2SendStatementDigest(CTransaction{fixture.tx}, consensus, postfork_height);

    BOOST_REQUIRE(bundle->IsValid());
    return *bundle;
}

SpendPathRecoveryFixture BuildPostforkSpendPathRecoveryFixture(unsigned char seed_base = 0x61)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t postfork_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(postfork_height >= 0);

    btx::test::shielded::SpendPathRecoveryFixtureBuildInput input;
    input.validation_height = postfork_height;
    input.matrict_disable_height = postfork_height;
    input.seed_base = seed_base;
    input.legacy_shield_fee = 1'000;
    input.recovery_fee = 1'000;
    input.legacy_funding_inputs.resize(3);
    for (size_t i = 0; i < input.legacy_funding_inputs.size(); ++i) {
        input.legacy_funding_inputs[i].funding_outpoint =
            COutPoint{Txid::FromUint256(uint256{static_cast<unsigned char>(0x20 + i)}), 0};
        input.legacy_funding_inputs[i].funding_value = 50'000 + static_cast<CAmount>(i) * 1'000;
    }

    std::string reject_reason;
    const auto built = btx::test::shielded::BuildSpendPathRecoveryFixture(input, reject_reason);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    SpendPathRecoveryFixture fixture;
    fixture.tx = built->recovery_tx;
    fixture.input_note_commitment = built->recovery_input_note_commitment;
    for (const auto& commitment : built->legacy_note_commitments) {
        fixture.tree.Append(commitment);
    }
    return fixture;
}

DataStream SerializeBundleWithExplicitProofPayload(
    const shielded::v2::TransactionBundle& bundle,
    Span<const uint8_t> proof_payload_bytes)
{
    DataStream ss;
    ::Serialize(ss, bundle.version);
    ::Serialize(ss, bundle.header);
    if (shielded::v2::IsGenericTransactionFamily(bundle.header.family_id)) {
        const auto payload_bytes =
            shielded::v2::SerializePayloadBytes(bundle.payload,
                                                shielded::v2::GetPayloadFamily(bundle.payload));
        ::Serialize(ss, payload_bytes);
    } else {
        shielded::v2::SerializePayload(ss,
                                       bundle.payload,
                                       shielded::v2::GetPayloadFamily(bundle.payload));
    }
    ::Serialize(ss, bundle.proof_shards);
    ::Serialize(ss, bundle.output_chunks);
    ::Serialize(ss,
                std::vector<uint8_t>{proof_payload_bytes.begin(),
                                     proof_payload_bytes.end()});
    return ss;
}

std::vector<uint256> GetOutputCommitments(const CShieldedBundle& bundle)
{
    std::vector<uint256> output_note_commitments;
    output_note_commitments.reserve(bundle.shielded_outputs.size());
    for (const CShieldedOutput& out : bundle.shielded_outputs) {
        output_note_commitments.push_back(out.note_commitment);
    }
    return output_note_commitments;
}

std::vector<Nullifier> GetInputNullifiers(const CShieldedBundle& bundle)
{
    std::vector<Nullifier> nullifiers;
    nullifiers.reserve(bundle.shielded_inputs.size());
    for (const CShieldedInput& in : bundle.shielded_inputs) {
        nullifiers.push_back(in.nullifier);
    }
    return nullifiers;
}

shielded::BridgeProofDescriptor MakeProofDescriptor(unsigned char seed)
{
    shielded::BridgeProofDescriptor descriptor;
    descriptor.proof_system_id = uint256{seed};
    descriptor.verifier_key_hash = uint256{static_cast<unsigned char>(seed + 1)};
    BOOST_REQUIRE(descriptor.IsValid());
    return descriptor;
}

shielded::BridgeProofAdapter MakeProofAdapter(unsigned char seed,
                                              shielded::BridgeProofClaimKind claim_kind)
{
    shielded::BridgeProofAdapter adapter;
    adapter.profile.family_id = uint256{seed};
    adapter.profile.proof_type_id = uint256{static_cast<unsigned char>(seed + 1)};
    adapter.profile.claim_system_id = uint256{static_cast<unsigned char>(seed + 2)};
    adapter.claim_kind = claim_kind;
    BOOST_REQUIRE(adapter.IsValid());
    return adapter;
}

std::vector<shielded::BridgeKeySpec> MakeVerifierSetAttestors(unsigned char seed_base, size_t count)
{
    std::vector<shielded::BridgeKeySpec> attestors;
    attestors.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        std::array<unsigned char, 32> material{};
        material.fill(static_cast<unsigned char>(seed_base + i));

        CPQKey key;
        BOOST_REQUIRE(key.MakeDeterministicKey(PQAlgorithm::ML_DSA_44, material));
        attestors.push_back({PQAlgorithm::ML_DSA_44, key.GetPubKey()});
    }
    return attestors;
}

shielded::BridgeBatchStatement MakeBatchStatement(shielded::BridgeDirection direction, CAmount total_amount)
{
    shielded::BridgeBatchStatement statement;
    statement.direction = direction;
    statement.ids.bridge_id = uint256{0x81};
    statement.ids.operation_id = uint256{0x82};
    statement.entry_count = 8;
    statement.total_amount = total_amount;
    statement.batch_root = uint256{0x84};
    statement.domain_id = uint256{0x85};
    statement.source_epoch = 12;
    statement.data_root = uint256{0x86};
    BOOST_REQUIRE(statement.IsValid());
    return statement;
}

shielded::BridgeBatchStatement MakeBatchStatementWithProofPolicy(
    shielded::BridgeDirection direction,
    CAmount total_amount,
    const shielded::BridgeProofPolicyCommitment& proof_policy)
{
    auto statement = MakeBatchStatement(direction, total_amount);
    statement.version = 3;
    statement.proof_policy = proof_policy;
    BOOST_REQUIRE(statement.IsValid());
    return statement;
}

shielded::BridgeBatchStatement MakeBatchStatementWithVerifierSetAndProofPolicy(
    shielded::BridgeDirection direction,
    CAmount total_amount,
    const shielded::BridgeVerifierSetCommitment& verifier_set,
    const shielded::BridgeProofPolicyCommitment& proof_policy)
{
    auto statement = MakeBatchStatement(direction, total_amount);
    statement.version = 4;
    statement.verifier_set = verifier_set;
    statement.proof_policy = proof_policy;
    BOOST_REQUIRE(statement.IsValid());
    return statement;
}

shielded::BridgeBatchStatement MakeFutureProofedBatchStatement(
    shielded::BridgeDirection direction,
    CAmount total_amount,
    const std::optional<shielded::BridgeVerifierSetCommitment>& verifier_set = std::nullopt,
    const std::optional<shielded::BridgeProofPolicyCommitment>& proof_policy = std::nullopt)
{
    auto statement = MakeBatchStatement(direction, total_amount);
    if (verifier_set.has_value()) {
        statement.verifier_set = *verifier_set;
    }
    if (proof_policy.has_value()) {
        statement.proof_policy = *proof_policy;
    }
    const auto aggregate_commitment = shielded::BuildDefaultBridgeBatchAggregateCommitment(statement.batch_root,
                                                                                           statement.data_root,
                                                                                           statement.proof_policy);
    BOOST_REQUIRE(aggregate_commitment.has_value());
    statement.aggregate_commitment = *aggregate_commitment;
    statement.version = 5;
    BOOST_REQUIRE(statement.IsValid());
    return statement;
}

shielded::BridgeBatchReceipt MakeSignedBatchReceipt(unsigned char seed,
                                                    const shielded::BridgeBatchStatement& statement)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);

    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(PQAlgorithm::ML_DSA_44, material));

    shielded::BridgeBatchReceipt receipt;
    receipt.statement = statement;
    receipt.attestor = {PQAlgorithm::ML_DSA_44, key.GetPubKey()};

    const uint256 receipt_hash = shielded::ComputeBridgeBatchReceiptHash(receipt);
    BOOST_REQUIRE(!receipt_hash.IsNull());
    BOOST_REQUIRE(key.Sign(receipt_hash, receipt.signature));
    BOOST_REQUIRE(receipt.IsValid());
    return receipt;
}

shielded::BridgeProofReceipt MakeProofReceipt(const shielded::BridgeBatchStatement& statement,
                                              const shielded::BridgeProofDescriptor& descriptor,
                                              unsigned char seed)
{
    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    receipt.proof_system_id = descriptor.proof_system_id;
    receipt.verifier_key_hash = descriptor.verifier_key_hash;
    receipt.public_values_hash = uint256{static_cast<unsigned char>(seed + 1)};
    receipt.proof_commitment = uint256{static_cast<unsigned char>(seed + 2)};
    BOOST_REQUIRE(receipt.IsValid());
    return receipt;
}

shielded::BridgeVerificationBundle MakeVerificationBundle(
    const std::vector<shielded::BridgeBatchReceipt>& signed_receipts,
    const std::vector<shielded::BridgeProofReceipt>& proof_receipts)
{
    shielded::BridgeVerificationBundle bundle;
    bundle.signed_receipt_root = shielded::ComputeBridgeBatchReceiptRoot(signed_receipts);
    bundle.proof_receipt_root = shielded::ComputeBridgeProofReceiptRoot(proof_receipts);
    BOOST_REQUIRE(bundle.IsValid());
    return bundle;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_v2_proof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(legacy_direct_statement_tracks_binding_hash)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    const CTransaction tx{mtx};

    const v2proof::ProofStatement statement = v2proof::DescribeLegacyDirectSpendStatement(tx);
    BOOST_CHECK(statement.IsValid());
    BOOST_CHECK(statement.domain == v2proof::VerificationDomain::DIRECT_SPEND);
    BOOST_CHECK(statement.envelope.statement_digest == shielded::ringct::ComputeMatRiCTBindingHash(tx));
    BOOST_CHECK(statement.envelope.proof_kind == shielded::v2::ProofKind::DIRECT_MATRICT);
    BOOST_CHECK(statement.envelope.membership_proof_kind == shielded::v2::ProofComponentKind::MATRICT);
    BOOST_CHECK(statement.envelope.amount_proof_kind == shielded::v2::ProofComponentKind::RANGE);
    BOOST_CHECK(statement.envelope.balance_proof_kind == shielded::v2::ProofComponentKind::BALANCE);
    BOOST_CHECK(statement.envelope.settlement_binding_kind == shielded::v2::SettlementBindingKind::NONE);
}

BOOST_AUTO_TEST_CASE(legacy_direct_context_rejects_smile_envelope)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    const CTransaction tx{mtx};

    v2proof::ProofStatement statement = v2proof::DescribeLegacyDirectSpendStatement(tx);
    statement.envelope.proof_kind = shielded::v2::ProofKind::DIRECT_SMILE;
    statement.envelope.membership_proof_kind = shielded::v2::ProofComponentKind::SMILE_MEMBERSHIP;
    statement.envelope.amount_proof_kind = shielded::v2::ProofComponentKind::SMILE_BALANCE;
    statement.envelope.balance_proof_kind = shielded::v2::ProofComponentKind::SMILE_BALANCE;

    std::string reject_reason;
    auto native_proof = v2proof::ParseLegacyDirectSpendNativeProof(mtx.shielded_bundle, reject_reason);
    BOOST_REQUIRE(native_proof.has_value());

    const auto context = v2proof::BindLegacyDirectSpendProof(mtx.shielded_bundle, statement, *native_proof);
    BOOST_CHECK(!context.IsValid(/*expected_input_count=*/1));
}

BOOST_AUTO_TEST_CASE(v2_send_statement_tracks_stripped_tx_digest)
{
    auto fixture = BuildSmileV2SendFixture();
    const CTransaction tx{fixture.tx};

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(tx);
    BOOST_CHECK(statement.IsValid());
    BOOST_CHECK(statement.envelope.statement_digest == v2proof::ComputeV2SendStatementDigest(tx));

    CMutableTransaction proof_mutated = fixture.tx;
    proof_mutated.shielded_bundle.v2_bundle->proof_payload.push_back(0xff);
    BOOST_CHECK(v2proof::ComputeV2SendStatementDigest(CTransaction{proof_mutated}) ==
                statement.envelope.statement_digest);

    CMutableTransaction tx_context_mutated = fixture.tx;
    tx_context_mutated.nLockTime ^= 1;
    BOOST_CHECK(v2proof::ComputeV2SendStatementDigest(CTransaction{tx_context_mutated}) !=
                statement.envelope.statement_digest);
}

BOOST_AUTO_TEST_CASE(spend_path_recovery_statement_tracks_stripped_tx_digest)
{
    auto fixture = BuildPostforkSpendPathRecoveryFixture();
    const CTransaction tx{fixture.tx};

    const v2proof::ProofStatement statement = v2proof::DescribeSpendPathRecoveryStatement(tx);
    BOOST_CHECK(statement.IsValid());
    BOOST_CHECK(statement.domain == v2proof::VerificationDomain::SPEND_PATH_RECOVERY);
    BOOST_CHECK(statement.envelope.statement_digest ==
                v2proof::ComputeSpendPathRecoveryStatementDigest(tx));

    CMutableTransaction proof_mutated = fixture.tx;
    proof_mutated.shielded_bundle.v2_bundle->proof_payload.push_back(0xff);
    BOOST_CHECK(v2proof::ComputeSpendPathRecoveryStatementDigest(CTransaction{proof_mutated}) ==
                statement.envelope.statement_digest);

    CMutableTransaction tx_context_mutated = fixture.tx;
    tx_context_mutated.nLockTime ^= 1;
    BOOST_CHECK(v2proof::ComputeSpendPathRecoveryStatementDigest(
                    CTransaction{tx_context_mutated}) != statement.envelope.statement_digest);
}

BOOST_AUTO_TEST_CASE(v2_send_statement_digest_binds_genesis_after_disable_height)
{
    auto fixture = BuildSmileV2SendFixture();
    const CTransaction tx{fixture.tx};
    const auto& main_consensus = Params().GetConsensus();
    const auto alt_params = CreateChainParams(*m_node.args, ChainType::SHIELDEDV2DEV);
    BOOST_REQUIRE(alt_params != nullptr);

    const uint256 legacy_digest = v2proof::ComputeV2SendStatementDigest(tx);
    const uint256 pre_disable_digest = v2proof::ComputeV2SendStatementDigest(
        tx,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight - 1);
    const uint256 post_disable_digest = v2proof::ComputeV2SendStatementDigest(
        tx,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight);
    const uint256 alt_chain_digest = v2proof::ComputeV2SendStatementDigest(
        tx,
        alt_params->GetConsensus(),
        alt_params->GetConsensus().nShieldedMatRiCTDisableHeight);
    const auto post_disable_statement = v2proof::DescribeV2SendStatement(
        tx,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight);

    BOOST_CHECK_EQUAL(legacy_digest, pre_disable_digest);
    BOOST_CHECK(post_disable_digest != legacy_digest);
    BOOST_CHECK(post_disable_digest != alt_chain_digest);
    BOOST_CHECK_EQUAL(post_disable_statement.envelope.statement_digest, post_disable_digest);
}

BOOST_AUTO_TEST_CASE(v2_send_context_parses_and_verifies)
{
    auto fixture = BuildSmileV2SendFixture();
    const CTransaction tx{fixture.tx};
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(tx);
    std::string reject_reason;
    auto context = v2proof::ParseV2SendProof(bundle, statement, reject_reason);
    BOOST_REQUIRE(context.has_value());
    BOOST_CHECK(context->IsValid(/*expected_input_count=*/1, /*expected_output_count=*/1));
    BOOST_CHECK(context->material.payload_location == v2proof::PayloadLocation::INLINE_WITNESS);
    BOOST_REQUIRE_EQUAL(context->material.proof_shards.size(), 1U);
    BOOST_CHECK_EQUAL(context->material.proof_shards[0].leaf_count, 1U);
    BOOST_CHECK_EQUAL(context->material.proof_shards[0].proof_payload_size, bundle.proof_payload.size());

    auto nullifiers = v2proof::ExtractBoundNullifiers(*context,
                                                      /*expected_input_count=*/1,
                                                      /*expected_output_count=*/1,
                                                      reject_reason);
    BOOST_REQUIRE(nullifiers.has_value());
    BOOST_CHECK_EQUAL(nullifiers->size(), 1U);
    BOOST_CHECK((*nullifiers)[0] == std::get<shielded::v2::SendPayload>(bundle.payload).spends[0].nullifier);

    auto ring_members = v2proof::BuildV2SendSmileRingMembers(bundle,
                                                             *context,
                                                             fixture.tree,
                                                             fixture.public_accounts,
                                                             fixture.account_leaf_commitments,
                                                             reject_reason);
    BOOST_REQUIRE(ring_members.has_value());
    BOOST_CHECK(v2proof::VerifyV2SendProof(bundle, *context, *ring_members));
}

BOOST_AUTO_TEST_CASE(spend_path_recovery_context_parses_under_disabled_scaffold)
{
    auto fixture = BuildPostforkSpendPathRecoveryFixture();
    const CTransaction tx{fixture.tx};
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;

    const v2proof::ProofStatement statement =
        v2proof::DescribeSpendPathRecoveryStatement(tx);
    std::string reject_reason;
    auto context = v2proof::ParseSpendPathRecoveryProof(bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(context->IsValid(/*expected_input_count=*/1, /*expected_output_count=*/1));
    BOOST_CHECK(context->material.statement.domain ==
                v2proof::VerificationDomain::SPEND_PATH_RECOVERY);
    BOOST_CHECK(context->material.payload_location == v2proof::PayloadLocation::INLINE_WITNESS);
    BOOST_REQUIRE_EQUAL(context->material.proof_shards.size(), 1U);
    BOOST_CHECK_EQUAL(context->material.proof_shards[0].leaf_count, 1U);
    BOOST_CHECK_EQUAL(context->material.proof_shards[0].proof_payload_size,
                      bundle.proof_payload.size());

    auto nullifiers = v2proof::ExtractBoundNullifiers(*context,
                                                      /*expected_input_count=*/1,
                                                      /*expected_output_count=*/1,
                                                      reject_reason);
    BOOST_REQUIRE(nullifiers.has_value());
    BOOST_CHECK_EQUAL(nullifiers->size(), 1U);
    BOOST_CHECK((*nullifiers)[0] ==
                std::get<shielded::v2::SpendPathRecoveryPayload>(bundle.payload).spends[0].nullifier);
}

BOOST_AUTO_TEST_CASE(spend_path_recovery_context_rejects_wrong_statement_digest)
{
    auto fixture = BuildPostforkSpendPathRecoveryFixture();
    CMutableTransaction mutated = fixture.tx;
    mutated.nLockTime ^= 1;

    std::string reject_reason;
    auto context = v2proof::ParseSpendPathRecoveryProof(
        *mutated.shielded_bundle.v2_bundle,
        v2proof::DescribeSpendPathRecoveryStatement(CTransaction{mutated}),
        reject_reason);
    BOOST_CHECK(!context.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(spend_path_recovery_context_rejects_missing_proof_payload)
{
    auto fixture = BuildPostforkSpendPathRecoveryFixture();
    fixture.tx.shielded_bundle.v2_bundle->proof_payload.clear();

    std::string reject_reason;
    auto context = v2proof::ParseSpendPathRecoveryProof(
        *fixture.tx.shielded_bundle.v2_bundle,
        v2proof::DescribeSpendPathRecoveryStatement(CTransaction{fixture.tx}),
        reject_reason);
    BOOST_CHECK(!context.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof-missing");
}

BOOST_AUTO_TEST_CASE(spend_path_recovery_context_rejects_malformed_witness_encoding)
{
    auto fixture = BuildPostforkSpendPathRecoveryFixture();
    fixture.tx.shielded_bundle.v2_bundle->proof_payload = {0x80};

    std::string reject_reason;
    auto context = v2proof::ParseSpendPathRecoveryProof(
        *fixture.tx.shielded_bundle.v2_bundle,
        v2proof::DescribeSpendPathRecoveryStatement(CTransaction{fixture.tx}),
        reject_reason);
    BOOST_CHECK(!context.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof-encoding");
}

BOOST_AUTO_TEST_CASE(spend_path_recovery_matrict_proof_verifies_against_recovery_context)
{
    auto fixture = BuildPostforkSpendPathRecoveryFixture();
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    const auto statement =
        v2proof::DescribeSpendPathRecoveryStatement(CTransaction{fixture.tx});

    std::string reject_reason;
    auto context = v2proof::ParseSpendPathRecoveryProof(bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    auto ring_members = v2proof::BuildSpendPathRecoveryRingMembers(bundle,
                                                                   *context,
                                                                   fixture.tree,
                                                                   reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(ring_members->size(), 1U);
    BOOST_REQUIRE_EQUAL(ring_members->front().size(), 1U);
    BOOST_CHECK_EQUAL(ring_members->front().front(), fixture.input_note_commitment);

    BOOST_CHECK(v2proof::VerifySpendPathRecoveryProof(bundle,
                                                      *context,
                                                      *ring_members));
}

BOOST_AUTO_TEST_CASE(v2_send_context_rejects_wrong_statement_digest)
{
    auto fixture = BuildSmileV2SendFixture();
    CMutableTransaction mutated = fixture.tx;
    mutated.nLockTime ^= 1;

    std::string reject_reason;
    auto context = v2proof::ParseV2SendProof(*mutated.shielded_bundle.v2_bundle,
                                             v2proof::DescribeV2SendStatement(CTransaction{mutated}),
                                             reject_reason);
    BOOST_CHECK(!context.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(v2_send_context_accepts_non_null_extension_digest)
{
    auto fixture = BuildSmileV2SendFixture();
    fixture.tx.shielded_bundle.v2_bundle->header.proof_envelope.extension_digest = uint256{0xee};
    const uint256 updated_digest = v2proof::ComputeV2SendStatementDigest(CTransaction{fixture.tx});
    fixture.tx.shielded_bundle.v2_bundle->header.proof_envelope.statement_digest = updated_digest;

    const CTransaction tx{fixture.tx};
    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(tx);
    BOOST_CHECK(statement.IsValid());
    BOOST_CHECK(statement.envelope.extension_digest == uint256{0xee});
    BOOST_CHECK(statement.envelope.statement_digest == updated_digest);

    std::string reject_reason;
    auto context = v2proof::ParseV2SendProof(*fixture.tx.shielded_bundle.v2_bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(context->IsValid(/*expected_input_count=*/1, /*expected_output_count=*/1));
}

BOOST_AUTO_TEST_CASE(v2_send_extension_digest_is_canonical_over_zeroed_binding_fields)
{
    auto fixture = BuildSmileV2SendFixture();
    const CTransaction tx{fixture.tx};
    const uint256 extension_digest = v2proof::ComputeV2SendExtensionDigest(tx);
    BOOST_CHECK(!extension_digest.IsNull());

    CMutableTransaction mutated = fixture.tx;
    mutated.shielded_bundle.v2_bundle->header.proof_envelope.extension_digest = uint256{};
    BOOST_CHECK(v2proof::ComputeV2SendExtensionDigest(CTransaction{mutated}) == extension_digest);

    mutated = fixture.tx;
    mutated.shielded_bundle.v2_bundle->header.proof_envelope.statement_digest = uint256{0x91};
    BOOST_CHECK(v2proof::ComputeV2SendExtensionDigest(CTransaction{mutated}) == extension_digest);

    auto statement = v2proof::DescribeV2SendStatement(tx, extension_digest);
    BOOST_CHECK(statement.IsValid());
    BOOST_CHECK(statement.envelope.extension_digest == extension_digest);
}

BOOST_AUTO_TEST_CASE(v2_send_smile_witness_requires_proof_bytes)
{
    auto fixture = BuildSmileV2SendFixture();
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_CHECK(witness->IsValid(/*expected_input_count=*/1, /*expected_output_count=*/1));

    witness->smile_proof_bytes.clear();
    BOOST_CHECK(!witness->IsValid(/*expected_input_count=*/1, /*expected_output_count=*/1));
}

BOOST_AUTO_TEST_CASE(v2_send_parse_rejects_missing_proof_payload)
{
    auto fixture = BuildSmileV2SendFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    bundle.proof_payload.clear();

    std::string reject_reason;
    const auto parsed = v2proof::ParseV2SendWitness(bundle, reject_reason);
    BOOST_CHECK(!parsed.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof-missing");
}

BOOST_AUTO_TEST_CASE(v2_send_parse_rejects_trailing_witness_bytes)
{
    auto fixture = BuildSmileV2SendFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    bundle.proof_payload.push_back(0xff);

    std::string reject_reason;
    const auto parsed = v2proof::ParseV2SendWitness(bundle, reject_reason);
    BOOST_CHECK(!parsed.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof-encoding");
}

BOOST_AUTO_TEST_CASE(postfork_generic_send_bundle_roundtrip_strips_padded_opaque_proof_payload)
{
    auto bundle = BuildPostforkGenericSmileSendBundle();

    const auto raw_proof_payload = bundle.proof_payload;
    const auto padded_proof_payload = shielded::v2::SerializeProofPayloadBytes(bundle);
    BOOST_REQUIRE_GT(padded_proof_payload.size(), raw_proof_payload.size());
    BOOST_CHECK_EQUAL(padded_proof_payload.size() %
                          shielded::v2::OPAQUE_FAMILY_PAYLOAD_PAD_QUANTUM,
                      0U);

    DataStream ss;
    ss << bundle;

    shielded::v2::TransactionBundle decoded;
    ss >> decoded;
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK_EQUAL(decoded.header.family_id,
                      shielded::v2::TransactionFamily::V2_GENERIC);
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(
        decoded,
        shielded::v2::TransactionFamily::V2_SEND));
    BOOST_CHECK(decoded.proof_payload == raw_proof_payload);
}

BOOST_AUTO_TEST_CASE(postfork_generic_send_bundle_rejects_noncanonical_unpadded_opaque_proof_payload)
{
    auto bundle = BuildPostforkGenericSmileSendBundle();
    BOOST_REQUIRE_LT(bundle.proof_payload.size(),
                     shielded::v2::SerializeProofPayloadBytes(bundle).size());

    DataStream ss = SerializeBundleWithExplicitProofPayload(
        bundle,
        Span<const uint8_t>{bundle.proof_payload.data(), bundle.proof_payload.size()});

    BOOST_CHECK_THROW(
        [&] {
            shielded::v2::TransactionBundle decoded;
            ss >> decoded;
        }(),
        std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(v2_send_parse_none_proof_accepts_only_empty_witness_surface)
{
    auto fixture = BuildSmileV2SendFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
    const auto original_spends = payload.spends;

    bundle.header.proof_envelope.proof_kind = shielded::v2::ProofKind::NONE;
    payload.spends.clear();
    bundle.proof_payload.clear();

    std::string reject_reason;
    const auto empty_witness = v2proof::ParseV2SendWitness(bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(empty_witness.has_value(), reject_reason);
    BOOST_CHECK(empty_witness->IsValid(/*expected_input_count=*/0,
                                       /*expected_output_count=*/payload.outputs.size()));

    payload.spends = original_spends;
    const auto rejected = v2proof::ParseV2SendWitness(bundle, reject_reason);
    BOOST_CHECK(!rejected.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(v2_send_parse_rejects_subminimum_ring_size_with_ring_reason)
{
    auto fixture = BuildSmileV2SendFixture();
    auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(witness->spends.size(), 1U);

    witness->spends[0].ring_positions.resize(1);
    DataStream witness_stream;
    witness_stream << *witness;
    const auto* witness_begin =
        reinterpret_cast<const uint8_t*>(witness_stream.data());
    bundle.proof_payload.assign(witness_begin, witness_begin + witness_stream.size());

    const auto parsed = v2proof::ParseV2SendWitness(bundle, reject_reason);
    BOOST_CHECK(!parsed.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-ring-positions");
}

BOOST_AUTO_TEST_CASE(v2_send_smile_context_extracts_serial_hash_nullifiers)
{
    auto fixture = BuildSmileV2SendFixture();
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{fixture.tx});

    std::string reject_reason;
    auto witness = v2proof::ParseV2SendWitness(bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);

    const auto context = v2proof::BindV2SendProof(bundle, statement, std::move(*witness));
    auto nullifiers = v2proof::ExtractBoundNullifiers(context,
                                                      /*expected_input_count=*/1,
                                                      /*expected_output_count=*/1,
                                                      reject_reason);
    BOOST_REQUIRE(nullifiers.has_value());
    BOOST_REQUIRE_EQUAL(nullifiers->size(), 1U);
    BOOST_CHECK((*nullifiers)[0] == fixture.serial_hashes[0]);
}

BOOST_AUTO_TEST_CASE(v2_send_smile_context_bound_nullifiers_are_unique_across_distinct_fixtures)
{
    std::vector<uint256> nullifiers;
    nullifiers.reserve(4);

    for (const unsigned char seed_base : {0x10, 0x20, 0x30, 0x40}) {
        auto fixture = BuildSmileV2SendFixture(seed_base);
        const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
        const v2proof::ProofStatement statement =
            v2proof::DescribeV2SendStatement(CTransaction{fixture.tx});

        std::string reject_reason;
        auto context = v2proof::ParseV2SendProof(bundle, statement, reject_reason);
        BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

        auto extracted = v2proof::ExtractBoundNullifiers(*context,
                                                         /*expected_input_count=*/1,
                                                         /*expected_output_count=*/1,
                                                         reject_reason);
        BOOST_REQUIRE_MESSAGE(extracted.has_value(), reject_reason);
        BOOST_REQUIRE_EQUAL(extracted->size(), 1U);
        BOOST_CHECK((*extracted)[0] == fixture.serial_hashes[0]);
        nullifiers.push_back((*extracted)[0]);
    }

    for (size_t i = 0; i < nullifiers.size(); ++i) {
        for (size_t j = i + 1; j < nullifiers.size(); ++j) {
            BOOST_CHECK(nullifiers[i] != nullifiers[j]);
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_send_smile_ring_reconstruction_requires_public_accounts)
{
    auto fixture = BuildSmileV2SendFixture();
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{fixture.tx});

    std::string reject_reason;
    auto context = v2proof::ParseV2SendProof(bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    std::map<uint256, smile2::CompactPublicAccount> public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    auto ring_members = v2proof::BuildV2SendSmileRingMembers(bundle,
                                                             *context,
                                                             fixture.tree,
                                                             public_accounts,
                                                             account_leaf_commitments,
                                                             reject_reason);
    BOOST_CHECK(!ring_members.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-smile2-ring-member-public-account");
}

BOOST_AUTO_TEST_CASE(v2_send_smile_ring_reconstruction_can_be_recovered_from_committed_registry_state)
{
    auto fixture = BuildSmileV2SendFixture();
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{fixture.tx});

    std::string reject_reason;
    auto context = v2proof::ParseV2SendProof(bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    shielded::registry::ShieldedAccountRegistryState registry_state;
    std::vector<shielded::registry::ShieldedAccountLeaf> leaves;
    leaves.reserve(fixture.public_accounts.size());
    for (const auto& [note_commitment, account] : fixture.public_accounts) {
        const auto leaf = shielded::registry::BuildShieldedAccountLeaf(
            account,
            note_commitment,
            shielded::registry::AccountDomain::DIRECT_SEND);
        BOOST_REQUIRE(leaf.has_value());
        leaves.push_back(*leaf);
    }
    BOOST_REQUIRE(registry_state.Append(
        Span<const shielded::registry::ShieldedAccountLeaf>{leaves.data(), leaves.size()}));

    std::map<uint256, smile2::CompactPublicAccount> public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    BOOST_REQUIRE(shielded::registry::BuildRegistryAccountState(registry_state,
                                                                public_accounts,
                                                                account_leaf_commitments));
    auto ring_members = v2proof::BuildV2SendSmileRingMembers(bundle,
                                                             *context,
                                                             fixture.tree,
                                                             public_accounts,
                                                             account_leaf_commitments,
                                                             reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(ring_members->size(), 1U);
    BOOST_REQUIRE_EQUAL((*ring_members)[0].size(), shielded::lattice::RING_SIZE);
    BOOST_CHECK_EQUAL((*ring_members)[0][fixture.real_index].note_commitment,
                      fixture.tree.CommitmentAt(fixture.real_index).value());
    BOOST_CHECK_EQUAL((*ring_members)[0][fixture.real_index].account_leaf_commitment,
                      fixture.account_leaf_commitments.at(
                          fixture.tree.CommitmentAt(fixture.real_index).value()));
}

BOOST_AUTO_TEST_CASE(v2_send_smile_ring_reconstruction_requires_account_leaf_commitments)
{
    auto fixture = BuildSmileV2SendFixture();
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{fixture.tx});

    std::string reject_reason;
    auto context = v2proof::ParseV2SendProof(bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    std::map<uint256, uint256> account_leaf_commitments;
    auto ring_members = v2proof::BuildV2SendSmileRingMembers(bundle,
                                                             *context,
                                                             fixture.tree,
                                                             fixture.public_accounts,
                                                             account_leaf_commitments,
                                                             reject_reason);
    BOOST_CHECK(!ring_members.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-smile2-ring-member-account-leaf");
}

BOOST_AUTO_TEST_CASE(v2_send_smile_verifier_rejects_account_leaf_binding_mismatch)
{
    auto fixture = BuildSmileV2SendFixture();
    std::string reject_reason;
    const auto& bundle = *fixture.tx.shielded_bundle.v2_bundle;
    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{fixture.tx});
    auto context = v2proof::ParseV2SendProof(bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    auto ring_members = v2proof::BuildV2SendSmileRingMembers(bundle,
                                                             *context,
                                                             fixture.tree,
                                                             fixture.public_accounts,
                                                             fixture.account_leaf_commitments,
                                                             reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);

    auto mutated_bundle = bundle;
    auto& mutated_payload = std::get<shielded::v2::SendPayload>(mutated_bundle.payload);
    const auto substitute_commitment = fixture.tree.CommitmentAt(fixture.real_index == 0 ? 1 : 0);
    BOOST_REQUIRE(substitute_commitment.has_value());
    const auto substitute_leaf = fixture.account_leaf_commitments.find(*substitute_commitment);
    BOOST_REQUIRE(substitute_leaf != fixture.account_leaf_commitments.end());
    const auto substitute_registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(*substitute_commitment,
                                                      fixture.public_accounts.at(*substitute_commitment));
    BOOST_REQUIRE(substitute_registry_witness.has_value());
    mutated_payload.account_registry_anchor = substitute_registry_witness->first;
    mutated_payload.spends[0].account_leaf_commitment = substitute_leaf->second;
    mutated_payload.spends[0].account_registry_proof = substitute_registry_witness->second;
    mutated_bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(mutated_payload);
    CMutableTransaction mutated_tx = fixture.tx;
    mutated_tx.shielded_bundle.v2_bundle = mutated_bundle;

    const v2proof::ProofStatement rebound_statement =
        v2proof::DescribeV2SendStatement(CTransaction{mutated_tx});
    mutated_bundle.header.proof_envelope.statement_digest = rebound_statement.envelope.statement_digest;
    mutated_tx.shielded_bundle.v2_bundle = mutated_bundle;

    context = v2proof::ParseV2SendProof(*mutated_tx.shielded_bundle.v2_bundle,
                                        rebound_statement,
                                        reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    ring_members = v2proof::BuildV2SendSmileRingMembers(*mutated_tx.shielded_bundle.v2_bundle,
                                                        *context,
                                                        fixture.tree,
                                                        fixture.public_accounts,
                                                        fixture.account_leaf_commitments,
                                                        reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_CHECK(!v2proof::VerifyV2SendProof(*mutated_tx.shielded_bundle.v2_bundle, *context, *ring_members));
}

BOOST_AUTO_TEST_CASE(v2_send_smile_shard_binds_declared_payload_and_output_coins)
{
    auto fixture = BuildSmileV2SendFixture();
    const auto& base_bundle = *fixture.tx.shielded_bundle.v2_bundle;
    const v2proof::ProofStatement base_statement = v2proof::DescribeV2SendStatement(CTransaction{fixture.tx});

    std::string reject_reason;
    auto base_witness = v2proof::ParseV2SendWitness(base_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(base_witness.has_value(), reject_reason);
    const auto base_context = v2proof::BindV2SendProof(base_bundle, base_statement, std::move(*base_witness));
    BOOST_REQUIRE_EQUAL(base_context.material.proof_shards.size(), 1U);
    const auto& base_shard = base_context.material.proof_shards[0];

    auto payload_bundle = base_bundle;
    auto& payload = std::get<shielded::v2::SendPayload>(payload_bundle.payload);
    payload.spends[0].nullifier = uint256{0x91};
    payload_bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);
    CMutableTransaction payload_tx = fixture.tx;
    payload_tx.shielded_bundle.v2_bundle = payload_bundle;
    const auto payload_statement = v2proof::DescribeV2SendStatement(CTransaction{payload_tx});
    payload_bundle.header.proof_envelope.statement_digest = payload_statement.envelope.statement_digest;

    auto payload_witness = v2proof::ParseV2SendWitness(base_bundle, reject_reason);
    BOOST_REQUIRE(payload_witness.has_value());
    const auto payload_context =
        v2proof::BindV2SendProof(payload_bundle, payload_statement, std::move(*payload_witness));
    BOOST_REQUIRE_EQUAL(payload_context.material.proof_shards.size(), 1U);
    BOOST_CHECK(base_shard.nullifier_commitment !=
                payload_context.material.proof_shards[0].nullifier_commitment);

    auto output_bundle = base_bundle;
    auto& output_payload = std::get<shielded::v2::SendPayload>(output_bundle.payload);
    BOOST_REQUIRE(output_payload.outputs[0].smile_account.has_value());
    BOOST_REQUIRE(!output_payload.outputs[0].smile_account->public_coin.t_msg.empty());
    output_payload.outputs[0].smile_account->public_coin.t_msg[0].coeffs[0] += 1;
    output_payload.outputs[0].note_commitment =
        smile2::ComputeCompactPublicAccountHash(*output_payload.outputs[0].smile_account);
    output_payload.outputs[0].value_commitment =
        smile2::ComputeSmileOutputCoinHash(output_payload.outputs[0].smile_account->public_coin);
    output_bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(output_payload);
    CMutableTransaction output_tx = fixture.tx;
    output_tx.shielded_bundle.v2_bundle = output_bundle;
    const auto output_statement = v2proof::DescribeV2SendStatement(CTransaction{output_tx});
    output_bundle.header.proof_envelope.statement_digest = output_statement.envelope.statement_digest;
    auto output_witness = v2proof::ParseV2SendWitness(output_bundle, reject_reason);
    BOOST_REQUIRE(output_witness.has_value());
    const auto output_context =
        v2proof::BindV2SendProof(output_bundle, output_statement, std::move(*output_witness));
    BOOST_REQUIRE_EQUAL(output_context.material.proof_shards.size(), 1U);
    BOOST_CHECK(base_shard.value_commitment !=
                output_context.material.proof_shards[0].value_commitment);
}

BOOST_AUTO_TEST_CASE(v2_send_smile_verifier_rejects_output_commitment_account_mismatch)
{
    auto fixture = BuildSmileV2SendFixture();
    auto& payload = std::get<shielded::v2::SendPayload>(fixture.tx.shielded_bundle.v2_bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), 1U);
    BOOST_REQUIRE(payload.outputs[0].smile_account.has_value());
    BOOST_REQUIRE(!payload.outputs[0].smile_account->public_key.empty());
    payload.outputs[0].smile_account->public_key[0].coeffs[0] =
        smile2::mod_q(payload.outputs[0].smile_account->public_key[0].coeffs[0] + 1);
    BOOST_CHECK_EXCEPTION(
        static_cast<void>(shielded::v2::ComputeSendPayloadDigest(payload)),
        std::ios_base::failure,
        HasReason("OutputDescription::SerializeDirectSend mismatched note_commitment"));
}

BOOST_AUTO_TEST_CASE(v2_send_smile_verifier_rejects_output_coin_account_mismatch)
{
    auto fixture = BuildSmileV2SendFixture();
    auto bundle = *fixture.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), 1U);
    BOOST_REQUIRE(payload.outputs[0].smile_account.has_value());
    BOOST_REQUIRE(!payload.outputs[0].smile_account->public_coin.t_msg.empty());
    payload.outputs[0].smile_account->public_coin.t_msg[0].coeffs[0] =
        smile2::mod_q(payload.outputs[0].smile_account->public_coin.t_msg[0].coeffs[0] + 1);
    payload.outputs[0].note_commitment =
        smile2::ComputeCompactPublicAccountHash(*payload.outputs[0].smile_account);
    payload.outputs[0].value_commitment =
        smile2::ComputeSmileOutputCoinHash(payload.outputs[0].smile_account->public_coin);
    bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(payload);

    CMutableTransaction tx = fixture.tx;
    tx.shielded_bundle.v2_bundle = bundle;
    const auto statement = v2proof::DescribeV2SendStatement(CTransaction{tx});
    bundle.header.proof_envelope.statement_digest = statement.envelope.statement_digest;
    tx.shielded_bundle.v2_bundle = bundle;

    std::string reject_reason;
    auto context = v2proof::ParseV2SendProof(*tx.shielded_bundle.v2_bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    auto ring_members = v2proof::BuildV2SendSmileRingMembers(*tx.shielded_bundle.v2_bundle,
                                                             *context,
                                                             fixture.tree,
                                                             fixture.public_accounts,
                                                             fixture.account_leaf_commitments,
                                                             reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_CHECK(!v2proof::VerifyV2SendProof(*tx.shielded_bundle.v2_bundle, *context, *ring_members));
}

BOOST_AUTO_TEST_CASE(legacy_direct_context_surfaces_descriptors_and_verifies)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    const CTransaction tx{mtx};

    const v2proof::ProofStatement statement = v2proof::DescribeLegacyDirectSpendStatement(tx);
    std::string reject_reason;
    auto context = v2proof::ParseLegacyDirectSpendProof(mtx.shielded_bundle, statement, reject_reason);
    BOOST_REQUIRE(context.has_value());
    BOOST_CHECK(context->IsValid(/*expected_input_count=*/1));
    BOOST_CHECK(context->material.payload_location == v2proof::PayloadLocation::INLINE_WITNESS);
    BOOST_REQUIRE_EQUAL(context->material.proof_shards.size(), 1U);
    BOOST_CHECK_EQUAL(context->material.proof_shards[0].first_leaf_index, 0U);
    BOOST_CHECK_EQUAL(context->material.proof_shards[0].leaf_count, 1U);
    BOOST_CHECK(context->material.proof_shards[0].statement_digest == statement.envelope.statement_digest);
    BOOST_CHECK_EQUAL(context->material.proof_shards[0].proof_payload_size, mtx.shielded_bundle.proof.size());

    auto nullifiers = v2proof::ExtractBoundNullifiers(*context,
                                                      /*expected_input_count=*/1,
                                                      reject_reason);
    BOOST_REQUIRE(nullifiers.has_value());
    BOOST_CHECK_EQUAL(nullifiers->size(), 1U);
    BOOST_CHECK((*nullifiers)[0] == mtx.shielded_bundle.shielded_inputs[0].nullifier);

    shielded::ShieldedMerkleTree tree = BuildTree();
    auto ring_members = v2proof::BuildLegacyDirectSpendRingMembers(mtx.shielded_bundle, tree, reject_reason);
    BOOST_REQUIRE(ring_members.has_value());

    BOOST_CHECK(v2proof::VerifyLegacyDirectSpendProof(*context,
                                                      *ring_members,
                                                      GetInputNullifiers(mtx.shielded_bundle),
                                                      GetOutputCommitments(mtx.shielded_bundle),
                                                      mtx.shielded_bundle.value_balance));
}

BOOST_AUTO_TEST_CASE(legacy_direct_context_fails_with_wrong_statement_digest)
{
    CMutableTransaction mtx;
    mtx.shielded_bundle = BuildProofBundle();
    const CTransaction tx{mtx};

    v2proof::ProofStatement statement = v2proof::DescribeLegacyDirectSpendStatement(tx);
    statement.envelope.statement_digest = GetRandHash();

    std::string reject_reason;
    auto context = v2proof::ParseLegacyDirectSpendProof(mtx.shielded_bundle, statement, reject_reason);
    BOOST_REQUIRE(context.has_value());

    shielded::ShieldedMerkleTree tree = BuildTree();
    auto ring_members = v2proof::BuildLegacyDirectSpendRingMembers(mtx.shielded_bundle, tree, reject_reason);
    BOOST_REQUIRE(ring_members.has_value());

    BOOST_CHECK(!v2proof::VerifyLegacyDirectSpendProof(*context,
                                                       *ring_members,
                                                       GetInputNullifiers(mtx.shielded_bundle),
                                                       GetOutputCommitments(mtx.shielded_bundle),
                                                       mtx.shielded_bundle.value_balance));
}

BOOST_AUTO_TEST_CASE(imported_receipt_context_records_payload_location)
{
    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = GetRandHash();
    receipt.proof_system_id = GetRandHash();
    receipt.verifier_key_hash = GetRandHash();
    receipt.public_values_hash = GetRandHash();
    receipt.proof_commitment = GetRandHash();

    const std::vector<uint8_t> proof_payload{0xaa, 0xbb, 0xcc, 0xdd};
    const v2proof::SettlementContext context =
        v2proof::DescribeImportedSettlementReceipt(receipt,
                                                   v2proof::PayloadLocation::OFFCHAIN,
                                                   proof_payload);
    BOOST_CHECK(context.IsValid());
    BOOST_CHECK(context.material.statement.domain == v2proof::VerificationDomain::BATCH_SETTLEMENT);
    BOOST_CHECK(context.material.payload_location == v2proof::PayloadLocation::OFFCHAIN);
    BOOST_CHECK(context.material.statement.envelope.proof_kind == shielded::v2::ProofKind::IMPORTED_RECEIPT);
    BOOST_REQUIRE(context.imported_receipt.has_value());
    BOOST_REQUIRE(context.descriptor.has_value());
    BOOST_CHECK(context.descriptor->proof_system_id == receipt.proof_system_id);
    BOOST_CHECK(context.descriptor->verifier_key_hash == receipt.verifier_key_hash);
    BOOST_REQUIRE_EQUAL(context.material.proof_shards.size(), 1U);
    BOOST_CHECK(context.material.proof_shards[0].statement_digest == receipt.statement_hash);
    BOOST_CHECK_EQUAL(context.material.proof_shards[0].proof_payload_size, proof_payload.size());
}

BOOST_AUTO_TEST_CASE(imported_claim_context_records_claim_binding)
{
    shielded::BridgeProofClaim claim;
    claim.kind = shielded::BridgeProofClaimKind::BATCH_TUPLE;
    claim.direction = shielded::BridgeDirection::BRIDGE_OUT;
    claim.statement_hash = GetRandHash();
    claim.entry_count = 12;
    claim.total_amount = 48000;
    claim.batch_root = GetRandHash();
    claim.domain_id = GetRandHash();
    claim.source_epoch = 99;
    claim.data_root = GetRandHash();

    const v2proof::SettlementContext context =
        v2proof::DescribeImportedSettlementClaim(claim,
                                                 v2proof::PayloadLocation::L1_DATA_AVAILABILITY,
                                                 {0x01, 0x02});
    BOOST_CHECK(context.IsValid());
    BOOST_CHECK(context.material.statement.envelope.proof_kind == shielded::v2::ProofKind::IMPORTED_CLAIM);
    BOOST_CHECK(context.material.statement.envelope.settlement_binding_kind ==
                shielded::v2::SettlementBindingKind::BRIDGE_CLAIM);
    BOOST_CHECK(context.material.payload_location == v2proof::PayloadLocation::L1_DATA_AVAILABILITY);
    BOOST_REQUIRE(context.imported_claim.has_value());
    BOOST_CHECK(context.material.proof_shards[0].settlement_domain == claim.domain_id);
    BOOST_CHECK(!context.descriptor.has_value());
}

BOOST_AUTO_TEST_CASE(generic_opaque_imported_receipt_statement_allows_postfork_bridge_shape_without_components)
{
    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = GetRandHash();
    receipt.proof_system_id = GetRandHash();
    receipt.verifier_key_hash = GetRandHash();
    receipt.public_values_hash = GetRandHash();
    receipt.proof_commitment = GetRandHash();

    auto context = v2proof::DescribeImportedSettlementReceipt(receipt,
                                                              v2proof::PayloadLocation::INLINE_WITNESS,
                                                              {0x11, 0x22, 0x33});
    BOOST_REQUIRE(context.IsValid());

    auto statement = context.material.statement;
    statement.envelope.proof_kind = shielded::v2::ProofKind::GENERIC_OPAQUE;
    statement.envelope.settlement_binding_kind = shielded::v2::SettlementBindingKind::GENERIC_POSTFORK;
    BOOST_CHECK(statement.IsValid());
}

BOOST_AUTO_TEST_CASE(native_batch_backend_changes_statement_digest)
{
    const auto statement = MakeFutureProofedBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);

    v2proof::NativeBatchBackend backend_a;
    backend_a.backend_id = uint256{0x91};
    BOOST_REQUIRE(backend_a.IsValid());

    v2proof::NativeBatchBackend backend_b = backend_a;
    backend_b.backend_id = uint256{0x92};
    BOOST_REQUIRE(backend_b.IsValid());

    const auto proof_statement_a = v2proof::DescribeNativeBatchSettlementStatement(statement, backend_a);
    const auto proof_statement_b = v2proof::DescribeNativeBatchSettlementStatement(statement, backend_b);
    BOOST_CHECK(proof_statement_a.IsValid());
    BOOST_CHECK(proof_statement_b.IsValid());
    BOOST_CHECK(proof_statement_a.domain == v2proof::VerificationDomain::BATCH_SETTLEMENT);
    BOOST_CHECK(proof_statement_a.envelope.proof_kind == shielded::v2::ProofKind::BATCH_MATRICT);
    BOOST_CHECK(proof_statement_a.envelope.settlement_binding_kind ==
                shielded::v2::SettlementBindingKind::NATIVE_BATCH);
    BOOST_CHECK(proof_statement_a.envelope.statement_digest != proof_statement_b.envelope.statement_digest);
}

BOOST_AUTO_TEST_CASE(native_batch_statement_binds_future_proofed_aggregate_commitment_digest)
{
    const auto statement = MakeFutureProofedBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 13 * COIN);
    const auto backend = v2proof::DescribeSmileNativeBatchBackend();
    const auto proof_statement = v2proof::DescribeNativeBatchSettlementStatement(statement, backend);
    BOOST_REQUIRE(proof_statement.IsValid());
    BOOST_CHECK(proof_statement.envelope.extension_digest ==
                shielded::ComputeBridgeBatchAggregateCommitmentHash(statement.aggregate_commitment));
}

BOOST_AUTO_TEST_CASE(native_batch_backend_selector_returns_smile_backend)
{
    const auto selected = v2proof::SelectDefaultNativeBatchBackend();
    const auto expected = v2proof::DescribeSmileNativeBatchBackend();

    BOOST_CHECK(selected.IsValid());
    BOOST_CHECK_EQUAL(selected.version, expected.version);
    BOOST_CHECK(selected.backend_id == expected.backend_id);
    BOOST_CHECK(selected.membership_proof_kind == expected.membership_proof_kind);
    BOOST_CHECK(selected.amount_proof_kind == expected.amount_proof_kind);
    BOOST_CHECK(selected.balance_proof_kind == expected.balance_proof_kind);
}

BOOST_AUTO_TEST_CASE(native_batch_backend_resolver_rejects_receipt_backed_supported_envelope)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 17 * COIN);
    const auto backend = v2proof::DescribeReceiptBackedNativeBatchBackend();
    BOOST_REQUIRE(backend.IsValid());
    BOOST_CHECK(backend.membership_proof_kind == shielded::v2::ProofComponentKind::RECEIPT);
    BOOST_CHECK(backend.amount_proof_kind == shielded::v2::ProofComponentKind::RECEIPT);
    BOOST_CHECK(backend.balance_proof_kind == shielded::v2::ProofComponentKind::RECEIPT);

    const auto proof_statement = v2proof::DescribeNativeBatchSettlementStatement(statement, backend);
    BOOST_REQUIRE(proof_statement.IsValid());
    BOOST_CHECK(proof_statement.envelope.proof_kind == shielded::v2::ProofKind::BATCH_MATRICT);
    BOOST_CHECK(proof_statement.envelope.membership_proof_kind ==
                shielded::v2::ProofComponentKind::RECEIPT);
    BOOST_CHECK(proof_statement.envelope.amount_proof_kind ==
                shielded::v2::ProofComponentKind::RECEIPT);
    BOOST_CHECK(proof_statement.envelope.balance_proof_kind ==
                shielded::v2::ProofComponentKind::RECEIPT);

    BOOST_CHECK(!v2proof::ResolveNativeBatchBackend(statement, proof_statement.envelope).has_value());
}

BOOST_AUTO_TEST_CASE(native_batch_backend_resolver_accepts_supported_envelope_and_rejects_unknown_backend)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 13 * COIN);
    const auto backend = v2proof::DescribeSmileNativeBatchBackend();
    const auto proof_statement = v2proof::DescribeNativeBatchSettlementStatement(statement, backend);
    BOOST_REQUIRE(proof_statement.IsValid());

    auto resolved = v2proof::ResolveNativeBatchBackend(statement, proof_statement.envelope);
    BOOST_REQUIRE(resolved.has_value());
    BOOST_CHECK(resolved->backend_id == backend.backend_id);

    v2proof::NativeBatchBackend unknown_backend = backend;
    unknown_backend.backend_id = uint256{0x94};
    BOOST_REQUIRE(unknown_backend.IsValid());

    const auto unknown_statement =
        v2proof::DescribeNativeBatchSettlementStatement(statement, unknown_backend);
    BOOST_REQUIRE(unknown_statement.IsValid());
    BOOST_CHECK(!v2proof::ResolveNativeBatchBackend(statement,
                                                    unknown_statement.envelope).has_value());
}

BOOST_AUTO_TEST_CASE(batch_statement_accepts_netting_manifest_binding)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 11 * COIN);

    v2proof::NativeBatchBackend backend;
    backend.backend_id = uint256{0x93};
    BOOST_REQUIRE(backend.IsValid());

    auto proof_statement = v2proof::DescribeNativeBatchSettlementStatement(statement, backend);
    proof_statement.envelope.settlement_binding_kind = shielded::v2::SettlementBindingKind::NETTING_MANIFEST;

    BOOST_CHECK(proof_statement.IsValid());
    BOOST_CHECK(proof_statement.domain == v2proof::VerificationDomain::BATCH_SETTLEMENT);
}

BOOST_AUTO_TEST_CASE(imported_claim_context_verifies_against_statement)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 8 * COIN);
    const auto claim = shielded::BuildBridgeProofClaimFromStatement(statement,
                                                                    shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    BOOST_REQUIRE(claim.has_value());

    const v2proof::SettlementContext context =
        v2proof::DescribeImportedSettlementClaim(*claim,
                                                 v2proof::PayloadLocation::INLINE_NON_WITNESS,
                                                 {0x11, 0x22});

    v2proof::SettlementWitness witness;
    witness.statement = statement;

    std::string reject_reason;
    BOOST_CHECK(v2proof::VerifySettlementContext(context, witness, reject_reason));

    witness.statement.source_epoch += 1;
    BOOST_CHECK(!v2proof::VerifySettlementContext(context, witness, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-v2-settlement-claim");
}

BOOST_AUTO_TEST_CASE(imported_receipt_context_verifies_proof_receipt_anchor)
{
    const shielded::BridgeProofDescriptor descriptor = MakeProofDescriptor(0xa0);
    const shielded::BridgeProofDescriptor other_descriptor = MakeProofDescriptor(0xa8);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{descriptor, other_descriptor};
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 1);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithProofPolicy(shielded::BridgeDirection::BRIDGE_OUT,
                                                             9 * COIN,
                                                             *proof_policy);
    const auto receipt = MakeProofReceipt(statement, descriptor, 0xaa);
    const v2proof::SettlementContext context =
        v2proof::DescribeImportedSettlementReceipt(receipt,
                                                   v2proof::PayloadLocation::INLINE_WITNESS,
                                                   {0xde, 0xad},
                                                   descriptor);

    v2proof::SettlementWitness witness;
    witness.statement = statement;
    witness.proof_receipts = {receipt};
    witness.descriptor_proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptor);
    BOOST_REQUIRE(witness.descriptor_proof.has_value());

    std::string reject_reason;
    BOOST_CHECK(v2proof::VerifySettlementContext(context, witness, reject_reason));

    witness.descriptor_proof->siblings[0] = GetRandHash();
    BOOST_CHECK(!v2proof::VerifySettlementContext(context, witness, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-v2-settlement-proof-descriptor");
}

BOOST_AUTO_TEST_CASE(imported_receipt_context_rejects_duplicate_proof_receipts)
{
    const shielded::BridgeProofDescriptor descriptor = MakeProofDescriptor(0xa6);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{descriptor};
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 1);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithProofPolicy(shielded::BridgeDirection::BRIDGE_OUT,
                                                             9 * COIN,
                                                             *proof_policy);
    const auto receipt = MakeProofReceipt(statement, descriptor, 0xa7);
    const v2proof::SettlementContext context =
        v2proof::DescribeImportedSettlementReceipt(receipt,
                                                   v2proof::PayloadLocation::INLINE_WITNESS,
                                                   {0xde, 0xad},
                                                   descriptor);

    v2proof::SettlementWitness witness;
    witness.statement = statement;
    witness.proof_receipts = {receipt, receipt};
    witness.descriptor_proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptor);
    BOOST_REQUIRE(witness.descriptor_proof.has_value());

    std::string reject_reason;
    BOOST_CHECK(!v2proof::VerifySettlementContext(context, witness, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-v2-settlement-proof-receipts");
}

BOOST_AUTO_TEST_CASE(imported_receipt_context_accepts_matching_adapter_and_rejects_mismatch)
{
    const auto adapter = MakeProofAdapter(0xae, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto descriptor = shielded::BuildBridgeProofDescriptorFromAdapter(adapter, uint256{0xaf});
    BOOST_REQUIRE(descriptor.has_value());
    const std::vector<shielded::BridgeProofDescriptor> descriptors{*descriptor};
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 1);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithProofPolicy(shielded::BridgeDirection::BRIDGE_OUT,
                                                             9 * COIN,
                                                             *proof_policy);
    const auto receipt =
        shielded::BuildBridgeProofReceiptFromAdapter(statement, adapter, descriptor->verifier_key_hash, uint256{0xb0});
    BOOST_REQUIRE(receipt.has_value());

    const v2proof::SettlementContext context =
        v2proof::DescribeImportedSettlementReceipt(*receipt,
                                                   v2proof::PayloadLocation::INLINE_WITNESS,
                                                   {0xde, 0xad},
                                                   *descriptor);

    v2proof::SettlementWitness witness;
    witness.statement = statement;
    witness.proof_receipts = {*receipt};
    witness.imported_adapters = {adapter};
    witness.descriptor_proof = shielded::BuildBridgeProofPolicyProof(descriptors, *descriptor);
    BOOST_REQUIRE(witness.descriptor_proof.has_value());

    std::string reject_reason;
    BOOST_CHECK(v2proof::VerifySettlementContext(context, witness, reject_reason));

    witness.imported_adapters[0] = MakeProofAdapter(0xb4, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    BOOST_CHECK(!v2proof::VerifySettlementContext(context, witness, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-v2-settlement-receipt-adapter");
}

BOOST_AUTO_TEST_CASE(imported_receipt_context_verifies_hybrid_bundle_and_rejects_bad_membership)
{
    const auto attestors = MakeVerifierSetAttestors(0xb0, 3);
    const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(attestors, 2);
    BOOST_REQUIRE(verifier_set.has_value());

    const shielded::BridgeProofDescriptor descriptor = MakeProofDescriptor(0xc0);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{descriptor};
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 1);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithVerifierSetAndProofPolicy(shielded::BridgeDirection::BRIDGE_OUT,
                                                                           10 * COIN,
                                                                           *verifier_set,
                                                                           *proof_policy);
    const auto signed_receipt_a = MakeSignedBatchReceipt(0xb0, statement);
    const auto signed_receipt_b = MakeSignedBatchReceipt(0xb1, statement);
    const auto proof_receipt = MakeProofReceipt(statement, descriptor, 0xc5);
    const std::vector<shielded::BridgeBatchReceipt> signed_receipts{signed_receipt_a, signed_receipt_b};
    const std::vector<shielded::BridgeProofReceipt> proof_receipts{proof_receipt};
    const auto proof_a = shielded::BuildBridgeVerifierSetProof(attestors, signed_receipt_a.attestor);
    const auto proof_b = shielded::BuildBridgeVerifierSetProof(attestors, signed_receipt_b.attestor);
    BOOST_REQUIRE(proof_a.has_value());
    BOOST_REQUIRE(proof_b.has_value());

    const auto bundle = MakeVerificationBundle(signed_receipts, proof_receipts);
    const v2proof::SettlementContext context =
        v2proof::DescribeImportedSettlementReceipt(proof_receipt,
                                                   v2proof::PayloadLocation::OFFCHAIN,
                                                   {},
                                                   descriptor,
                                                   bundle);

    v2proof::SettlementWitness witness;
    witness.statement = statement;
    witness.signed_receipts = signed_receipts;
    witness.signed_receipt_proofs = {*proof_a, *proof_b};
    witness.proof_receipts = proof_receipts;
    witness.descriptor_proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptor);
    BOOST_REQUIRE(witness.descriptor_proof.has_value());

    std::string reject_reason;
    BOOST_CHECK(v2proof::VerifySettlementContext(context, witness, reject_reason));

    witness.signed_receipt_proofs[1] = witness.signed_receipt_proofs[0];
    BOOST_CHECK(!v2proof::VerifySettlementContext(context, witness, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-v2-settlement-signed-membership");
}

BOOST_AUTO_TEST_CASE(settlement_witness_roundtrip_and_imported_metadata_parse)
{
    const shielded::BridgeProofDescriptor descriptor = MakeProofDescriptor(0xd0);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{descriptor};
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 1);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithProofPolicy(shielded::BridgeDirection::BRIDGE_OUT,
                                                             11 * COIN,
                                                             *proof_policy);
    const auto receipt = MakeProofReceipt(statement, descriptor, 0xd5);
    const auto claim = shielded::BuildBridgeProofClaimFromStatement(statement,
                                                                    shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    BOOST_REQUIRE(claim.has_value());

    v2proof::SettlementWitness witness;
    witness.statement = statement;
    witness.proof_receipts = {receipt};
    witness.descriptor_proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptor);
    BOOST_REQUIRE(witness.descriptor_proof.has_value());

    DataStream witness_stream;
    witness_stream << witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    std::vector<uint8_t> witness_payload(witness_begin, witness_begin + witness_stream.size());

    std::string reject_reason;
    const auto parsed_witness = v2proof::ParseSettlementWitness(witness_payload, reject_reason);
    BOOST_REQUIRE(parsed_witness.has_value());
    BOOST_CHECK(parsed_witness->IsValid());
    BOOST_CHECK(parsed_witness->statement.entry_count == witness.statement.entry_count);
    BOOST_CHECK(parsed_witness->proof_receipts.size() == 1U);

    const auto receipt_context =
        v2proof::DescribeImportedSettlementReceipt(receipt,
                                                   v2proof::PayloadLocation::INLINE_WITNESS,
                                                   witness_payload,
                                                   descriptor);
    const auto parsed_receipt =
        v2proof::ParseImportedSettlementReceipt(receipt_context.material.statement.envelope,
                                                receipt_context.material.proof_shards.front(),
                                                reject_reason);
    BOOST_REQUIRE(parsed_receipt.has_value());
    BOOST_CHECK(shielded::ComputeBridgeProofReceiptHash(*parsed_receipt) ==
                shielded::ComputeBridgeProofReceiptHash(receipt));

    const auto claim_context =
        v2proof::DescribeImportedSettlementClaim(*claim,
                                                 v2proof::PayloadLocation::INLINE_NON_WITNESS,
                                                 {0x11, 0x22});
    const auto parsed_claim =
        v2proof::ParseImportedSettlementClaim(claim_context.material.statement.envelope,
                                              claim_context.material.proof_shards.front(),
                                              reject_reason);
    BOOST_REQUIRE(parsed_claim.has_value());
    BOOST_CHECK(shielded::ComputeBridgeProofClaimHash(*parsed_claim) ==
                shielded::ComputeBridgeProofClaimHash(*claim));

    const auto anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(statement,
                                                                             witness.proof_receipts);
    BOOST_REQUIRE(anchor.has_value());
    BOOST_CHECK(!v2proof::ComputeSettlementExternalAnchorDigest(*anchor).IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
