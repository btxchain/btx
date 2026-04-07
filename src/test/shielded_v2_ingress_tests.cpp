// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <kernel/mempool_options.h>
#include <policy/policy.h>
#include <pqkey.h>
#include <shielded/account_registry.h>
#include <shielded/bundle.h>
#include <shielded/note_encryption.h>
#include <shielded/ringct/ring_selection.h>
#include <shielded/smile2/public_account.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/validation.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_send.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <map>
#include <numeric>
#include <memory>
#include <string>
#include <vector>

namespace {

using shielded::BridgeBatchLeaf;
using shielded::BridgeBatchLeafKind;
using shielded::BridgeBatchStatement;
using shielded::BridgeDirection;
using shielded::BridgeProofDescriptor;
using namespace shielded::v2;

[[nodiscard]] ShieldedNote MakeNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    BOOST_REQUIRE(note.IsValid());
    return note;
}

[[nodiscard]] std::vector<uint64_t> BuildRingPositions()
{
    std::vector<uint64_t> positions;
    positions.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        positions.push_back(i);
    }
    return positions;
}

[[nodiscard]] std::vector<uint256> BuildRingMembers(const shielded::ShieldedMerkleTree& tree,
                                                    const std::vector<uint64_t>& positions)
{
    std::vector<uint256> members;
    members.reserve(positions.size());
    for (const uint64_t pos : positions) {
        const auto commitment = tree.CommitmentAt(pos);
        BOOST_REQUIRE(commitment.has_value());
        members.push_back(*commitment);
    }
    return members;
}

[[nodiscard]] V2SendSpendInput MakeDirectSpendInput(const ShieldedNote& note,
                                                    const std::vector<uint64_t>& ring_positions,
                                                    const std::vector<uint256>& ring_members,
                                                    size_t real_index,
                                                    std::optional<uint256> note_commitment = std::nullopt)
{
    V2SendSpendInput spend_input;
    spend_input.note = note;
    spend_input.note_commitment = note_commitment.value_or(note.GetCommitment());
    spend_input.account_leaf_hint = shielded::registry::MakeDirectSendAccountLeafHint();
    spend_input.ring_positions = ring_positions;
    spend_input.ring_members = ring_members;
    spend_input.real_index = real_index;
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitness(spend_input));
    return spend_input;
}

[[nodiscard]] mlkem::KeyPair BuildRecipientKeyPair(unsigned char seed)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> key_seed{};
    key_seed.fill(seed);
    return mlkem::KeyGenDerand(key_seed);
}

[[nodiscard]] BridgeBatchLeaf MakeBridgeLeaf(unsigned char seed, CAmount amount)
{
    BridgeBatchLeaf leaf;
    leaf.kind = BridgeBatchLeafKind::SHIELD_CREDIT;
    leaf.wallet_id = uint256{seed};
    leaf.destination_id = uint256{static_cast<unsigned char>(seed + 1)};
    leaf.amount = amount;
    leaf.authorization_hash = uint256{static_cast<unsigned char>(seed + 2)};
    BOOST_REQUIRE(leaf.IsValid());
    return leaf;
}

[[nodiscard]] V2IngressLeafInput MakeIngressLeaf(unsigned char seed, CAmount amount, CAmount fee)
{
    V2IngressLeafInput leaf;
    leaf.bridge_leaf = MakeBridgeLeaf(seed, amount);
    leaf.l2_id = uint256{static_cast<unsigned char>(seed + 3)};
    leaf.fee = fee;
    BOOST_REQUIRE(leaf.IsValid());
    return leaf;
}

[[nodiscard]] BridgeProofDescriptor MakeIngressProofDescriptor()
{
    const auto adapter = shielded::BuildCanonicalBridgeProofAdapter(
        shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    BOOST_REQUIRE(adapter.has_value());

    const auto descriptor = shielded::BuildBridgeProofDescriptorFromAdapter(*adapter, uint256{0xb2});
    BOOST_REQUIRE(descriptor.has_value());
    BOOST_REQUIRE(descriptor->IsValid());
    return *descriptor;
}

[[nodiscard]] V2IngressSettlementWitness BuildIngressProofSettlementWitness(const BridgeBatchStatement& statement,
                                                                           unsigned char seed = 0xd1)
{
    const auto descriptor = MakeIngressProofDescriptor();
    std::vector<BridgeProofDescriptor> descriptors{descriptor};

    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    receipt.proof_system_id = descriptor.proof_system_id;
    receipt.verifier_key_hash = descriptor.verifier_key_hash;
    receipt.public_values_hash = uint256{seed};
    receipt.proof_commitment = uint256{static_cast<unsigned char>(seed + 1)};
    BOOST_REQUIRE(receipt.IsValid());

    auto descriptor_proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptor);
    BOOST_REQUIRE(descriptor_proof.has_value());

    V2IngressSettlementWitness witness;
    witness.proof_receipts = {receipt};
    witness.proof_receipt_descriptor_proofs = {*descriptor_proof};
    BOOST_REQUIRE(witness.IsValid());
    return witness;
}

enum class IngressSettlementWitnessKind {
    PROOF_ONLY,
    SIGNED_ONLY,
    HYBRID,
};

struct IngressSettlementContext
{
    BridgeBatchStatement statement;
    V2IngressSettlementWitness witness;
};

[[nodiscard]] shielded::BridgeKeySpec MakeIngressAttestor(unsigned char seed,
                                                          PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);

    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(algo, material));
    return {algo, key.GetPubKey()};
}

[[nodiscard]] shielded::BridgeBatchReceipt MakeIngressSignedReceipt(unsigned char seed,
                                                                    const BridgeBatchStatement& statement,
                                                                    PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);

    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(algo, material));

    shielded::BridgeBatchReceipt receipt;
    receipt.statement = statement;
    receipt.attestor = {algo, key.GetPubKey()};

    const uint256 receipt_hash = shielded::ComputeBridgeBatchReceiptHash(receipt);
    BOOST_REQUIRE(!receipt_hash.IsNull());
    BOOST_REQUIRE(key.Sign(receipt_hash, receipt.signature));
    BOOST_REQUIRE(receipt.IsValid());
    return receipt;
}

[[nodiscard]] IngressSettlementContext BuildIngressSettlementContext(
    const std::vector<V2IngressLeafInput>& ingress_leaves,
    IngressSettlementWitnessKind settlement_kind)
{
    struct AttestorSpec {
        unsigned char seed;
        PQAlgorithm algo;
    };

    const std::array<AttestorSpec, 2> attestor_specs{{
        {0xd1, PQAlgorithm::ML_DSA_44},
        {0xd2, PQAlgorithm::SLH_DSA_128S},
    }};

    std::vector<shielded::BridgeKeySpec> attestors;
    if (settlement_kind != IngressSettlementWitnessKind::PROOF_ONLY) {
        attestors.reserve(attestor_specs.size());
        for (const auto& spec : attestor_specs) {
            attestors.push_back(MakeIngressAttestor(spec.seed, spec.algo));
        }
    }

    std::vector<BridgeProofDescriptor> descriptors;
    if (settlement_kind != IngressSettlementWitnessKind::SIGNED_ONLY) {
        descriptors.push_back(MakeIngressProofDescriptor());
    }

    V2IngressStatementTemplate statement_template;
    statement_template.ids.bridge_id = uint256{0xc1};
    statement_template.ids.operation_id = uint256{0xc2};
    statement_template.domain_id = uint256{0xc3};
    statement_template.source_epoch = 11;
    statement_template.data_root = uint256{0xc4};

    if (!attestors.empty()) {
        const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(
            Span<const shielded::BridgeKeySpec>{attestors.data(), attestors.size()},
            /*required_signers=*/attestors.size());
        BOOST_REQUIRE(verifier_set.has_value());
        statement_template.verifier_set = *verifier_set;
    }

    if (!descriptors.empty()) {
        const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(
            Span<const BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
            /*required_receipts=*/1);
        BOOST_REQUIRE(proof_policy.has_value());
        statement_template.proof_policy = *proof_policy;
    }

    std::string reject_reason;
    auto statement = BuildV2IngressStatement(
        statement_template,
        Span<const V2IngressLeafInput>{ingress_leaves.data(), ingress_leaves.size()},
        reject_reason);
    BOOST_REQUIRE_MESSAGE(statement.has_value(), reject_reason);
    BOOST_REQUIRE(statement->IsValid());
    BOOST_CHECK_EQUAL(statement->version, 5U);
    BOOST_CHECK(statement->aggregate_commitment.action_root == statement->batch_root);
    BOOST_CHECK(statement->aggregate_commitment.data_availability_root == statement->data_root);

    V2IngressSettlementWitness witness;
    if (!attestors.empty()) {
        witness.signed_receipts.reserve(attestors.size());
        witness.signed_receipt_proofs.reserve(attestors.size());
        for (size_t idx = 0; idx < attestor_specs.size(); ++idx) {
            const auto& spec = attestor_specs[idx];
            const auto receipt = MakeIngressSignedReceipt(spec.seed, *statement, spec.algo);
            auto proof = shielded::BuildBridgeVerifierSetProof(
                Span<const shielded::BridgeKeySpec>{attestors.data(), attestors.size()},
                receipt.attestor);
            BOOST_REQUIRE(proof.has_value());
            witness.signed_receipts.push_back(receipt);
            witness.signed_receipt_proofs.push_back(*proof);
        }
    }

    if (!descriptors.empty()) {
        const auto proof_witness = BuildIngressProofSettlementWitness(*statement);
        witness.proof_receipts = proof_witness.proof_receipts;
        witness.proof_receipt_descriptor_proofs = proof_witness.proof_receipt_descriptor_proofs;
    }

    BOOST_REQUIRE(witness.IsValid());
    return {*statement, witness};
}

struct IngressFixture
{
    shielded::ShieldedMerkleTree tree;
    std::map<uint256, smile2::CompactPublicAccount> public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    V2IngressBuildInput input;
    V2IngressBuildResult built;
    const Consensus::Params* consensus{nullptr};
    int32_t validation_height{std::numeric_limits<int32_t>::max()};
};

[[nodiscard]] bool FixtureUsesBoundSmileAnonsetContext(const IngressFixture& fixture)
{
    return fixture.consensus != nullptr &&
           fixture.consensus->IsShieldedMatRiCTDisabled(fixture.validation_height);
}

[[nodiscard]] std::optional<std::vector<smile2::wallet::SmileRingMember>> BuildSharedSmileRingMembers(
    const std::vector<uint256>& ring_members,
    const std::vector<ShieldedNote>& input_notes,
    const std::vector<size_t>& real_indices,
    const std::vector<uint256>& input_chain_commitments,
    const std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
    const std::map<uint256, uint256>& account_leaf_commitments)
{
    if (input_notes.size() != real_indices.size() || input_notes.size() != input_chain_commitments.size()) {
        return std::nullopt;
    }

    std::vector<smile2::wallet::SmileRingMember> members;
    members.reserve(ring_members.size());
    for (const auto& commitment : ring_members) {
        const auto account_it = public_accounts.find(commitment);
        const auto leaf_it = account_leaf_commitments.find(commitment);
        if (account_it == public_accounts.end() || leaf_it == account_leaf_commitments.end()) {
            return std::nullopt;
        }
        auto member = smile2::wallet::BuildRingMemberFromCompactPublicAccount(
            smile2::wallet::SMILE_GLOBAL_SEED,
            commitment,
            account_it->second,
            leaf_it->second);
        if (!member.has_value()) {
            return std::nullopt;
        }
        members.push_back(std::move(*member));
    }

    for (size_t input_idx = 0; input_idx < input_notes.size(); ++input_idx) {
        const auto leaf_it = account_leaf_commitments.find(input_chain_commitments[input_idx]);
        if (leaf_it == account_leaf_commitments.end() ||
            real_indices[input_idx] >= members.size()) {
            return std::nullopt;
        }
        auto member = smile2::wallet::BuildRingMemberFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            input_notes[input_idx],
            input_chain_commitments[input_idx],
            leaf_it->second);
        if (!member.has_value()) {
            return std::nullopt;
        }
        members[real_indices[input_idx]] = std::move(*member);
    }
    return members;
}

[[nodiscard]] std::optional<std::vector<std::vector<std::vector<smile2::wallet::SmileRingMember>>>>
BuildContextualIngressRingMembers(const V2IngressContext& context,
                                  const IngressFixture& fixture,
                                  std::string& reject_reason)
{
    return BuildV2IngressSmileRingMembers(context,
                                          fixture.tree,
                                          fixture.public_accounts,
                                          fixture.account_leaf_commitments,
                                          reject_reason);
}

[[nodiscard]] std::vector<size_t> SelectRealIndices(size_t spend_input_count)
{
    BOOST_REQUIRE_GT(spend_input_count, 0U);
    BOOST_REQUIRE_LE(spend_input_count, shielded::lattice::RING_SIZE);

    std::vector<size_t> indices;
    indices.reserve(spend_input_count);
    for (size_t input_idx = 0; input_idx < spend_input_count; ++input_idx) {
        const size_t index = (2 + input_idx * 5) % shielded::lattice::RING_SIZE;
        BOOST_REQUIRE(std::find(indices.begin(), indices.end(), index) == indices.end());
        indices.push_back(index);
    }
    return indices;
}

[[nodiscard]] std::vector<CAmount> DistributeInputValues(CAmount total, size_t count)
{
    BOOST_REQUIRE_GT(count, 0U);

    std::vector<CAmount> values;
    values.reserve(count);
    CAmount assigned{0};
    for (size_t idx = 0; idx < count; ++idx) {
        const size_t remaining = count - idx;
        const CAmount remaining_total = total - assigned;
        const CAmount value = remaining == 1
            ? remaining_total
            : remaining_total / static_cast<CAmount>(remaining);
        BOOST_REQUIRE_GT(value, 0);
        values.push_back(value);
        assigned += value;
    }
    BOOST_REQUIRE_EQUAL(assigned, total);
    return values;
}

[[nodiscard]] std::vector<V2IngressLeafInput> BuildCanonicalActivationIngressFixtureLeaves()
{
    std::vector<V2IngressLeafInput> ingress_leaves;
    ingress_leaves.push_back(MakeIngressLeaf(/*seed=*/0xe1, /*amount=*/900, /*fee=*/500));
    ingress_leaves.push_back(MakeIngressLeaf(/*seed=*/0xf1, /*amount=*/900, /*fee=*/500));
    return ingress_leaves;
}

[[nodiscard]] std::vector<V2IngressLeafInput> BuildIngressLeafInputs(size_t count,
                                                                     CAmount amount,
                                                                     CAmount fee,
                                                                     unsigned char seed_base = 0x81)
{
    std::vector<V2IngressLeafInput> ingress_leaves;
    ingress_leaves.reserve(count);
    for (size_t leaf_idx = 0; leaf_idx < count; ++leaf_idx) {
        ingress_leaves.push_back(
            MakeIngressLeaf(static_cast<unsigned char>(seed_base + leaf_idx * 0x10),
                            amount,
                            fee));
    }
    return ingress_leaves;
}

[[nodiscard]] IngressFixture BuildIngressFixture(std::vector<CAmount> input_values,
                                                 std::vector<CAmount> reserve_values,
                                                 std::vector<V2IngressLeafInput> ingress_leaves,
                                                 IngressSettlementWitnessKind settlement_kind =
                                                     IngressSettlementWitnessKind::PROOF_ONLY,
                                                 size_t tree_member_count = 0,
                                                 const Consensus::Params* consensus = nullptr,
                                                 int32_t validation_height =
                                                     std::numeric_limits<int32_t>::max());

[[nodiscard]] IngressFixture BuildIngressFixture(size_t spend_input_count,
                                                 std::vector<CAmount> reserve_values,
                                                 std::vector<V2IngressLeafInput> ingress_leaves,
                                                 IngressSettlementWitnessKind settlement_kind =
                                                     IngressSettlementWitnessKind::PROOF_ONLY,
                                                 size_t tree_member_count = 0,
                                                 const Consensus::Params* consensus = nullptr,
                                                 int32_t validation_height =
                                                     std::numeric_limits<int32_t>::max())
{
    const CAmount reserve_total = std::accumulate(reserve_values.begin(), reserve_values.end(), CAmount{0});
    const CAmount ingress_total = std::accumulate(
        ingress_leaves.begin(),
        ingress_leaves.end(),
        CAmount{0},
        [](CAmount total, const V2IngressLeafInput& leaf) {
            return total + leaf.bridge_leaf.amount + leaf.fee;
        });
    return BuildIngressFixture(
        DistributeInputValues(reserve_total + ingress_total, spend_input_count),
        std::move(reserve_values),
        std::move(ingress_leaves),
        settlement_kind,
        tree_member_count,
        consensus,
        validation_height);
}

[[nodiscard]] IngressFixture BuildIngressFixture(std::vector<CAmount> input_values,
                                                 std::vector<CAmount> reserve_values,
                                                 std::vector<V2IngressLeafInput> ingress_leaves,
                                                 IngressSettlementWitnessKind settlement_kind,
                                                 size_t tree_member_count,
                                                 const Consensus::Params* consensus,
                                                 int32_t validation_height)
{
    const std::vector<unsigned char> spending_key(32, 0x42);
    IngressFixture fixture;
    const size_t spend_input_count = input_values.size();
    const size_t reserve_output_count = reserve_values.size();
    const size_t ingress_leaf_count = ingress_leaves.size();
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    const size_t effective_tree_member_count = tree_member_count == 0
        ? (effective_consensus->IsShieldedMatRiCTDisabled(validation_height)
               ? shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE)
               : shielded::lattice::RING_SIZE)
        : tree_member_count;
    fixture.consensus = effective_consensus;
    fixture.validation_height = validation_height;

    BOOST_REQUIRE_GE(effective_tree_member_count, shielded::lattice::RING_SIZE);
    BOOST_REQUIRE_GT(spend_input_count, 0U);
    BOOST_REQUIRE_GT(reserve_output_count, 0U);
    BOOST_REQUIRE_GT(ingress_leaf_count, 0U);
    BOOST_REQUIRE_LE(reserve_output_count, MAX_BATCH_RESERVE_OUTPUTS);
    BOOST_REQUIRE_LE(ingress_leaf_count, MAX_BATCH_LEAVES);
    BOOST_REQUIRE(std::all_of(input_values.begin(), input_values.end(), [](const CAmount value) {
        return value > 0 && MoneyRange(value);
    }));

    fixture.input.ingress_leaves = std::move(ingress_leaves);
    const auto settlement = BuildIngressSettlementContext(fixture.input.ingress_leaves, settlement_kind);
    fixture.input.statement = settlement.statement;
    fixture.input.settlement_witness = settlement.witness;

    const CAmount reserve_total = std::accumulate(reserve_values.begin(), reserve_values.end(), CAmount{0});
    const CAmount ingress_total = std::accumulate(
        fixture.input.ingress_leaves.begin(),
        fixture.input.ingress_leaves.end(),
        CAmount{0},
        [](CAmount total, const V2IngressLeafInput& leaf) {
            return total + leaf.bridge_leaf.amount + leaf.fee;
        });
    BOOST_REQUIRE_EQUAL(
        std::accumulate(input_values.begin(), input_values.end(), CAmount{0}),
        reserve_total + ingress_total);

    const auto real_indices = SelectRealIndices(spend_input_count);
    std::vector<ShieldedNote> input_notes;
    input_notes.reserve(spend_input_count);
    for (size_t input_idx = 0; input_idx < spend_input_count; ++input_idx) {
        input_notes.push_back(MakeNote(input_values[input_idx], static_cast<unsigned char>(0x21 + input_idx * 0x10)));
    }

    std::vector<uint256> input_chain_commitments(spend_input_count);
    fixture.tree = [&]() {
        shielded::ShieldedMerkleTree tree;
        size_t matched_inputs{0};
        for (size_t member_idx = 0; member_idx < effective_tree_member_count; ++member_idx) {
            ShieldedNote ring_note;
            const auto it = std::find(real_indices.begin(), real_indices.end(), member_idx);
            if (it != real_indices.end()) {
                const size_t input_index = static_cast<size_t>(std::distance(real_indices.begin(), it));
                ring_note = input_notes[input_index];
                ++matched_inputs;
            } else {
                ring_note = MakeNote(/*value=*/1100 + static_cast<CAmount>(member_idx) * 17,
                                     static_cast<unsigned char>(0xb1 + member_idx));
            }

            auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
                smile2::wallet::SMILE_GLOBAL_SEED,
                ring_note);
            BOOST_REQUIRE(account.has_value());
            const uint256 chain_commitment = smile2::ComputeCompactPublicAccountHash(*account);
            BOOST_REQUIRE(!chain_commitment.IsNull());
            const auto leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
                ring_note,
                chain_commitment,
                shielded::registry::MakeDirectSendAccountLeafHint());
            BOOST_REQUIRE(leaf_commitment.has_value());
            tree.Append(chain_commitment);
            fixture.public_accounts.emplace(chain_commitment, *account);
            fixture.account_leaf_commitments.emplace(chain_commitment, *leaf_commitment);
            if (it != real_indices.end()) {
                const size_t input_index = static_cast<size_t>(std::distance(real_indices.begin(), it));
                input_chain_commitments[input_index] = chain_commitment;
            }
        }
        BOOST_REQUIRE_EQUAL(matched_inputs, spend_input_count);
        return tree;
    }();

    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(fixture.tree, ring_positions);
    auto smile_ring_members = BuildSharedSmileRingMembers(ring_members,
                                                          input_notes,
                                                          real_indices,
                                                          input_chain_commitments,
                                                          fixture.public_accounts,
                                                          fixture.account_leaf_commitments);
    BOOST_REQUIRE(smile_ring_members.has_value());

    fixture.input.spend_inputs.reserve(spend_input_count);
    for (size_t input_idx = 0; input_idx < spend_input_count; ++input_idx) {
        V2SendSpendInput spend_input = MakeDirectSpendInput(input_notes[input_idx],
                                                            ring_positions,
                                                            ring_members,
                                                            real_indices[input_idx],
                                                            input_chain_commitments[input_idx]);
        spend_input.smile_ring_members = *smile_ring_members;
        fixture.input.spend_inputs.push_back(std::move(spend_input));
    }
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitnesses(fixture.input.spend_inputs));

    fixture.input.reserve_outputs.reserve(reserve_output_count);
    for (size_t output_idx = 0; output_idx < reserve_output_count; ++output_idx) {
        const ShieldedNote reserve_note_template =
            MakeNote(reserve_values[output_idx], static_cast<unsigned char>(0x41 + output_idx * 0x10));
        const mlkem::KeyPair reserve_recipient = BuildRecipientKeyPair(static_cast<unsigned char>(0x51 + output_idx * 0x10));
        std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed{};
        kem_seed.fill(static_cast<unsigned char>(0x61 + output_idx * 0x10));
        std::array<uint8_t, 12> nonce{};
        nonce.fill(static_cast<unsigned char>(0x71 + output_idx * 0x10));
        const auto bound_note = shielded::NoteEncryption::EncryptBoundNoteDeterministic(
            reserve_note_template,
            reserve_recipient.pk,
            kem_seed,
            nonce);
        auto reserve_payload = EncodeLegacyEncryptedNotePayload(
            bound_note.encrypted_note,
            reserve_recipient.pk,
            ScanDomain::RESERVE);
        BOOST_REQUIRE(reserve_payload.has_value());

        V2SendOutputInput reserve_output;
        reserve_output.note_class = NoteClass::RESERVE;
        reserve_output.note = bound_note.note;
        reserve_output.encrypted_note = *reserve_payload;
        fixture.input.reserve_outputs.push_back(std::move(reserve_output));
    }

    BOOST_REQUIRE(fixture.input.statement.IsValid());
    BOOST_REQUIRE_EQUAL(fixture.input.spend_inputs.size(), spend_input_count);
    BOOST_REQUIRE_EQUAL(fixture.input.reserve_outputs.size(), reserve_output_count);
    BOOST_REQUIRE(std::all_of(fixture.input.spend_inputs.begin(),
                              fixture.input.spend_inputs.end(),
                              [](const V2SendSpendInput& spend) { return spend.IsValid(); }));
    BOOST_REQUIRE(std::all_of(fixture.input.reserve_outputs.begin(),
                              fixture.input.reserve_outputs.end(),
                              [](const V2SendOutputInput& output) {
                                  return output.IsValid() &&
                                         output.note_class == NoteClass::RESERVE &&
                                         output.encrypted_note.scan_domain == ScanDomain::OPAQUE;
                              }));
    BOOST_REQUIRE(std::all_of(fixture.input.ingress_leaves.begin(),
                              fixture.input.ingress_leaves.end(),
                              [](const V2IngressLeafInput& leaf) { return leaf.IsValid(); }));
    BOOST_REQUIRE(fixture.input.IsValid());

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 23;

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xA5);
    auto built = BuildV2IngressBatchTransaction(tx_template,
                                                fixture.tree.Root(),
                                                fixture.input,
                                                spending_key,
                                                reject_reason,
                                                Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()},
                                                effective_consensus,
                                                validation_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK(built->IsValid());
    fixture.built = std::move(*built);
    return fixture;
}

[[nodiscard]] IngressFixture BuildIngressFixture(size_t spend_input_count = 1,
                                                 size_t reserve_output_count = 1,
                                                 size_t ingress_leaf_count = 2,
                                                 IngressSettlementWitnessKind settlement_kind =
                                                     IngressSettlementWitnessKind::PROOF_ONLY,
                                                 size_t tree_member_count = 0,
                                                 const Consensus::Params* consensus = nullptr,
                                                 int32_t validation_height =
                                                     std::numeric_limits<int32_t>::max())
{
    const Consensus::Params* effective_consensus = consensus != nullptr ? consensus : &Params().GetConsensus();
    std::vector<CAmount> reserve_values;
    reserve_values.reserve(reserve_output_count);
    for (size_t output_idx = 0; output_idx < reserve_output_count; ++output_idx) {
        reserve_values.push_back(700 + static_cast<CAmount>(output_idx) * 150);
    }
    auto ingress_leaves = BuildIngressLeafInputs(
        ingress_leaf_count,
        /*amount=*/900,
        /*fee=*/40);
    for (size_t leaf_idx = 0; leaf_idx < ingress_leaves.size(); ++leaf_idx) {
        ingress_leaves[leaf_idx].bridge_leaf.amount += static_cast<CAmount>(leaf_idx) * 200;
        ingress_leaves[leaf_idx].fee += static_cast<CAmount>(leaf_idx) * 10;
        ingress_leaves[leaf_idx].fee = shielded::RoundShieldedFeeToCanonicalBucket(ingress_leaves[leaf_idx].fee,
                                                                                    *effective_consensus,
                                                                                    validation_height);
    }
    return BuildIngressFixture(
        spend_input_count,
        std::move(reserve_values),
        std::move(ingress_leaves),
        settlement_kind,
        tree_member_count,
        consensus,
        validation_height);
}

[[nodiscard]] IngressFixture BuildMultiShardIngressFixture()
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    std::vector<CAmount> reserve_values{100, 100};
    auto ingress_leaves = BuildIngressLeafInputs(/*count=*/8, /*amount=*/80, /*fee=*/20, /*seed_base=*/0xa1);
    for (auto& leaf : ingress_leaves) {
        leaf.fee = shielded::RoundShieldedFeeToCanonicalBucket(leaf.fee, consensus, activation_height);
    }
    return BuildIngressFixture(/*spend_input_count=*/2,
                               std::move(reserve_values),
                               std::move(ingress_leaves),
                               IngressSettlementWitnessKind::PROOF_ONLY,
                               /*tree_member_count=*/0,
                               &consensus,
                               activation_height);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_v2_ingress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(build_v2_ingress_transaction_matches_contextual_verifier)
{
    const auto fixture = BuildIngressFixture();
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(bundle->IsValid());
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle, TransactionFamily::V2_INGRESS_BATCH));

    const auto& payload = std::get<IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 1U);
    BOOST_REQUIRE_EQUAL(payload.reserve_outputs.size(), 1U);
    BOOST_REQUIRE_EQUAL(payload.ingress_leaves.size(), 2U);
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards[0].spends.size(), 1U);
    BOOST_CHECK(fixture.built.witness.shards[0].UsesSmileProof());
    BOOST_CHECK_EQUAL(fixture.built.witness.shards[0].spends[0].real_index, 0U);
    BOOST_CHECK(fixture.built.witness.shards[0].spends[0].note_commitment.IsNull());
    const auto expected_account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
        fixture.input.spend_inputs[0].note,
        fixture.input.spend_inputs[0].note_commitment,
        shielded::registry::MakeDirectSendAccountLeafHint());
    BOOST_REQUIRE(expected_account_leaf_commitment.has_value());
    BOOST_CHECK_EQUAL(payload.consumed_spends[0].account_leaf_commitment,
                      *expected_account_leaf_commitment);

    std::string reject_reason;
    auto context = ParseV2IngressProof(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_CHECK(VerifyV2IngressProof(*bundle,
                                     *context,
                                     *ring_members,
                                     reject_reason,
                                     /*reject_rice_codec=*/false,
                                     FixtureUsesBoundSmileAnonsetContext(fixture)));

    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    *fixture.consensus,
                                    fixture.validation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected ingress proof-check failure"));
}

BOOST_AUTO_TEST_CASE(postfork_ingress_builder_uses_generic_wire_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height > 0);

    const auto fixture = BuildIngressFixture(/*spend_input_count=*/1,
                                             /*reserve_output_count=*/1,
                                             /*ingress_leaf_count=*/2,
                                             IngressSettlementWitnessKind::PROOF_ONLY,
                                             shielded::lattice::RING_SIZE,
                                             &consensus,
                                             activation_height);
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK_EQUAL(bundle->header.family_id, TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(bundle->header.proof_envelope.proof_kind, ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle, TransactionFamily::V2_INGRESS_BATCH));
    BOOST_REQUIRE_EQUAL(bundle->output_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(bundle->output_chunks.front().output_count,
                      std::get<IngressBatchPayload>(bundle->payload).reserve_outputs.size());
}

BOOST_AUTO_TEST_CASE(prefork_ingress_builder_omits_wire_output_chunks)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t prefork_height = std::max<int32_t>(1, consensus.nShieldedMatRiCTDisableHeight - 1);

    const auto fixture = BuildIngressFixture(/*spend_input_count=*/1,
                                             /*reserve_output_count=*/1,
                                             /*ingress_leaf_count=*/2,
                                             IngressSettlementWitnessKind::PROOF_ONLY,
                                             shielded::lattice::RING_SIZE,
                                             &consensus,
                                             prefork_height);
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK_EQUAL(bundle->header.family_id, TransactionFamily::V2_INGRESS_BATCH);
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle, TransactionFamily::V2_INGRESS_BATCH));
    BOOST_CHECK(bundle->output_chunks.empty());
    BOOST_CHECK_EQUAL(bundle->header.output_chunk_count, 0U);
    BOOST_CHECK(bundle->header.output_chunk_root.IsNull());
}

BOOST_AUTO_TEST_CASE(postfork_ingress_payload_leaves_use_generic_family)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    BOOST_REQUIRE(activation_height > 0);

    const auto fixture = BuildIngressFixture(/*spend_input_count=*/1,
                                             /*reserve_output_count=*/1,
                                             /*ingress_leaf_count=*/2,
                                             IngressSettlementWitnessKind::PROOF_ONLY,
                                             shielded::lattice::RING_SIZE,
                                             &consensus,
                                             activation_height);
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(std::holds_alternative<IngressBatchPayload>(bundle->payload));

    const auto& payload = std::get<IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE(!payload.ingress_leaves.empty());
    for (const auto& leaf : payload.ingress_leaves) {
        BOOST_CHECK_EQUAL(leaf.family_id, TransactionFamily::V2_GENERIC);
    }
}

BOOST_AUTO_TEST_CASE(proof_check_accepts_v2_ingress_with_canonical_fee_bucket_after_activation)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const auto fixture = BuildIngressFixture(/*spend_input_count=*/1,
                                             std::vector<CAmount>{700},
                                             BuildCanonicalActivationIngressFixtureLeaves(),
                                             IngressSettlementWitnessKind::SIGNED_ONLY,
                                             shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE),
                                             &consensus,
                                             activation_height);
    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    consensus,
                                    activation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_CHECK_MESSAGE(!res.has_value(), res.value_or("unexpected ingress activation failure"));
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_ingress_small_anonymity_pool_after_activation)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const auto fixture = BuildIngressFixture(/*spend_input_count=*/1,
                                             std::vector<CAmount>{700},
                                             BuildCanonicalActivationIngressFixtureLeaves(),
                                             IngressSettlementWitnessKind::PROOF_ONLY,
                                             shielded::lattice::RING_SIZE,
                                             &consensus,
                                             activation_height);
    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    consensus,
                                    activation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-anonymity-pool-size");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_ingress_noncanonical_fee_bucket_after_activation)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    auto ingress_leaves = BuildIngressLeafInputs(/*count=*/2, /*amount=*/900, /*fee=*/40);
    ingress_leaves[1].bridge_leaf.amount += 200;
    ingress_leaves[1].fee += 10;
    const auto fixture = BuildIngressFixture(/*spend_input_count=*/1,
                                             /*reserve_values=*/std::vector<CAmount>{700},
                                             std::move(ingress_leaves),
                                             IngressSettlementWitnessKind::PROOF_ONLY,
                                             shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE),
                                             &consensus,
                                             activation_height);
    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    consensus,
                                    activation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-ingress-fee-bucket");
}

BOOST_AUTO_TEST_CASE(build_v2_ingress_ring_members_rejects_non_redacted_spend_metadata)
{
    const auto fixture = BuildIngressFixture();
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto context = ParseV2IngressProof(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(context->witness.shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(context->witness.shards[0].spends.size(), 1U);

    context->witness.shards[0].spends[0].note_commitment = fixture.input.spend_inputs[0].note.GetCommitment();

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_CHECK(!ring_members.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-ring-positions");
}

BOOST_AUTO_TEST_CASE(parse_v2_ingress_proof_records_default_native_batch_backend)
{
    const auto fixture = BuildIngressFixture();
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto context = ParseV2IngressProof(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    const auto expected_backend = shielded::v2::proof::SelectDefaultNativeBatchBackend();
    BOOST_CHECK(context->backend.IsValid());
    BOOST_CHECK(context->backend.backend_id == expected_backend.backend_id);
    BOOST_CHECK(context->backend.membership_proof_kind == expected_backend.membership_proof_kind);
    BOOST_CHECK(context->backend.amount_proof_kind == expected_backend.amount_proof_kind);
    BOOST_CHECK(context->backend.balance_proof_kind == expected_backend.balance_proof_kind);
}

BOOST_AUTO_TEST_CASE(build_v2_ingress_outputs_bind_smile_accounts)
{
    const auto fixture = BuildIngressFixture();
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    const auto& payload = std::get<IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE(!payload.reserve_outputs.empty());
    for (const auto& output : payload.reserve_outputs) {
        BOOST_REQUIRE(output.smile_account.has_value());
        BOOST_CHECK(smile2::ComputeCompactPublicAccountHash(*output.smile_account) ==
                    output.note_commitment);
    }
}

BOOST_AUTO_TEST_CASE(build_v2_ingress_transaction_rejects_receipt_backed_backend_override)
{
    const auto receipt_backend = shielded::v2::proof::DescribeReceiptBackedNativeBatchBackend();
    BOOST_REQUIRE(receipt_backend.IsValid());
    auto fixture = BuildIngressFixture();
    fixture.input.backend_override = receipt_backend;

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 23;
    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xB7);
    auto rebuilt = BuildV2IngressBatchTransaction(tx_template,
                                                  fixture.tree.Root(),
                                                  fixture.input,
                                                  std::vector<unsigned char>(32, 0x42),
                                                  reject_reason,
                                                  Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_CHECK(!rebuilt.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-ingress-backend");
}

BOOST_AUTO_TEST_CASE(parse_v2_ingress_proof_rejects_unsupported_backend_envelope)
{
    auto fixture = BuildIngressFixture();
    auto& bundle = *fixture.built.tx.shielded_bundle.v2_bundle;

    auto unsupported_backend = shielded::v2::proof::DescribeMatRiCTPlusNativeBatchBackend();
    unsupported_backend.backend_id = uint256{0xee};
    BOOST_REQUIRE(unsupported_backend.IsValid());

    const auto unsupported_statement = shielded::v2::proof::DescribeNativeBatchSettlementStatement(
        fixture.input.statement,
        unsupported_backend);
    BOOST_REQUIRE(unsupported_statement.IsValid());
    bundle.header.proof_envelope = unsupported_statement.envelope;

    std::string reject_reason;
    auto context = ParseV2IngressProof(bundle, reject_reason);
    BOOST_CHECK(!context.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-ingress-backend");
}

BOOST_AUTO_TEST_CASE(build_v2_signed_ingress_transaction_matches_contextual_verifier)
{
    const auto fixture = BuildIngressFixture(/*spend_input_count=*/1,
                                             /*reserve_output_count=*/1,
                                             /*ingress_leaf_count=*/2,
                                             IngressSettlementWitnessKind::SIGNED_ONLY);
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto context = ParseV2IngressProof(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE(context->witness.header.settlement_witness.has_value());
    BOOST_REQUIRE_EQUAL(context->witness.header.settlement_witness->signed_receipts.size(), 2U);
    BOOST_REQUIRE(context->witness.header.statement.verifier_set.IsValid());
    BOOST_CHECK(!context->witness.header.statement.proof_policy.IsValid());

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_CHECK(VerifyV2IngressProof(*bundle,
                                     *context,
                                     *ring_members,
                                     reject_reason,
                                     /*reject_rice_codec=*/false,
                                     FixtureUsesBoundSmileAnonsetContext(fixture)));
}

BOOST_AUTO_TEST_CASE(build_v2_hybrid_ingress_transaction_matches_contextual_verifier)
{
    const auto fixture = BuildIngressFixture(/*spend_input_count=*/2,
                                             /*reserve_output_count=*/1,
                                             /*ingress_leaf_count=*/3,
                                             IngressSettlementWitnessKind::HYBRID);
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    std::string reject_reason;
    auto context = ParseV2IngressProof(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE(context->witness.header.settlement_witness.has_value());
    BOOST_REQUIRE_EQUAL(context->witness.header.settlement_witness->signed_receipts.size(), 2U);
    BOOST_REQUIRE_EQUAL(context->witness.header.settlement_witness->proof_receipts.size(), 1U);
    BOOST_REQUIRE(context->witness.header.statement.verifier_set.IsValid());
    BOOST_REQUIRE(context->witness.header.statement.proof_policy.IsValid());

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_CHECK(VerifyV2IngressProof(*bundle,
                                     *context,
                                     *ring_members,
                                     reject_reason,
                                     /*reject_rice_codec=*/false,
                                     FixtureUsesBoundSmileAnonsetContext(fixture)));
}

BOOST_AUTO_TEST_CASE(build_large_v2_ingress_transaction_matches_contextual_verifier)
{
    const auto fixture = BuildIngressFixture(/*spend_input_count=*/2,
                                             /*reserve_output_count=*/3,
                                             /*ingress_leaf_count=*/5);
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(bundle->IsValid());
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle, TransactionFamily::V2_INGRESS_BATCH));

    const auto& payload = std::get<IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.reserve_outputs.size(), 3U);
    BOOST_REQUIRE_EQUAL(payload.ingress_leaves.size(), 5U);
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards[0].spends.size(), 2U);
    BOOST_REQUIRE(fixture.built.witness.shards[0].smile_witness.has_value());
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards[0].smile_witness->reserve_output_count, 3U);
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards[0].smile_witness->leaf_count, 5U);
    BOOST_CHECK(!fixture.built.witness.shards[0].smile_witness->smile_proof_bytes.empty());

    std::string reject_reason;
    auto context = ParseV2IngressProof(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(ring_members->size(), 1U);
    BOOST_REQUIRE_EQUAL((*ring_members)[0].size(), 2U);
    BOOST_CHECK(VerifyV2IngressProof(*bundle,
                                     *context,
                                     *ring_members,
                                     reject_reason,
                                     /*reject_rice_codec=*/false,
                                     FixtureUsesBoundSmileAnonsetContext(fixture)));

    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    *fixture.consensus,
                                    fixture.validation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(build_multishard_v2_ingress_transaction_matches_contextual_verifier)
{
    const auto fixture = BuildMultiShardIngressFixture();
    const auto* bundle = fixture.built.tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(bundle->IsValid());
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle, TransactionFamily::V2_INGRESS_BATCH));

    const auto& payload = std::get<IngressBatchPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.reserve_outputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(payload.ingress_leaves.size(), 8U);
    BOOST_REQUIRE_EQUAL(bundle->proof_shards.size(), 2U);
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards.size(), 2U);
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards[0].spends.size(), 1U);
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards[1].spends.size(), 1U);
    BOOST_REQUIRE(fixture.built.witness.shards[0].smile_witness.has_value());
    BOOST_REQUIRE(fixture.built.witness.shards[1].smile_witness.has_value());
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards[0].smile_witness->reserve_output_count +
                            fixture.built.witness.shards[1].smile_witness->reserve_output_count,
                        payload.reserve_outputs.size());
    BOOST_REQUIRE_EQUAL(fixture.built.witness.shards[0].smile_witness->leaf_count +
                            fixture.built.witness.shards[1].smile_witness->leaf_count,
                        payload.ingress_leaves.size());
    BOOST_CHECK(!fixture.built.witness.shards[0].smile_witness->smile_proof_bytes.empty());
    BOOST_CHECK(!fixture.built.witness.shards[1].smile_witness->smile_proof_bytes.empty());
    BOOST_REQUIRE_EQUAL(bundle->proof_shards[0].first_leaf_index, 0U);
    BOOST_REQUIRE_EQUAL(bundle->proof_shards[1].first_leaf_index, bundle->proof_shards[0].leaf_count);
    BOOST_REQUIRE_EQUAL(bundle->proof_shards[0].leaf_count + bundle->proof_shards[1].leaf_count,
                        payload.ingress_leaves.size());

    std::string reject_reason;
    auto context = ParseV2IngressProof(*bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(context->witness.shards.size(), 2U);

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(ring_members->size(), 2U);
    BOOST_REQUIRE_EQUAL((*ring_members)[0].size(), 1U);
    BOOST_REQUIRE_EQUAL((*ring_members)[1].size(), 1U);
    BOOST_CHECK(VerifyV2IngressProof(*bundle,
                                     *context,
                                     *ring_members,
                                     reject_reason,
                                     /*reject_rice_codec=*/false,
                                     FixtureUsesBoundSmileAnonsetContext(fixture)));

    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    *fixture.consensus,
                                    fixture.validation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_CHECK(!res.has_value());
}

BOOST_AUTO_TEST_CASE(canonical_ingress_shard_plan_accepts_wallet_shaped_change_partition)
{
    const auto ingress_leaves = BuildIngressLeafInputs(/*count=*/8, /*amount=*/40, /*fee=*/10, /*seed_base=*/0xc1);

    const std::vector<CAmount> schedulable_spends{400, 600};
    const std::vector<CAmount> schedulable_reserves{200, 200, 200};
    BOOST_CHECK(CanBuildCanonicalV2IngressShardPlan(
        Span<const CAmount>{schedulable_spends.data(), schedulable_spends.size()},
        Span<const CAmount>{schedulable_reserves.data(), schedulable_reserves.size()},
        Span<const V2IngressLeafInput>{ingress_leaves.data(), ingress_leaves.size()}));

    const std::vector<CAmount> unschedulable_spends{400, 400};
    BOOST_CHECK(!CanBuildCanonicalV2IngressShardPlan(
        Span<const CAmount>{unschedulable_spends.data(), unschedulable_spends.size()},
        Span<const CAmount>{schedulable_reserves.data(), schedulable_reserves.size()},
        Span<const V2IngressLeafInput>{ingress_leaves.data(), ingress_leaves.size()}));
}

BOOST_AUTO_TEST_CASE(build_v2_ingress_transaction_stays_within_standard_policy_weight_for_single_input_batch)
{
    const auto fixture = BuildIngressFixture();
    const CTransaction tx{fixture.built.tx};

    const int64_t policy_weight = GetShieldedPolicyWeight(tx);
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_SHIELDED_POLICY_WEIGHT);
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT);

    kernel::MemPoolOptions opts;
    std::string reason;
    BOOST_CHECK(IsStandardTx(tx, opts, reason));
    BOOST_CHECK(reason.empty());
}

BOOST_AUTO_TEST_CASE(build_v2_ingress_transaction_requires_statement_bound_settlement_witness)
{
    auto fixture = BuildIngressFixture();
    fixture.input.settlement_witness.reset();

    std::string reject_reason;
    auto rebuilt = BuildV2IngressBatchTransaction(CMutableTransaction{},
                                                  fixture.tree.Root(),
                                                  fixture.input,
                                                  std::vector<unsigned char>(32, 0x42),
                                                  reject_reason);
    BOOST_CHECK(!rebuilt.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-ingress-builder-input");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_ingress_proof_descriptor_membership_mismatch)
{
    auto fixture = BuildIngressFixture();
    auto& bundle = *fixture.built.tx.shielded_bundle.v2_bundle;

    std::string reject_reason;
    auto context = ParseV2IngressProof(bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE(context->witness.header.settlement_witness.has_value());
    ++context->witness.header.settlement_witness->proof_receipt_descriptor_proofs[0].leaf_index;

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_CHECK(!VerifyV2IngressProof(bundle,
                                      *context,
                                      *ring_members,
                                      reject_reason,
                                      /*reject_rice_codec=*/false,
                                      FixtureUsesBoundSmileAnonsetContext(fixture)));
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-ingress-proof-descriptor");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_ingress_signed_receipt_membership_mismatch)
{
    auto fixture = BuildIngressFixture(/*spend_input_count=*/1,
                                       /*reserve_output_count=*/1,
                                       /*ingress_leaf_count=*/2,
                                       IngressSettlementWitnessKind::SIGNED_ONLY);
    auto& bundle = *fixture.built.tx.shielded_bundle.v2_bundle;

    std::string reject_reason;
    auto context = ParseV2IngressProof(bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE(context->witness.header.settlement_witness.has_value());
    ++context->witness.header.settlement_witness->signed_receipt_proofs[0].leaf_index;

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_CHECK(!VerifyV2IngressProof(bundle,
                                      *context,
                                      *ring_members,
                                      reject_reason,
                                      /*reject_rice_codec=*/false,
                                      FixtureUsesBoundSmileAnonsetContext(fixture)));
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-ingress-signed-membership");
}

BOOST_AUTO_TEST_CASE(smile_ingress_account_leaf_substitution_requires_reproof)
{
    auto fixture = BuildIngressFixture(/*spend_input_count=*/2,
                                       /*reserve_output_count=*/1,
                                       /*ingress_leaf_count=*/2);
    auto& bundle = *fixture.built.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<IngressBatchPayload>(bundle.payload);
    BOOST_REQUIRE_EQUAL(payload.consumed_spends.size(), 2U);

    payload.consumed_spends[0].account_leaf_commitment =
        payload.consumed_spends[1].account_leaf_commitment;
    payload.consumed_spends[0].account_registry_proof =
        payload.consumed_spends[1].account_registry_proof;
    bundle.header.payload_digest = ComputeIngressBatchPayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());

    std::string reject_reason;
    auto context = ParseV2IngressProof(bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    auto ring_members = BuildContextualIngressRingMembers(*context, fixture, reject_reason);
    BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
    BOOST_CHECK(!VerifyV2IngressProof(bundle,
                                      *context,
                                      *ring_members,
                                      reject_reason,
                                      /*reject_rice_codec=*/false,
                                      FixtureUsesBoundSmileAnonsetContext(fixture)));
    BOOST_CHECK_EQUAL(reject_reason, "bad-smile2-proof-invalid");

    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    *fixture.consensus,
                                    fixture.validation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-smile2-proof-invalid");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_ingress_binding_mismatch)
{
    auto fixture = BuildIngressFixture();
    auto& bundle = *fixture.built.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<IngressBatchPayload>(bundle.payload);
    payload.settlement_binding_digest = uint256{0xaa};
    bundle.header.payload_digest = ComputeIngressBatchPayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());

    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    *fixture.consensus,
                                    fixture.validation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-ingress-binding");
}

BOOST_AUTO_TEST_CASE(proof_check_rejects_v2_ingress_credit_commitment_mismatch)
{
    auto fixture = BuildIngressFixture();
    auto& bundle = *fixture.built.tx.shielded_bundle.v2_bundle;
    auto& payload = std::get<IngressBatchPayload>(bundle.payload);
    payload.ingress_leaves[0].amount_commitment = uint256{0xbb};
    payload.ingress_root = ComputeBatchLeafRoot(
        Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    payload.l2_credit_root = ComputeV2IngressL2CreditRoot(
        Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    bundle.header.payload_digest = ComputeIngressBatchPayloadDigest(payload);
    BOOST_REQUIRE(bundle.IsValid());

    const CTransaction tx{fixture.built.tx};
    CShieldedProofCheck proof_check(tx,
                                    *fixture.consensus,
                                    fixture.validation_height,
                                    std::make_shared<shielded::ShieldedMerkleTree>(fixture.tree),
                                    std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(
                                        fixture.public_accounts),
                                    std::make_shared<std::map<uint256, uint256>>(
                                        fixture.account_leaf_commitments));
    const auto res = proof_check();
    BOOST_REQUIRE(res.has_value());
    BOOST_CHECK_EQUAL(*res, "bad-shielded-v2-ingress-credit");
}

BOOST_AUTO_TEST_SUITE_END()
