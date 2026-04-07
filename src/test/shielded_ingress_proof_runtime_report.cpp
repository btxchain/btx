// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_ingress_proof_runtime_report.h>

#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <chainparams.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <policy/policy.h>
#include <shielded/account_registry.h>
#include <shielded/bundle.h>
#include <shielded/note_encryption.h>
#include <shielded/ringct/ring_selection.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/validation.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_send.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <streams.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace btx::test::ingress {
namespace {

using shielded::BridgeBatchLeaf;
using shielded::BridgeBatchLeafKind;
using shielded::BridgeBatchStatement;
using shielded::BridgeProofDescriptor;
using shielded::ShieldedMerkleTree;
using shielded::v2::MAX_BATCH_LEAVES;
using shielded::v2::MAX_BATCH_RESERVE_OUTPUTS;
using shielded::v2::MAX_PROOF_PAYLOAD_BYTES;
using shielded::v2::MAX_PROOF_SHARDS;
using shielded::v2::MAX_SETTLEMENT_REFS;
using shielded::v2::BatchLeaf;
using shielded::v2::OutputDescription;
using shielded::v2::V2IngressBuildInput;
using shielded::v2::V2IngressBuildResult;
using shielded::v2::V2IngressLeafInput;
using shielded::v2::V2IngressSettlementWitness;
using shielded::v2::V2IngressShardSchedule;
using shielded::v2::V2IngressStatementTemplate;
using shielded::v2::V2SendOutputInput;
using shielded::v2::V2SendSpendInput;

struct ScenarioInput
{
    std::vector<CAmount> spend_values;
    std::vector<CAmount> reserve_values;
    std::vector<V2IngressLeafInput> ingress_leaves;
};

struct RuntimeFixture
{
    ShieldedMerkleTree tree;
    std::map<uint256, smile2::CompactPublicAccount> public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    V2IngressBuildInput input;
    V2IngressShardSchedule schedule;
};

struct MeasuredTxMetrics
{
    uint64_t serialized_size_bytes{0};
    uint64_t tx_weight{0};
    int64_t shielded_policy_weight{0};
    uint64_t proof_payload_size{0};
    uint64_t proof_shard_count{0};
    ShieldedResourceUsage usage{};
    uint64_t max_transactions_by_serialized_size{0};
    uint64_t max_transactions_by_weight{0};
    uint64_t max_transactions_by_verify{0};
    uint64_t max_transactions_by_scan{0};
    uint64_t max_transactions_by_tree_update{0};
    uint64_t max_transactions_per_block{0};
    uint64_t max_spend_inputs_per_block{0};
    uint64_t max_reserve_outputs_per_block{0};
    uint64_t max_ingress_leaves_per_block{0};
    std::string block_binding_limit;
    bool within_standard_policy_weight{false};
    int64_t standard_policy_weight_headroom{0};
    uint64_t max_transactions_by_standard_policy_weight{0};
};

const char* GetRuntimeBackendName(ProofRuntimeBackendKind backend_kind)
{
    switch (backend_kind) {
    case ProofRuntimeBackendKind::SMILE:
        return "smile";
    case ProofRuntimeBackendKind::MATRICT_PLUS:
        return "matrict_plus";
    case ProofRuntimeBackendKind::RECEIPT_BACKED:
        return "receipt_backed";
    }
    throw std::runtime_error("unknown ingress proof runtime backend");
}

shielded::v2::proof::NativeBatchBackend ResolveRuntimeBackend(ProofRuntimeBackendKind backend_kind)
{
    switch (backend_kind) {
    case ProofRuntimeBackendKind::SMILE:
        return shielded::v2::proof::DescribeSmileNativeBatchBackend();
    case ProofRuntimeBackendKind::MATRICT_PLUS:
        return shielded::v2::proof::DescribeMatRiCTPlusNativeBatchBackend();
    case ProofRuntimeBackendKind::RECEIPT_BACKED:
        return shielded::v2::proof::DescribeReceiptBackedNativeBatchBackend();
    }
    throw std::runtime_error("unknown ingress proof runtime backend");
}

size_t GetRuntimeMaxOutputsPerProofShard(ProofRuntimeBackendKind backend_kind)
{
    return shielded::v2::GetMaxIngressOutputsPerProofShard(ResolveRuntimeBackend(backend_kind));
}

uint256 DeterministicUint256(std::string_view tag, uint64_t index)
{
    HashWriter hw;
    hw << std::string{tag} << index;
    return hw.GetSHA256();
}

ShieldedNote MakeNote(CAmount value, std::string_view tag, uint64_t index)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = DeterministicUint256(std::string{tag} + "_pkh", index);
    note.rho = DeterministicUint256(std::string{tag} + "_rho", index);
    note.rcm = DeterministicUint256(std::string{tag} + "_rcm", index);
    if (!note.IsValid()) {
        throw std::runtime_error("constructed invalid shielded note");
    }
    return note;
}

mlkem::KeyPair BuildRecipientKeyPair(uint64_t index)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> seed{};
    seed.fill(static_cast<uint8_t>(0x51 + (index % 173)));
    return mlkem::KeyGenDerand(seed);
}

shielded::EncryptedNote BuildEncryptedNote(const ShieldedNote& note,
                                           const mlkem::PublicKey& recipient_pk,
                                           uint64_t index)
{
    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed{};
    kem_seed.fill(static_cast<uint8_t>(0x61 + (index % 149)));
    std::array<uint8_t, 12> nonce{};
    nonce.fill(static_cast<uint8_t>(0x71 + (index % 127)));
    return shielded::NoteEncryption::EncryptDeterministic(note, recipient_pk, kem_seed, nonce);
}

BridgeBatchLeaf BuildBridgeLeaf(uint64_t index)
{
    BridgeBatchLeaf leaf;
    leaf.kind = BridgeBatchLeafKind::SHIELD_CREDIT;
    leaf.wallet_id = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_WALLET", index);
    leaf.destination_id = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_DEST", index);
    leaf.amount = 100 + static_cast<CAmount>(index % 17);
    leaf.authorization_hash = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_AUTH", index);
    return leaf;
}

V2IngressLeafInput BuildIngressLeaf(uint64_t index)
{
    V2IngressLeafInput leaf;
    leaf.bridge_leaf = BuildBridgeLeaf(index);
    leaf.l2_id = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_L2", index);
    leaf.fee = shielded::SHIELDED_PRIVACY_FEE_QUANTUM * (1 + static_cast<CAmount>(index % 3));
    if (!leaf.IsValid()) {
        throw std::runtime_error("constructed invalid ingress leaf");
    }
    return leaf;
}

std::vector<V2IngressLeafInput> BuildIngressLeaves(size_t leaf_count)
{
    std::vector<V2IngressLeafInput> leaves;
    leaves.reserve(leaf_count);
    for (size_t i = 0; i < leaf_count; ++i) {
        leaves.push_back(BuildIngressLeaf(i));
    }
    return leaves;
}

std::vector<CAmount> BuildReserveValues(size_t reserve_output_count)
{
    std::vector<CAmount> reserve_values;
    reserve_values.reserve(reserve_output_count);
    for (size_t i = 0; i < reserve_output_count; ++i) {
        reserve_values.push_back(250 + static_cast<CAmount>(i % 11) * 7);
    }
    return reserve_values;
}

CAmount ComputeLeafValue(const V2IngressLeafInput& leaf)
{
    return leaf.bridge_leaf.amount + leaf.fee;
}

std::vector<std::pair<size_t, size_t>> BuildShardOutputLayout(size_t reserve_output_count,
                                                              size_t leaf_count,
                                                              size_t max_outputs_per_proof_shard)
{
    std::vector<std::pair<size_t, size_t>> layout;
    size_t remaining_reserves = reserve_output_count;
    size_t remaining_leaves = leaf_count;

    while (remaining_leaves > 0) {
        const size_t reserve_this = std::min<size_t>(
            remaining_reserves,
            max_outputs_per_proof_shard - 1);
        const size_t leaf_capacity = max_outputs_per_proof_shard - reserve_this;
        const size_t leaves_this = std::min(remaining_leaves, leaf_capacity);
        if (leaves_this == 0) {
            throw std::runtime_error("unable to assign ingress leaves to shard layout");
        }
        layout.emplace_back(reserve_this, leaves_this);
        remaining_reserves -= reserve_this;
        remaining_leaves -= leaves_this;
    }

    if (remaining_reserves != 0) {
        throw std::runtime_error("reserve outputs exceed current proof-shard capacity");
    }
    return layout;
}

ScenarioInput BuildScenario(size_t reserve_output_count,
                            size_t leaf_count,
                            ProofRuntimeBackendKind backend_kind)
{
    if (reserve_output_count == 0) {
        throw std::runtime_error("reserve_output_count must be greater than zero");
    }
    if (reserve_output_count > MAX_BATCH_RESERVE_OUTPUTS) {
        throw std::runtime_error("reserve_output_count exceeds MAX_BATCH_RESERVE_OUTPUTS");
    }
    if (leaf_count == 0) {
        throw std::runtime_error("leaf_count must be greater than zero");
    }
    if (leaf_count > MAX_BATCH_LEAVES) {
        throw std::runtime_error("leaf_count exceeds MAX_BATCH_LEAVES");
    }
    if (GetRuntimeMaxOutputsPerProofShard(backend_kind) == 0) {
        throw std::runtime_error("unsupported backend for ingress proof runtime scenario");
    }

    ScenarioInput scenario;
    scenario.reserve_values = BuildReserveValues(reserve_output_count);
    scenario.ingress_leaves = BuildIngressLeaves(leaf_count);

    const auto layout = BuildShardOutputLayout(
        reserve_output_count,
        leaf_count,
        GetRuntimeMaxOutputsPerProofShard(backend_kind));
    scenario.spend_values.reserve(layout.size());

    size_t reserve_index{0};
    size_t leaf_index{0};
    for (const auto& [reserve_count, shard_leaf_count] : layout) {
        CAmount spend_value{0};
        for (size_t i = 0; i < reserve_count; ++i) {
            spend_value += scenario.reserve_values[reserve_index + i];
        }
        for (size_t i = 0; i < shard_leaf_count; ++i) {
            spend_value += ComputeLeafValue(scenario.ingress_leaves[leaf_index + i]);
        }
        scenario.spend_values.push_back(spend_value);
        reserve_index += reserve_count;
        leaf_index += shard_leaf_count;
    }

    return scenario;
}

BridgeProofDescriptor MakeProofDescriptor()
{
    const auto adapter = shielded::BuildCanonicalBridgeProofAdapter(
        shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    if (!adapter.has_value()) {
        throw std::runtime_error("failed to build canonical ingress proof adapter");
    }
    const auto descriptor = shielded::BuildBridgeProofDescriptorFromAdapter(
        *adapter,
        DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_VERIFIER_KEY", 0));
    if (!descriptor.has_value()) {
        throw std::runtime_error("constructed invalid proof descriptor");
    }
    return *descriptor;
}

shielded::BridgeProofPolicyProof BuildProofDescriptorProof(const BridgeProofDescriptor& descriptor)
{
    const std::vector<BridgeProofDescriptor> descriptors{descriptor};
    auto descriptor_proof = shielded::BuildBridgeProofPolicyProof(
        Span<const BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
        descriptor);
    if (!descriptor_proof.has_value()) {
        throw std::runtime_error("failed to build proof policy proof");
    }
    return *descriptor_proof;
}

V2IngressSettlementWitness BuildProofSettlementWitness(const BridgeBatchStatement& statement)
{
    const auto descriptor = MakeProofDescriptor();
    const auto descriptor_proof = BuildProofDescriptorProof(descriptor);

    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    receipt.proof_system_id = descriptor.proof_system_id;
    receipt.verifier_key_hash = descriptor.verifier_key_hash;
    receipt.public_values_hash = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_PUBLIC_VALUES", 0);
    receipt.proof_commitment = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_PROOF_COMMITMENT", 0);
    if (!receipt.IsValid()) {
        throw std::runtime_error("constructed invalid proof receipt");
    }

    V2IngressSettlementWitness witness;
    witness.proof_receipts = {receipt};
    witness.proof_receipt_descriptor_proofs = {descriptor_proof};
    if (!witness.IsValid()) {
        throw std::runtime_error("constructed invalid settlement witness");
    }
    return witness;
}

BridgeBatchStatement BuildStatement(Span<const V2IngressLeafInput> ingress_leaves)
{
    const auto descriptor = MakeProofDescriptor();
    const std::vector<BridgeProofDescriptor> descriptors{descriptor};
    auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(
        Span<const BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
        /*required_receipts=*/1);
    if (!proof_policy.has_value()) {
        throw std::runtime_error("failed to build proof policy commitment");
    }

    V2IngressStatementTemplate statement_template;
    statement_template.ids.bridge_id = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_BRIDGE", 0);
    statement_template.ids.operation_id = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_OPERATION", 0);
    statement_template.domain_id = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_DOMAIN", 0);
    statement_template.source_epoch = 17;
    statement_template.data_root = DeterministicUint256("BTX_INGRESS_PROOF_RUNTIME_DATA_ROOT", 0);
    statement_template.proof_policy = *proof_policy;

    std::string reject_reason;
    auto statement = shielded::v2::BuildV2IngressStatement(statement_template, ingress_leaves, reject_reason);
    if (!statement.has_value()) {
        throw std::runtime_error("failed to build ingress statement: " + reject_reason);
    }
    return *statement;
}

std::vector<unsigned char> BuildRuntimeSpendingKey()
{
    return std::vector<unsigned char>(32, 0x42);
}

std::vector<unsigned char> BuildRuntimeEntropy()
{
    return std::vector<unsigned char>(32, 0xA5);
}

ShieldedMerkleTree BuildTree(Span<const ShieldedNote> input_notes,
                             Span<const size_t> real_indices,
                             std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
                             std::map<uint256, uint256>& account_leaf_commitments,
                             std::vector<uint256>& input_chain_commitments)
{
    ShieldedMerkleTree tree;
    size_t matched_inputs{0};
    const size_t target_tree_size = std::max<size_t>(
        shielded::lattice::RING_SIZE,
        shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE));
    for (size_t ring_index = 0; ring_index < target_tree_size; ++ring_index) {
        ShieldedNote ring_note;
        const auto it = ring_index < shielded::lattice::RING_SIZE
            ? std::find(real_indices.begin(), real_indices.end(), ring_index)
            : real_indices.end();
        if (it != real_indices.end()) {
            const size_t input_index = static_cast<size_t>(std::distance(real_indices.begin(), it));
            ring_note = input_notes[input_index];
            ++matched_inputs;
        } else {
            ring_note = MakeNote(1100 + static_cast<CAmount>(ring_index) * 17,
                                 "BTX_INGRESS_PROOF_RUNTIME_RING_MEMBER",
                                 static_cast<uint64_t>(ring_index));
        }
        auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            ring_note);
        if (!account.has_value()) {
            throw std::runtime_error("failed to build SMILE compact public account for ingress runtime ring member");
        }
        const uint256 chain_commitment = smile2::ComputeCompactPublicAccountHash(*account);
        const auto leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
            ring_note,
            chain_commitment,
            shielded::registry::MakeDirectSendAccountLeafHint());
        if (!leaf_commitment.has_value()) {
            throw std::runtime_error("failed to build ingress runtime account leaf commitment");
        }
        tree.Append(chain_commitment);
        public_accounts.emplace(chain_commitment, *account);
        account_leaf_commitments.emplace(chain_commitment, *leaf_commitment);
        if (it != real_indices.end()) {
            const size_t input_index = static_cast<size_t>(std::distance(real_indices.begin(), it));
            input_chain_commitments[input_index] = chain_commitment;
        }
    }
    if (matched_inputs != input_notes.size()) {
        throw std::runtime_error("failed to place all ingress runtime real ring members");
    }
    return tree;
}

std::vector<size_t> SelectRealIndices(size_t spend_input_count)
{
    if (spend_input_count == 0 || spend_input_count > shielded::lattice::RING_SIZE) {
        throw std::runtime_error("invalid ingress runtime spend input count");
    }

    std::vector<size_t> indices;
    indices.reserve(spend_input_count);
    for (size_t input_idx = 0; input_idx < spend_input_count; ++input_idx) {
        const size_t index = (2 + input_idx * 5) % shielded::lattice::RING_SIZE;
        if (std::find(indices.begin(), indices.end(), index) != indices.end()) {
            throw std::runtime_error("duplicate ingress runtime real index");
        }
        indices.push_back(index);
    }
    return indices;
}

std::vector<uint64_t> BuildRingPositions()
{
    std::vector<uint64_t> positions;
    positions.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        positions.push_back(i);
    }
    return positions;
}

std::vector<uint256> BuildRingMembers(const ShieldedMerkleTree& tree,
                                      Span<const uint64_t> positions)
{
    std::vector<uint256> members;
    members.reserve(positions.size());
    for (const uint64_t pos : positions) {
        const auto commitment = tree.CommitmentAt(pos);
        if (!commitment.has_value()) {
            throw std::runtime_error("missing ring commitment");
        }
        members.push_back(*commitment);
    }
    return members;
}

std::optional<std::vector<smile2::wallet::SmileRingMember>> BuildSharedSmileRingMembers(
    Span<const uint256> ring_members,
    Span<const ShieldedNote> input_notes,
    Span<const size_t> real_indices,
    Span<const uint256> input_chain_commitments,
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
        if (leaf_it == account_leaf_commitments.end() || real_indices[input_idx] >= members.size()) {
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

std::vector<Nullifier> BuildNullifiers(Span<const V2SendSpendInput> spend_inputs,
                                       Span<const unsigned char> spending_key)
{
    std::vector<Nullifier> nullifiers;
    nullifiers.reserve(spend_inputs.size());
    for (const auto& spend_input : spend_inputs) {
        uint256 nullifier;
        if (!shielded::ringct::DeriveInputNullifierForNote(nullifier,
                                                           spending_key,
                                                           spend_input.note,
                                                           spend_input.ring_members[spend_input.real_index])) {
            throw std::runtime_error("failed to derive ingress runtime nullifier");
        }
        nullifiers.push_back(nullifier);
    }
    return nullifiers;
}

std::vector<OutputDescription> BuildPayloadReserveOutputs(const BridgeBatchStatement& statement,
                                                          Span<const V2SendOutputInput> reserve_outputs)
{
    const uint256 statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    if (statement_hash.IsNull()) {
        throw std::runtime_error("failed to compute ingress runtime statement hash");
    }

    std::vector<OutputDescription> payload_reserves;
    payload_reserves.reserve(reserve_outputs.size());
    for (size_t output_index = 0; output_index < reserve_outputs.size(); ++output_index) {
        const auto& reserve_output = reserve_outputs[output_index];
        auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            reserve_output.note);
        if (!smile_account.has_value()) {
            throw std::runtime_error("failed to build ingress runtime reserve smile account");
        }
        OutputDescription output;
        output.note_class = reserve_output.note_class;
        output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        output.value_commitment = shielded::v2::ComputeV2IngressPlaceholderReserveValueCommitment(
            statement_hash,
            static_cast<uint32_t>(output_index),
            output.note_commitment);
        output.smile_account = std::move(*smile_account);
        output.encrypted_note = reserve_output.encrypted_note;
        payload_reserves.push_back(std::move(output));
    }
    return payload_reserves;
}

std::vector<BatchLeaf> BuildPayloadIngressLeaves(const BridgeBatchStatement& statement,
                                                 Span<const V2IngressLeafInput> ingress_leaves)
{
    std::vector<BatchLeaf> payload_leaves;
    payload_leaves.reserve(ingress_leaves.size());
    for (size_t leaf_index = 0; leaf_index < ingress_leaves.size(); ++leaf_index) {
        payload_leaves.push_back(shielded::v2::BuildV2IngressPayloadLeaf(
            statement,
            ingress_leaves[leaf_index],
            static_cast<uint32_t>(leaf_index)));
    }
    return payload_leaves;
}

std::vector<uint256> BuildSyntheticIngressNoteCommitments(const BridgeBatchStatement& statement,
                                                          Span<const V2IngressLeafInput> ingress_leaves)
{
    std::vector<uint256> commitments;
    commitments.reserve(ingress_leaves.size());
    for (size_t leaf_index = 0; leaf_index < ingress_leaves.size(); ++leaf_index) {
        const uint256 commitment = shielded::v2::ComputeV2IngressSyntheticCreditNoteCommitment(
            statement,
            ingress_leaves[leaf_index],
            static_cast<uint32_t>(leaf_index));
        if (commitment.IsNull()) {
            throw std::runtime_error("failed to compute ingress runtime synthetic note commitment");
        }
        commitments.push_back(commitment);
    }
    return commitments;
}

V2IngressSettlementWitness BuildReceiptSettlementWitness(
    const BridgeBatchStatement& statement,
    const shielded::v2::proof::NativeBatchBackend& backend,
    const V2IngressShardSchedule& schedule,
    Span<const V2SendSpendInput> spend_inputs,
    Span<const V2SendOutputInput> reserve_outputs,
    Span<const V2IngressLeafInput> ingress_leaves,
    Span<const unsigned char> spending_key)
{
    const auto receipt_backend = shielded::v2::proof::DescribeReceiptBackedNativeBatchBackend();
    if (backend.backend_id != receipt_backend.backend_id) {
        throw std::runtime_error("receipt settlement witness requested for non-receipt backend");
    }

    const auto descriptor = MakeProofDescriptor();
    const auto descriptor_proof = BuildProofDescriptorProof(descriptor);
    const auto statement_description =
        shielded::v2::proof::DescribeNativeBatchSettlementStatement(statement, backend);
    if (!statement_description.IsValid()) {
        throw std::runtime_error("failed to describe receipt-backed ingress statement");
    }

    const uint256 statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    if (statement_hash.IsNull()) {
        throw std::runtime_error("failed to compute receipt-backed ingress statement hash");
    }

    const auto nullifiers = BuildNullifiers(spend_inputs, spending_key);
    const auto payload_reserves = BuildPayloadReserveOutputs(statement, reserve_outputs);
    const auto payload_leaves = BuildPayloadIngressLeaves(statement, ingress_leaves);
    const auto ingress_note_commitments = BuildSyntheticIngressNoteCommitments(statement, ingress_leaves);

    V2IngressSettlementWitness witness;
    witness.proof_receipts.reserve(schedule.shards.size());
    witness.proof_receipt_descriptor_proofs.reserve(schedule.shards.size());
    for (size_t shard_index = 0; shard_index < schedule.shards.size(); ++shard_index) {
        const auto& shard = schedule.shards[shard_index];
        const Span<const uint256> shard_nullifiers{
            nullifiers.data() + static_cast<std::ptrdiff_t>(shard.spend_index),
            shard.spend_count};
        const Span<const OutputDescription> shard_reserves{
            payload_reserves.data() + static_cast<std::ptrdiff_t>(shard.reserve_output_index),
            shard.reserve_output_count};
        const Span<const BatchLeaf> shard_leaves{
            payload_leaves.data() + static_cast<std::ptrdiff_t>(shard.leaf_index),
            shard.leaf_count};
        const Span<const uint256> shard_note_commitments{
            ingress_note_commitments.data() + static_cast<std::ptrdiff_t>(shard.leaf_index),
            shard.leaf_count};
        const Span<const V2IngressLeafInput> shard_inputs{
            ingress_leaves.data() + static_cast<std::ptrdiff_t>(shard.leaf_index),
            shard.leaf_count};
        CAmount shard_fee{0};
        for (const auto& shard_input : shard_inputs) {
            shard_fee += shard_input.fee;
        }
        if (!MoneyRange(shard_fee)) {
            throw std::runtime_error("failed to sum receipt-backed shard fees");
        }

        shielded::BridgeProofReceipt receipt;
        receipt.statement_hash = statement_hash;
        receipt.proof_system_id = descriptor.proof_system_id;
        receipt.verifier_key_hash = descriptor.verifier_key_hash;
        receipt.public_values_hash = shielded::v2::ComputeV2IngressReceiptPublicValuesHash(
            shard_nullifiers,
            shard_reserves,
            shard_leaves,
            shard_note_commitments,
            shard_fee,
            statement_description.envelope.statement_digest);
        receipt.proof_commitment = DeterministicUint256(
            "BTX_INGRESS_PROOF_RUNTIME_RECEIPT_COMMITMENT",
            shard_index);
        if (!receipt.IsValid()) {
            throw std::runtime_error("constructed invalid receipt-backed ingress proof receipt");
        }

        witness.proof_receipts.push_back(std::move(receipt));
        witness.proof_receipt_descriptor_proofs.push_back(descriptor_proof);
    }

    if (!witness.IsValid()) {
        throw std::runtime_error("constructed invalid receipt-backed settlement witness");
    }
    return witness;
}

std::optional<RuntimeFixture> BuildRuntimeFixture(size_t reserve_output_count,
                                                  size_t leaf_count,
                                                  ProofRuntimeBackendKind backend_kind,
                                                  std::string& reject_reason)
{
    reject_reason.clear();
    const ScenarioInput scenario = BuildScenario(reserve_output_count, leaf_count, backend_kind);
    const auto backend = ResolveRuntimeBackend(backend_kind);
    const auto schedule = shielded::v2::BuildCanonicalV2IngressShardSchedule(
        Span<const CAmount>{scenario.spend_values.data(), scenario.spend_values.size()},
        Span<const CAmount>{scenario.reserve_values.data(), scenario.reserve_values.size()},
        Span<const V2IngressLeafInput>{scenario.ingress_leaves.data(), scenario.ingress_leaves.size()},
        backend);
    if (!schedule.has_value()) {
        reject_reason = "failed to build canonical ingress schedule";
        return std::nullopt;
    }
    if (!schedule->IsValid(
            scenario.spend_values.size(),
            scenario.reserve_values.size(),
            scenario.ingress_leaves.size(),
            shielded::v2::GetMaxIngressOutputsPerProofShard(backend))) {
        reject_reason = "invalid canonical ingress schedule";
        return std::nullopt;
    }
    if (schedule->shards.size() > MAX_PROOF_SHARDS) {
        reject_reason = "scenario exceeds max proof shards";
        return std::nullopt;
    }

    RuntimeFixture fixture;
    fixture.schedule = *schedule;
    fixture.input.ingress_leaves = scenario.ingress_leaves;
    fixture.input.statement = BuildStatement(
        Span<const V2IngressLeafInput>{fixture.input.ingress_leaves.data(), fixture.input.ingress_leaves.size()});
    fixture.input.backend_override = backend;

    std::vector<ShieldedNote> input_notes;
    input_notes.reserve(scenario.spend_values.size());
    for (size_t spend_index = 0; spend_index < scenario.spend_values.size(); ++spend_index) {
        input_notes.push_back(MakeNote(
            scenario.spend_values[spend_index],
            "BTX_INGRESS_PROOF_RUNTIME_INPUT",
            spend_index));
    }

    const auto real_indices = SelectRealIndices(input_notes.size());
    std::vector<uint256> input_chain_commitments(input_notes.size());
    fixture.tree = BuildTree(Span<const ShieldedNote>{input_notes.data(), input_notes.size()},
                             Span<const size_t>{real_indices.data(), real_indices.size()},
                             fixture.public_accounts,
                             fixture.account_leaf_commitments,
                             input_chain_commitments);

    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(
        fixture.tree,
        Span<const uint64_t>{ring_positions.data(), ring_positions.size()});
    auto shared_smile_ring_members = BuildSharedSmileRingMembers(
        Span<const uint256>{ring_members.data(), ring_members.size()},
        Span<const ShieldedNote>{input_notes.data(), input_notes.size()},
        Span<const size_t>{real_indices.data(), real_indices.size()},
        Span<const uint256>{input_chain_commitments.data(), input_chain_commitments.size()},
        fixture.public_accounts,
        fixture.account_leaf_commitments);
    if (!shared_smile_ring_members.has_value()) {
        throw std::runtime_error("failed to build ingress runtime shared SMILE ring");
    }

    fixture.input.spend_inputs.reserve(input_notes.size());
    for (size_t spend_index = 0; spend_index < input_notes.size(); ++spend_index) {
        V2SendSpendInput spend_input;
        spend_input.note = input_notes[spend_index];
        spend_input.note_commitment = input_chain_commitments[spend_index];
        spend_input.account_leaf_hint = shielded::registry::MakeDirectSendAccountLeafHint();
        spend_input.ring_positions = ring_positions;
        spend_input.ring_members = ring_members;
        spend_input.smile_ring_members = *shared_smile_ring_members;
        spend_input.real_index = real_indices[spend_index];
        fixture.input.spend_inputs.push_back(std::move(spend_input));
    }
    if (!::test::shielded::AttachAccountRegistryWitnesses(fixture.input.spend_inputs)) {
        throw std::runtime_error("failed to attach ingress runtime account registry witnesses");
    }
    if (!std::all_of(fixture.input.spend_inputs.begin(),
                     fixture.input.spend_inputs.end(),
                     [](const V2SendSpendInput& spend) { return spend.IsValid(); })) {
        throw std::runtime_error("constructed invalid spend input");
    }

    fixture.input.reserve_outputs.reserve(scenario.reserve_values.size());
    for (size_t output_index = 0; output_index < scenario.reserve_values.size(); ++output_index) {
        V2SendOutputInput reserve_output;
        reserve_output.note_class = shielded::v2::NoteClass::RESERVE;
        reserve_output.note = MakeNote(
            scenario.reserve_values[output_index],
            "BTX_INGRESS_PROOF_RUNTIME_RESERVE",
            output_index);
        const auto recipient = BuildRecipientKeyPair(output_index);
        const auto encrypted_note = BuildEncryptedNote(
            reserve_output.note,
            recipient.pk,
            output_index);
        auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            encrypted_note,
            recipient.pk,
            shielded::v2::ScanDomain::RESERVE);
        if (!payload.has_value()) {
            throw std::runtime_error("failed to encode reserve payload");
        }
        reserve_output.encrypted_note = *payload;
        if (!reserve_output.IsValid()) {
            throw std::runtime_error("constructed invalid reserve output");
        }
        fixture.input.reserve_outputs.push_back(std::move(reserve_output));
    }

    const auto spending_key = BuildRuntimeSpendingKey();
    if (backend_kind == ProofRuntimeBackendKind::RECEIPT_BACKED) {
        fixture.input.settlement_witness = BuildReceiptSettlementWitness(
            fixture.input.statement,
            backend,
            fixture.schedule,
            Span<const V2SendSpendInput>{fixture.input.spend_inputs.data(), fixture.input.spend_inputs.size()},
            Span<const V2SendOutputInput>{fixture.input.reserve_outputs.data(), fixture.input.reserve_outputs.size()},
            Span<const V2IngressLeafInput>{fixture.input.ingress_leaves.data(), fixture.input.ingress_leaves.size()},
            Span<const unsigned char>{spending_key.data(), spending_key.size()});
    } else {
        fixture.input.settlement_witness = BuildProofSettlementWitness(fixture.input.statement);
    }

    if (!fixture.input.IsValid()) {
        throw std::runtime_error("constructed invalid ingress build input");
    }
    return fixture;
}

uint64_t MeasureNanoseconds(const std::function<void()>& fn)
{
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

uint64_t Average(const std::vector<uint64_t>& values)
{
    if (values.empty()) return 0;
    const uint64_t total = std::accumulate(values.begin(), values.end(), uint64_t{0});
    return total / values.size();
}

uint64_t Median(std::vector<uint64_t> values)
{
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() % 2) == 1) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2;
}

UniValue BuildSummary(const std::vector<uint64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min_ns", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median_ns", Median(values));
    summary.pushKV("average_ns", Average(values));
    summary.pushKV("max_ns", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

uint64_t SerializedTransactionSize(const CMutableTransaction& tx)
{
    return static_cast<uint64_t>(CTransaction{tx}.GetTotalSize());
}

uint64_t ProofPayloadSize(const CMutableTransaction& tx)
{
    const auto& bundle = tx.shielded_bundle.v2_bundle;
    if (!bundle) {
        throw std::runtime_error("missing v2 ingress bundle");
    }
    return static_cast<uint64_t>(bundle->proof_payload.size());
}

std::optional<uint64_t> ParseProofPayloadRejectionSize(std::string_view reject_reason)
{
    static constexpr std::string_view PREFIX{
        "bad-shielded-v2-ingress-bundle-proof-payload-size:"};
    if (!reject_reason.starts_with(PREFIX)) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(std::stoull(std::string{reject_reason.substr(PREFIX.size())}));
}

UniValue BuildLeafCountArray(Span<const size_t> leaf_counts)
{
    UniValue out(UniValue::VARR);
    for (const size_t leaf_count : leaf_counts) {
        out.push_back(static_cast<uint64_t>(leaf_count));
    }
    return out;
}

const UniValue* FindBandByLeafCount(const UniValue& bands, size_t leaf_count)
{
    if (!bands.isArray()) return nullptr;
    for (size_t i = 0; i < bands.size(); ++i) {
        const UniValue& band = bands[i];
        if (!band.isObject()) continue;
        const UniValue& band_leaf_count = band.find_value("leaf_count");
        if (!band_leaf_count.isNum()) continue;
        if (band_leaf_count.getInt<int64_t>() == static_cast<int64_t>(leaf_count)) {
            return &band;
        }
    }
    return nullptr;
}

UniValue BuildTargetScenarioJson(size_t reserve_output_count,
                                 size_t leaf_count,
                                 ProofRuntimeBackendKind backend_kind)
{
    const ScenarioInput scenario = BuildScenario(reserve_output_count, leaf_count, backend_kind);
    const auto backend = ResolveRuntimeBackend(backend_kind);
    const auto schedule = shielded::v2::BuildCanonicalV2IngressShardSchedule(
        Span<const CAmount>{scenario.spend_values.data(), scenario.spend_values.size()},
        Span<const CAmount>{scenario.reserve_values.data(), scenario.reserve_values.size()},
        Span<const V2IngressLeafInput>{scenario.ingress_leaves.data(), scenario.ingress_leaves.size()},
        backend);
    if (!schedule.has_value()) {
        throw std::runtime_error("failed to build target ingress schedule");
    }
    if (!schedule->IsValid(
            scenario.spend_values.size(),
            scenario.reserve_values.size(),
            scenario.ingress_leaves.size(),
            shielded::v2::GetMaxIngressOutputsPerProofShard(backend))) {
        throw std::runtime_error("invalid target ingress schedule");
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("leaf_count", static_cast<uint64_t>(leaf_count));
    out.pushKV("reserve_output_count", static_cast<uint64_t>(reserve_output_count));
    out.pushKV("spend_input_count", static_cast<uint64_t>(scenario.spend_values.size()));
    out.pushKV("proof_shard_count", static_cast<uint64_t>(schedule->shards.size()));
    out.pushKV("max_spend_inputs_per_shard", static_cast<uint64_t>(schedule->MaxSpendInputCount()));
    out.pushKV("max_reserve_outputs_per_shard", static_cast<uint64_t>(schedule->MaxReserveOutputCount()));
    out.pushKV("max_ingress_leaves_per_shard", static_cast<uint64_t>(schedule->MaxIngressLeafCount()));
    out.pushKV("max_total_outputs_per_shard", static_cast<uint64_t>(schedule->MaxOutputCount()));
    out.pushKV("bundle_max_average_payload_per_shard_bytes",
               static_cast<double>(MAX_PROOF_PAYLOAD_BYTES) / static_cast<double>(schedule->shards.size()));
    return out;
}

UniValue BuildScenarioJson(const RuntimeFixture& fixture)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("reserve_output_count", static_cast<uint64_t>(fixture.input.reserve_outputs.size()));
    out.pushKV("ingress_leaf_count", static_cast<uint64_t>(fixture.input.ingress_leaves.size()));
    out.pushKV("spend_input_count", static_cast<uint64_t>(fixture.input.spend_inputs.size()));
    out.pushKV("proof_shard_count", static_cast<uint64_t>(fixture.schedule.shards.size()));
    out.pushKV("max_spend_inputs_per_shard", static_cast<uint64_t>(fixture.schedule.MaxSpendInputCount()));
    out.pushKV("max_reserve_outputs_per_shard", static_cast<uint64_t>(fixture.schedule.MaxReserveOutputCount()));
    out.pushKV("max_ingress_leaves_per_shard", static_cast<uint64_t>(fixture.schedule.MaxIngressLeafCount()));
    out.pushKV("max_total_outputs_per_shard", static_cast<uint64_t>(fixture.schedule.MaxOutputCount()));
    return out;
}

MeasuredTxMetrics BuildMeasuredTxMetrics(const CTransaction& tx, const RuntimeFixture& fixture)
{
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr) {
        throw std::runtime_error("missing v2 ingress bundle");
    }

    MeasuredTxMetrics metrics;
    metrics.serialized_size_bytes = tx.GetTotalSize();
    metrics.tx_weight = GetTransactionWeight(tx);
    metrics.shielded_policy_weight = GetShieldedPolicyWeight(tx);
    metrics.proof_payload_size = bundle->proof_payload.size();
    metrics.proof_shard_count = bundle->proof_shards.size();
    metrics.usage = GetShieldedResourceUsage(tx.GetShieldedBundle());
    metrics.within_standard_policy_weight =
        metrics.shielded_policy_weight <= MAX_STANDARD_SHIELDED_POLICY_WEIGHT;
    metrics.standard_policy_weight_headroom = metrics.within_standard_policy_weight
        ? static_cast<uint64_t>(MAX_STANDARD_SHIELDED_POLICY_WEIGHT) -
              static_cast<uint64_t>(metrics.shielded_policy_weight)
        : 0;
    metrics.max_transactions_by_standard_policy_weight =
        metrics.shielded_policy_weight > 0 &&
                metrics.shielded_policy_weight <= MAX_STANDARD_SHIELDED_POLICY_WEIGHT
            ? static_cast<uint64_t>(MAX_STANDARD_SHIELDED_POLICY_WEIGHT) /
                  static_cast<uint64_t>(metrics.shielded_policy_weight)
            : 0;

    metrics.max_transactions_by_serialized_size =
        metrics.serialized_size_bytes > 0 ? MAX_BLOCK_SERIALIZED_SIZE / metrics.serialized_size_bytes : 0;
    metrics.max_transactions_by_weight =
        metrics.tx_weight > 0 ? MAX_BLOCK_WEIGHT / metrics.tx_weight : 0;
    metrics.max_transactions_by_verify =
        metrics.usage.verify_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST / metrics.usage.verify_units
            : 0;
    metrics.max_transactions_by_scan =
        metrics.usage.scan_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS / metrics.usage.scan_units
            : 0;
    metrics.max_transactions_by_tree_update =
        metrics.usage.tree_update_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS / metrics.usage.tree_update_units
            : 0;

    std::vector<std::pair<std::string, uint64_t>> limits{
        {"serialized_size", metrics.max_transactions_by_serialized_size},
        {"weight", metrics.max_transactions_by_weight},
    };
    if (metrics.usage.verify_units > 0) {
        limits.emplace_back("shielded_verify_units", metrics.max_transactions_by_verify);
    }
    if (metrics.usage.scan_units > 0) {
        limits.emplace_back("shielded_scan_units", metrics.max_transactions_by_scan);
    }
    if (metrics.usage.tree_update_units > 0) {
        limits.emplace_back("shielded_tree_update_units", metrics.max_transactions_by_tree_update);
    }
    const auto best = std::min_element(limits.begin(), limits.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second < rhs.second;
    });
    metrics.block_binding_limit = best->first;
    metrics.max_transactions_per_block = best->second;
    metrics.max_spend_inputs_per_block =
        metrics.max_transactions_per_block * fixture.input.spend_inputs.size();
    metrics.max_reserve_outputs_per_block =
        metrics.max_transactions_per_block * fixture.input.reserve_outputs.size();
    metrics.max_ingress_leaves_per_block =
        metrics.max_transactions_per_block * fixture.input.ingress_leaves.size();
    return metrics;
}

UniValue BuildTxShapeJson(const MeasuredTxMetrics& metrics)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("serialized_size_bytes", metrics.serialized_size_bytes);
    out.pushKV("tx_weight", metrics.tx_weight);
    out.pushKV("shielded_policy_weight", metrics.shielded_policy_weight);
    out.pushKV("proof_payload_size", metrics.proof_payload_size);
    out.pushKV("proof_shard_count", metrics.proof_shard_count);
    return out;
}

UniValue BuildResourceUsageJson(const MeasuredTxMetrics& metrics)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("verify_units", metrics.usage.verify_units);
    out.pushKV("scan_units", metrics.usage.scan_units);
    out.pushKV("tree_update_units", metrics.usage.tree_update_units);
    return out;
}

UniValue BuildRelayPolicyJson(const MeasuredTxMetrics& metrics)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("within_standard_policy_weight", metrics.within_standard_policy_weight);
    out.pushKV("standard_policy_weight_headroom", metrics.standard_policy_weight_headroom);
    out.pushKV("max_transactions_by_standard_policy_weight",
               metrics.max_transactions_by_standard_policy_weight);
    return out;
}

UniValue BuildBlockCapacityJson(const MeasuredTxMetrics& metrics)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("binding_limit", metrics.block_binding_limit);
    out.pushKV("max_transactions_by_serialized_size", metrics.max_transactions_by_serialized_size);
    out.pushKV("max_transactions_by_weight", metrics.max_transactions_by_weight);
    out.pushKV("max_transactions_by_shielded_verify_units", metrics.max_transactions_by_verify);
    out.pushKV("max_transactions_by_shielded_scan_units", metrics.max_transactions_by_scan);
    out.pushKV("max_transactions_by_shielded_tree_update_units", metrics.max_transactions_by_tree_update);
    out.pushKV("max_transactions_per_block", metrics.max_transactions_per_block);
    out.pushKV("max_spend_inputs_per_block", metrics.max_spend_inputs_per_block);
    out.pushKV("max_reserve_outputs_per_block", metrics.max_reserve_outputs_per_block);
    out.pushKV("max_ingress_leaves_per_block", metrics.max_ingress_leaves_per_block);
    return out;
}

} // namespace

UniValue BuildProofRuntimeReport(const ProofRuntimeReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }
    if (config.reserve_output_count == 0) {
        throw std::runtime_error("reserve_output_count must be non-zero");
    }
    if (config.leaf_count == 0) {
        throw std::runtime_error("leaf_count must be non-zero");
    }

    const auto backend = ResolveRuntimeBackend(config.backend_kind);
    UniValue runtime_config(UniValue::VOBJ);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("reserve_output_count", static_cast<uint64_t>(config.reserve_output_count));
    runtime_config.pushKV("leaf_count", static_cast<uint64_t>(config.leaf_count));
    runtime_config.pushKV("backend", GetRuntimeBackendName(config.backend_kind));
    runtime_config.pushKV("backend_id", backend.backend_id.GetHex());
    runtime_config.pushKV("backend_membership_proof_kind",
                          static_cast<uint64_t>(backend.membership_proof_kind));
    runtime_config.pushKV("backend_amount_proof_kind",
                          static_cast<uint64_t>(backend.amount_proof_kind));
    runtime_config.pushKV("backend_balance_proof_kind",
                          static_cast<uint64_t>(backend.balance_proof_kind));
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");
    runtime_config.pushKV("settlement_witness_kind", "proof_only");

    UniValue limits(UniValue::VOBJ);
    limits.pushKV("max_bundle_ingress_leaves", static_cast<uint64_t>(MAX_BATCH_LEAVES));
    limits.pushKV("max_bundle_reserve_outputs", static_cast<uint64_t>(MAX_BATCH_RESERVE_OUTPUTS));
    limits.pushKV("max_proof_shards", static_cast<uint64_t>(MAX_PROOF_SHARDS));
    limits.pushKV("max_outputs_per_proof_shard",
                  static_cast<uint64_t>(shielded::v2::GetMaxIngressOutputsPerProofShard(backend)));
    limits.pushKV("max_matrict_inputs_per_proof_shard", static_cast<uint64_t>(shielded::ringct::MAX_MATRICT_INPUTS));
    limits.pushKV("max_settlement_refs", static_cast<uint64_t>(MAX_SETTLEMENT_REFS));
    limits.pushKV("max_proof_payload_bytes", MAX_PROOF_PAYLOAD_BYTES);

    std::string fixture_reject_reason;
    std::optional<RuntimeFixture> fixture;
    try {
        fixture = BuildRuntimeFixture(
            config.reserve_output_count,
            config.leaf_count,
            config.backend_kind,
            fixture_reject_reason);
    } catch (const std::runtime_error& e) {
        fixture_reject_reason = e.what();
    }
    if (!fixture.has_value()) {
        UniValue rejection(UniValue::VOBJ);
        rejection.pushKV("failed_sample_index", 0);
        rejection.pushKV("build_ns", 0);
        rejection.pushKV("reject_reason", fixture_reject_reason);

        UniValue measurements(UniValue::VARR);
        UniValue measurement(UniValue::VOBJ);
        measurement.pushKV("sample_index", 0);
        measurement.pushKV("status", "scenario_rejected");
        measurement.pushKV("build_ns", 0);
        measurement.pushKV("reject_reason", fixture_reject_reason);
        measurements.push_back(std::move(measurement));

        UniValue out(UniValue::VOBJ);
        out.pushKV("format_version", 1);
        out.pushKV("report_kind", "v2_ingress_proof_runtime");
        out.pushKV("limits", std::move(limits));
        out.pushKV("runtime_config", std::move(runtime_config));
        out.pushKV("scenario",
                   BuildTargetScenarioJson(
                       config.reserve_output_count,
                       config.leaf_count,
                       config.backend_kind));
        out.pushKV("status", "scenario_rejected");
        out.pushKV("rejection", std::move(rejection));
        out.pushKV("build_summary", BuildSummary({}));
        out.pushKV("proof_check_summary", BuildSummary({}));
        out.pushKV("measurements", std::move(measurements));
        return out;
    }
    const auto spending_key = BuildRuntimeSpendingKey();
    const auto rng_entropy = BuildRuntimeEntropy();
    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = consensus.nShieldedMatRiCTDisableHeight;
    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 23;

    for (size_t i = 0; i < config.warmup_iterations; ++i) {
        std::string reject_reason;
        auto built = shielded::v2::BuildV2IngressBatchTransaction(
            tx_template,
            fixture->tree.Root(),
            fixture->input,
            spending_key,
            reject_reason,
            rng_entropy,
            &consensus,
            validation_height);
        if (!built.has_value()) {
            throw std::runtime_error("warmup ingress build failed: " + reject_reason);
        }
        const CTransaction tx{built->tx};
        CShieldedProofCheck proof_check(
            tx,
            consensus,
            validation_height,
            std::make_shared<ShieldedMerkleTree>(fixture->tree),
            std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(fixture->public_accounts),
            std::make_shared<std::map<uint256, uint256>>(fixture->account_leaf_commitments));
        if (const auto result = proof_check(); result.has_value()) {
            throw std::runtime_error("warmup ingress proof check failed: " + *result);
        }
    }

    std::vector<uint64_t> build_times_ns;
    std::vector<uint64_t> proof_check_times_ns;
    build_times_ns.reserve(config.measured_iterations);
    proof_check_times_ns.reserve(config.measured_iterations);
    std::string status{"built_and_checked"};
    std::string reject_reason;
    size_t failed_sample_index{0};
    uint64_t rejected_build_ns{0};

    UniValue measurements(UniValue::VARR);
    std::optional<MeasuredTxMetrics> metrics;
    for (size_t i = 0; i < config.measured_iterations; ++i) {
        V2IngressBuildResult built;
        bool build_ok{false};
        std::string build_reject_reason;
        const uint64_t build_ns = MeasureNanoseconds([&] {
            auto candidate = shielded::v2::BuildV2IngressBatchTransaction(
                tx_template,
                fixture->tree.Root(),
                fixture->input,
                spending_key,
                build_reject_reason,
                rng_entropy,
                &consensus,
                validation_height);
            if (!candidate.has_value()) {
                return;
            }
            built = std::move(*candidate);
            build_ok = true;
        });
        if (!build_ok) {
            status = "builder_rejected";
            reject_reason = build_reject_reason;
            failed_sample_index = i;
            rejected_build_ns = build_ns;

            UniValue measurement(UniValue::VOBJ);
            measurement.pushKV("sample_index", static_cast<uint64_t>(i));
            measurement.pushKV("status", status);
            measurement.pushKV("build_ns", build_ns);
            measurement.pushKV("reject_reason", reject_reason);
            measurements.push_back(std::move(measurement));
            break;
        }
        if (!built.IsValid()) {
            throw std::runtime_error("ingress build produced invalid result");
        }

        const CTransaction tx{built.tx};
        if (!metrics.has_value()) {
            metrics = BuildMeasuredTxMetrics(tx, *fixture);
        }
        const uint64_t proof_check_ns = MeasureNanoseconds([&] {
            CShieldedProofCheck proof_check(
                tx,
                consensus,
                validation_height,
                std::make_shared<ShieldedMerkleTree>(fixture->tree),
                std::make_shared<std::map<uint256, smile2::CompactPublicAccount>>(fixture->public_accounts),
                std::make_shared<std::map<uint256, uint256>>(fixture->account_leaf_commitments));
            if (const auto result = proof_check(); result.has_value()) {
                throw std::runtime_error("ingress proof check failed: " + *result);
            }
        });

        build_times_ns.push_back(build_ns);
        proof_check_times_ns.push_back(proof_check_ns);

        UniValue measurement(UniValue::VOBJ);
        measurement.pushKV("sample_index", static_cast<uint64_t>(i));
        measurement.pushKV("status", status);
        measurement.pushKV("build_ns", build_ns);
        measurement.pushKV("proof_check_ns", proof_check_ns);
        measurement.pushKV("proof_payload_size", ProofPayloadSize(built.tx));
        measurement.pushKV("serialized_tx_size", SerializedTransactionSize(built.tx));
        measurement.pushKV("proof_shard_count",
                           static_cast<uint64_t>(built.tx.shielded_bundle.v2_bundle->proof_shards.size()));
        measurement.pushKV("tx_weight", metrics->tx_weight);
        measurement.pushKV("shielded_policy_weight", metrics->shielded_policy_weight);
        measurement.pushKV("verify_units", metrics->usage.verify_units);
        measurement.pushKV("scan_units", metrics->usage.scan_units);
        measurement.pushKV("tree_update_units", metrics->usage.tree_update_units);
        measurements.push_back(std::move(measurement));
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("report_kind", "v2_ingress_proof_runtime");
    out.pushKV("limits", std::move(limits));
    out.pushKV("runtime_config", std::move(runtime_config));
    UniValue scenario = BuildScenarioJson(*fixture);
    if (metrics.has_value()) {
        scenario.pushKV("tx_shape", BuildTxShapeJson(*metrics));
        scenario.pushKV("resource_usage", BuildResourceUsageJson(*metrics));
        scenario.pushKV("relay_policy", BuildRelayPolicyJson(*metrics));
        scenario.pushKV("block_capacity", BuildBlockCapacityJson(*metrics));
    }
    out.pushKV("scenario", std::move(scenario));
    out.pushKV("status", status);
    if (!reject_reason.empty()) {
        UniValue rejection(UniValue::VOBJ);
        rejection.pushKV("failed_sample_index", static_cast<uint64_t>(failed_sample_index));
        rejection.pushKV("build_ns", rejected_build_ns);
        rejection.pushKV("reject_reason", reject_reason);
        out.pushKV("rejection", std::move(rejection));
    }
    out.pushKV("build_summary", BuildSummary(build_times_ns));
    out.pushKV("proof_check_summary", BuildSummary(proof_check_times_ns));
    out.pushKV("measurements", std::move(measurements));
    return out;
}

UniValue BuildProofCapacitySweepReport(const ProofCapacitySweepConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }
    if (config.reserve_output_count == 0) {
        throw std::runtime_error("reserve_output_count must be non-zero");
    }
    if (config.leaf_counts.empty()) {
        throw std::runtime_error("leaf_counts must be non-empty");
    }

    UniValue bands(UniValue::VARR);
    std::optional<size_t> highest_successful_leaf_count;
    std::optional<size_t> lowest_rejected_leaf_count;
    std::optional<uint64_t> highest_successful_proof_payload_size;
    std::optional<uint64_t> lowest_rejected_proof_payload_size;

    for (const size_t leaf_count : config.leaf_counts) {
        const UniValue report = BuildProofRuntimeReport({
            .backend_kind = config.backend_kind,
            .warmup_iterations = config.warmup_iterations,
            .measured_iterations = config.measured_iterations,
            .reserve_output_count = config.reserve_output_count,
            .leaf_count = leaf_count,
        });

        const UniValue& scenario = report.find_value("scenario");
        const UniValue& build_summary = report.find_value("build_summary");
        const UniValue& proof_check_summary = report.find_value("proof_check_summary");
        const UniValue& measurements = report.find_value("measurements");
        const std::string status = report.find_value("status").get_str();

        UniValue band(UniValue::VOBJ);
        band.pushKV("leaf_count", static_cast<uint64_t>(leaf_count));
        band.pushKV("status", status);
        band.pushKV("spend_input_count", scenario.find_value("spend_input_count").getInt<int64_t>());
        band.pushKV("proof_shard_count", scenario.find_value("proof_shard_count").getInt<int64_t>());
        band.pushKV("max_ingress_leaves_per_shard", scenario.find_value("max_ingress_leaves_per_shard").getInt<int64_t>());
        band.pushKV("build_ns", build_summary.find_value("median_ns").getInt<int64_t>());

        if (status == "built_and_checked") {
            const UniValue& measurement = measurements[measurements.size() - 1];
            const UniValue& tx_shape = scenario.find_value("tx_shape");
            const UniValue& resource_usage = scenario.find_value("resource_usage");
            const UniValue& relay_policy = scenario.find_value("relay_policy");
            const UniValue& block_capacity = scenario.find_value("block_capacity");
            const uint64_t proof_payload_size = measurement.find_value("proof_payload_size").getInt<int64_t>();
            band.pushKV("proof_check_ns", proof_check_summary.find_value("median_ns").getInt<int64_t>());
            band.pushKV("proof_payload_size", proof_payload_size);
            band.pushKV("serialized_tx_size", measurement.find_value("serialized_tx_size").getInt<int64_t>());
            band.pushKV("tx_weight", tx_shape.find_value("tx_weight").getInt<int64_t>());
            band.pushKV("shielded_policy_weight", tx_shape.find_value("shielded_policy_weight").getInt<int64_t>());
            band.pushKV("verify_units", resource_usage.find_value("verify_units").getInt<int64_t>());
            band.pushKV("scan_units", resource_usage.find_value("scan_units").getInt<int64_t>());
            band.pushKV("tree_update_units", resource_usage.find_value("tree_update_units").getInt<int64_t>());
            band.pushKV("binding_limit", block_capacity.find_value("binding_limit").get_str());
            band.pushKV("max_transactions_per_block",
                        block_capacity.find_value("max_transactions_per_block").getInt<int64_t>());
            band.pushKV("max_spend_inputs_per_block",
                        block_capacity.find_value("max_spend_inputs_per_block").getInt<int64_t>());
            band.pushKV("max_reserve_outputs_per_block",
                        block_capacity.find_value("max_reserve_outputs_per_block").getInt<int64_t>());
            band.pushKV("max_ingress_leaves_per_block",
                        block_capacity.find_value("max_ingress_leaves_per_block").getInt<int64_t>());
            band.pushKV("within_standard_policy_weight",
                        relay_policy.find_value("within_standard_policy_weight").get_bool());

            if (!highest_successful_leaf_count.has_value() || leaf_count > *highest_successful_leaf_count) {
                highest_successful_leaf_count = leaf_count;
                highest_successful_proof_payload_size = proof_payload_size;
            }
        } else if (status == "builder_rejected" || status == "scenario_rejected") {
            const UniValue& rejection = report.find_value("rejection");
            const std::string reject_reason = rejection.find_value("reject_reason").get_str();
            band.pushKV("reject_reason", reject_reason);
            band.pushKV("rejected_build_ns", rejection.find_value("build_ns").getInt<int64_t>());
            if (const auto rejected_size = ParseProofPayloadRejectionSize(reject_reason)) {
                band.pushKV("rejected_proof_payload_size", *rejected_size);
                if (!lowest_rejected_leaf_count.has_value() || leaf_count < *lowest_rejected_leaf_count) {
                    lowest_rejected_leaf_count = leaf_count;
                    lowest_rejected_proof_payload_size = *rejected_size;
                }
            } else if (!lowest_rejected_leaf_count.has_value() || leaf_count < *lowest_rejected_leaf_count) {
                lowest_rejected_leaf_count = leaf_count;
                lowest_rejected_proof_payload_size.reset();
            }
        } else {
            throw std::runtime_error("unexpected proof runtime status: " + status);
        }

        bands.push_back(std::move(band));
    }

    UniValue runtime_config(UniValue::VOBJ);
    const auto backend = ResolveRuntimeBackend(config.backend_kind);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("reserve_output_count", static_cast<uint64_t>(config.reserve_output_count));
    runtime_config.pushKV("leaf_counts", BuildLeafCountArray(
        Span<const size_t>{config.leaf_counts.data(), config.leaf_counts.size()}));
    runtime_config.pushKV("backend", GetRuntimeBackendName(config.backend_kind));
    runtime_config.pushKV("backend_id", backend.backend_id.GetHex());
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");
    runtime_config.pushKV("settlement_witness_kind", "proof_only");

    UniValue limits(UniValue::VOBJ);
    limits.pushKV("max_bundle_ingress_leaves", static_cast<uint64_t>(MAX_BATCH_LEAVES));
    limits.pushKV("max_bundle_reserve_outputs", static_cast<uint64_t>(MAX_BATCH_RESERVE_OUTPUTS));
    limits.pushKV("max_proof_shards", static_cast<uint64_t>(MAX_PROOF_SHARDS));
    limits.pushKV("max_outputs_per_proof_shard",
                  static_cast<uint64_t>(shielded::v2::GetMaxIngressOutputsPerProofShard(backend)));
    limits.pushKV("max_matrict_inputs_per_proof_shard", static_cast<uint64_t>(shielded::ringct::MAX_MATRICT_INPUTS));
    limits.pushKV("max_settlement_refs", static_cast<uint64_t>(MAX_SETTLEMENT_REFS));
    limits.pushKV("max_proof_payload_bytes", MAX_PROOF_PAYLOAD_BYTES);

    UniValue boundary(UniValue::VOBJ);
    if (highest_successful_leaf_count.has_value()) {
        boundary.pushKV("highest_successful_leaf_count", static_cast<uint64_t>(*highest_successful_leaf_count));
    }
    if (highest_successful_proof_payload_size.has_value()) {
        boundary.pushKV("highest_successful_proof_payload_size", *highest_successful_proof_payload_size);
        boundary.pushKV("highest_successful_proof_payload_headroom_bytes",
                        MAX_PROOF_PAYLOAD_BYTES - *highest_successful_proof_payload_size);
    }
    if (lowest_rejected_leaf_count.has_value()) {
        boundary.pushKV("lowest_rejected_leaf_count", static_cast<uint64_t>(*lowest_rejected_leaf_count));
    }
    if (lowest_rejected_proof_payload_size.has_value()) {
        boundary.pushKV("lowest_rejected_proof_payload_size", *lowest_rejected_proof_payload_size);
        boundary.pushKV("lowest_rejected_proof_payload_overflow_bytes",
                        *lowest_rejected_proof_payload_size - MAX_PROOF_PAYLOAD_BYTES);
    }
    if (highest_successful_leaf_count.has_value() && lowest_rejected_leaf_count.has_value() &&
        *lowest_rejected_leaf_count > *highest_successful_leaf_count) {
        boundary.pushKV("unverified_leaf_gap",
                        static_cast<uint64_t>(*lowest_rejected_leaf_count - *highest_successful_leaf_count - 1));
    }

    std::string status{"all_candidates_built_and_checked"};
    if (highest_successful_leaf_count.has_value() && lowest_rejected_leaf_count.has_value()) {
        status = "capacity_boundary_bracketed";
    } else if (lowest_rejected_leaf_count.has_value()) {
        status = "all_candidates_rejected";
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("report_kind", "v2_ingress_proof_capacity_sweep");
    out.pushKV("limits", std::move(limits));
    out.pushKV("runtime_config", std::move(runtime_config));
    out.pushKV("status", status);
    out.pushKV("boundary", std::move(boundary));
    out.pushKV("bands", std::move(bands));
    return out;
}

UniValue BuildProofBackendDecisionReport(const ProofBackendDecisionReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }
    if (config.reserve_output_count == 0) {
        throw std::runtime_error("reserve_output_count must be non-zero");
    }
    if (config.measured_leaf_counts.empty()) {
        throw std::runtime_error("measured_leaf_counts must be non-empty");
    }
    if (config.target_leaf_counts.empty()) {
        throw std::runtime_error("target_leaf_counts must be non-empty");
    }

    const UniValue measured = BuildProofCapacitySweepReport({
        .backend_kind = config.backend_kind,
        .warmup_iterations = config.warmup_iterations,
        .measured_iterations = config.measured_iterations,
        .reserve_output_count = config.reserve_output_count,
        .leaf_counts = config.measured_leaf_counts,
    });

    const UniValue& boundary = measured.find_value("boundary");
    const UniValue& bands = measured.find_value("bands");
    if (!boundary.isObject() || !bands.isArray()) {
        throw std::runtime_error("invalid capacity sweep report");
    }

    const UniValue* highest_success_band = nullptr;
    if (const UniValue& highest_success_leaf_count = boundary.find_value("highest_successful_leaf_count");
        highest_success_leaf_count.isNum()) {
        highest_success_band = FindBandByLeafCount(
            bands,
            static_cast<size_t>(highest_success_leaf_count.getInt<int64_t>()));
    }
    if (highest_success_band == nullptr) {
        throw std::runtime_error("missing highest successful measured band");
    }

    double best_success_average_payload_per_shard = std::numeric_limits<double>::max();
    for (size_t i = 0; i < bands.size(); ++i) {
        const UniValue& band = bands[i];
        if (!band.isObject()) continue;
        if (band.find_value("status").get_str() != "built_and_checked") continue;
        const double shard_count = static_cast<double>(band.find_value("proof_shard_count").getInt<int64_t>());
        const double proof_payload_size = static_cast<double>(band.find_value("proof_payload_size").getInt<int64_t>());
        best_success_average_payload_per_shard = std::min(best_success_average_payload_per_shard,
                                                          proof_payload_size / shard_count);
    }
    if (best_success_average_payload_per_shard == std::numeric_limits<double>::max()) {
        throw std::runtime_error("missing successful measured bands");
    }

    const double highest_success_average_payload_per_shard =
        static_cast<double>(highest_success_band->find_value("proof_payload_size").getInt<int64_t>()) /
        static_cast<double>(highest_success_band->find_value("proof_shard_count").getInt<int64_t>());

    UniValue target_bands(UniValue::VARR);
    bool replacement_backend_required{false};
    for (const size_t target_leaf_count : config.target_leaf_counts) {
        UniValue target = BuildTargetScenarioJson(
            config.reserve_output_count,
            target_leaf_count,
            config.backend_kind);
        const auto proof_shard_count =
            static_cast<uint64_t>(target.find_value("proof_shard_count").getInt<int64_t>());
        const double bundle_max_average_payload_per_shard_bytes =
            target.find_value("bundle_max_average_payload_per_shard_bytes").get_real();
        const double estimated_total_payload_at_best_success =
            best_success_average_payload_per_shard *
            static_cast<double>(proof_shard_count);
        const double estimated_total_payload_at_highest_success =
            highest_success_average_payload_per_shard *
            static_cast<double>(proof_shard_count);
        const double required_reduction_factor_vs_best_success =
            best_success_average_payload_per_shard / bundle_max_average_payload_per_shard_bytes;
        const double required_reduction_factor_vs_highest_success =
            highest_success_average_payload_per_shard / bundle_max_average_payload_per_shard_bytes;
        const bool exceeds_proof_shard_limit = proof_shard_count > MAX_PROOF_SHARDS;
        const bool exceeds_settlement_ref_limit = proof_shard_count > MAX_SETTLEMENT_REFS;
        const bool exceeds_payload_budget = required_reduction_factor_vs_best_success > 1.0;
        const bool requires_replacement =
            exceeds_proof_shard_limit || exceeds_settlement_ref_limit || exceeds_payload_budget;
        replacement_backend_required = replacement_backend_required || requires_replacement;

        UniValue incompatibility_reasons(UniValue::VARR);
        if (exceeds_proof_shard_limit) {
            incompatibility_reasons.push_back("proof_shard_limit");
        }
        if (exceeds_settlement_ref_limit) {
            incompatibility_reasons.push_back("settlement_ref_limit");
        }
        if (exceeds_payload_budget) {
            incompatibility_reasons.push_back("proof_payload_budget");
        }

        target.pushKV("measured_best_success_avg_shard_payload_bytes", best_success_average_payload_per_shard);
        target.pushKV("measured_highest_success_avg_shard_payload_bytes", highest_success_average_payload_per_shard);
        target.pushKV("estimated_total_payload_if_best_success_avg_shard_persists",
                      estimated_total_payload_at_best_success);
        target.pushKV("estimated_total_payload_if_highest_success_avg_shard_persists",
                      estimated_total_payload_at_highest_success);
        target.pushKV("estimated_overflow_vs_cap_if_best_success_avg_shard_persists",
                      estimated_total_payload_at_best_success - static_cast<double>(MAX_PROOF_PAYLOAD_BYTES));
        target.pushKV("estimated_overflow_vs_cap_if_highest_success_avg_shard_persists",
                      estimated_total_payload_at_highest_success - static_cast<double>(MAX_PROOF_PAYLOAD_BYTES));
        target.pushKV("required_reduction_factor_vs_best_success_avg_shard_payload",
                      required_reduction_factor_vs_best_success);
        target.pushKV("required_reduction_factor_vs_highest_success_avg_shard_payload",
                      required_reduction_factor_vs_highest_success);
        target.pushKV("exceeds_max_proof_shards", exceeds_proof_shard_limit);
        target.pushKV("exceeds_max_settlement_refs", exceeds_settlement_ref_limit);
        target.pushKV("incompatibility_reasons", std::move(incompatibility_reasons));
        target.pushKV("status",
                      requires_replacement
                          ? "replacement_backend_required"
                          : "selected_backend_within_bundle_payload_budget");
        target_bands.push_back(std::move(target));
    }

    UniValue runtime_config(UniValue::VOBJ);
    const auto backend = ResolveRuntimeBackend(config.backend_kind);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("reserve_output_count", static_cast<uint64_t>(config.reserve_output_count));
    runtime_config.pushKV("measured_leaf_counts", BuildLeafCountArray(
        Span<const size_t>{config.measured_leaf_counts.data(), config.measured_leaf_counts.size()}));
    runtime_config.pushKV("target_leaf_counts", BuildLeafCountArray(
        Span<const size_t>{config.target_leaf_counts.data(), config.target_leaf_counts.size()}));
    runtime_config.pushKV("backend", GetRuntimeBackendName(config.backend_kind));
    runtime_config.pushKV("backend_id", backend.backend_id.GetHex());
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");
    runtime_config.pushKV("settlement_witness_kind", "proof_only");

    UniValue limits(UniValue::VOBJ);
    limits.pushKV("max_bundle_ingress_leaves", static_cast<uint64_t>(MAX_BATCH_LEAVES));
    limits.pushKV("max_bundle_reserve_outputs", static_cast<uint64_t>(MAX_BATCH_RESERVE_OUTPUTS));
    limits.pushKV("max_proof_shards", static_cast<uint64_t>(MAX_PROOF_SHARDS));
    limits.pushKV("max_outputs_per_proof_shard",
                  static_cast<uint64_t>(shielded::v2::GetMaxIngressOutputsPerProofShard(backend)));
    limits.pushKV("max_matrict_inputs_per_proof_shard", static_cast<uint64_t>(shielded::ringct::MAX_MATRICT_INPUTS));
    limits.pushKV("max_settlement_refs", static_cast<uint64_t>(MAX_SETTLEMENT_REFS));
    limits.pushKV("max_proof_payload_bytes", MAX_PROOF_PAYLOAD_BYTES);

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("report_kind", "v2_ingress_proof_backend_decision");
    out.pushKV("limits", std::move(limits));
    out.pushKV("runtime_config", std::move(runtime_config));
    out.pushKV("status",
               replacement_backend_required
                   ? "selected_backend_incompatible_with_target_range"
                   : "selected_backend_within_target_range");
    out.pushKV("measured_capacity_boundary", boundary);
    out.pushKV("measured_bands", bands);
    out.pushKV("target_bands", std::move(target_bands));
    return out;
}

} // namespace btx::test::ingress
