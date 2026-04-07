// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_ingress.h>

#include <hash.h>
#include <serialize.h>
#include <shielded/smile2/public_account.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/ringct/commitment.h>
#include <streams.h>
#include <util/overflow.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace shielded::v2 {
namespace {

constexpr std::string_view TAG_INGRESS_DESTINATION_COMMITMENT{"BTX_ShieldedV2_Ingress_Destination_V1"};
constexpr std::string_view TAG_INGRESS_FEE_COMMITMENT{"BTX_ShieldedV2_Ingress_Fee_V1"};
constexpr std::string_view TAG_INGRESS_L2_CREDIT_LEAF{"BTX_ShieldedV2_Ingress_L2_Credit_Leaf_V1"};
constexpr std::string_view TAG_INGRESS_L2_CREDIT_NODE{"BTX_ShieldedV2_Ingress_L2_Credit_Node_V1"};
constexpr std::string_view TAG_INGRESS_FEE_ROOT_LEAF{"BTX_ShieldedV2_Ingress_Fee_Root_Leaf_V1"};
constexpr std::string_view TAG_INGRESS_FEE_ROOT_NODE{"BTX_ShieldedV2_Ingress_Fee_Root_Node_V1"};
constexpr std::string_view TAG_INGRESS_RESERVE_AGGREGATE{"BTX_ShieldedV2_Ingress_Reserve_Aggregate_V1"};
constexpr std::string_view TAG_INGRESS_NULLIFIER_COMMITMENT{"BTX_ShieldedV2_Ingress_Nullifier_Commit_V1"};
constexpr std::string_view TAG_INGRESS_PROOF_VALUE_COMMITMENT{"BTX_ShieldedV2_Ingress_Proof_Value_V1"};
constexpr std::string_view TAG_INGRESS_PROOF_METADATA{"BTX_ShieldedV2_Ingress_Proof_Metadata_V1"};
constexpr std::string_view TAG_INGRESS_CREDIT_PKH{"BTX_ShieldedV2_Ingress_Credit_Pkh_V1"};
constexpr std::string_view TAG_INGRESS_CREDIT_RHO{"BTX_ShieldedV2_Ingress_Credit_Rho_V1"};
constexpr std::string_view TAG_INGRESS_CREDIT_RCM{"BTX_ShieldedV2_Ingress_Credit_Rcm_V1"};
constexpr std::string_view TAG_INGRESS_LEAF_NONCE{"BTX_ShieldedV2_Ingress_Leaf_Nonce_V1"};
constexpr std::string_view TAG_INGRESS_PLACEHOLDER_RESERVE_VALUE{"BTX_ShieldedV2_Ingress_Placeholder_Reserve_Value_V1"};

template <typename T>
[[nodiscard]] uint256 HashTaggedObject(std::string_view tag, const T& obj)
{
    HashWriter hw;
    hw << std::string{tag} << obj;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashTaggedPair(std::string_view tag, const uint256& left, const uint256& right)
{
    HashWriter hw;
    hw << std::string{tag} << left << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashTaggedIndex(std::string_view tag,
                                      const uint256& statement_hash,
                                      uint32_t index,
                                      const uint256& discriminator)
{
    HashWriter hw;
    hw << std::string{tag} << statement_hash << index << discriminator;
    return hw.GetSHA256();
}

template <typename T>
[[nodiscard]] bool AllValid(Span<const T> values)
{
    return std::all_of(values.begin(), values.end(), [](const T& value) { return value.IsValid(); });
}

[[nodiscard]] std::vector<uint256> ExtractConsumedNullifiers(Span<const ConsumedAccountLeafSpend> spends)
{
    std::vector<uint256> nullifiers;
    nullifiers.reserve(spends.size());
    for (const auto& spend : spends) {
        nullifiers.push_back(spend.nullifier);
    }
    return nullifiers;
}

[[nodiscard]] uint256 HashCommitmentLeaf(std::string_view tag, const uint256& commitment)
{
    return HashTaggedObject(tag, commitment);
}

[[nodiscard]] uint256 ComputeCommitmentRoot(Span<const uint256> commitments,
                                            std::string_view leaf_tag,
                                            std::string_view node_tag)
{
    if (commitments.empty()) return uint256::ZERO;

    std::vector<uint256> level;
    level.reserve(commitments.size());
    for (const uint256& commitment : commitments) {
        if (commitment.IsNull()) return uint256{};
        level.push_back(HashCommitmentLeaf(leaf_tag, commitment));
    }

    while (level.size() > 1) {
        if (level.size() & 1U) {
            level.push_back(level.back());
        }

        std::vector<uint256> next_level;
        next_level.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next_level.push_back(HashTaggedPair(node_tag, level[i], level[i + 1]));
        }
        level = std::move(next_level);
    }

    return level.front();
}

template <typename T>
[[nodiscard]] std::vector<uint8_t> SerializeObject(const T& object)
{
    DataStream stream;
    stream << object;
    if (stream.empty()) return {};
    const auto* begin = reinterpret_cast<const uint8_t*>(stream.data());
    return {begin, begin + stream.size()};
}

[[nodiscard]] std::vector<uint8_t> SerializeMatRiCTProofMetadata(const shielded::ringct::MatRiCTProof& proof)
{
    DataStream meta;
    meta << std::string{TAG_INGRESS_PROOF_METADATA}
         << COMPACTSIZE(static_cast<uint64_t>(proof.input_commitments.size()))
         << COMPACTSIZE(static_cast<uint64_t>(proof.output_commitments.size()))
         << COMPACTSIZE(static_cast<uint64_t>(proof.output_range_proofs.size()))
         << proof.challenge_seed;
    if (meta.empty()) return {};
    const auto* begin = reinterpret_cast<const uint8_t*>(meta.data());
    return {begin, begin + meta.size()};
}

[[nodiscard]] std::vector<uint8_t> SerializeSmileProofMetadata(const std::vector<uint8_t>& proof_bytes)
{
    DataStream meta;
    meta << std::string{TAG_INGRESS_PROOF_METADATA}
         << COMPACTSIZE(static_cast<uint64_t>(proof_bytes.size()));
    if (meta.empty()) return {};
    const auto* begin = reinterpret_cast<const uint8_t*>(meta.data());
    return {begin, begin + meta.size()};
}

[[nodiscard]] std::vector<uint8_t> SerializeWitnessHeader(const V2IngressWitnessHeader& header)
{
    return SerializeObject(header);
}

[[nodiscard]] std::vector<uint8_t> SerializeSmileShardWitness(const V2IngressProofShardWitness& shard)
{
    return SerializeObject(*shard.smile_witness);
}

[[nodiscard]] bool ProofShardsEqual(const ProofShardDescriptor& lhs, const ProofShardDescriptor& rhs)
{
    return lhs.version == rhs.version &&
           lhs.settlement_domain == rhs.settlement_domain &&
           lhs.first_leaf_index == rhs.first_leaf_index &&
           lhs.leaf_count == rhs.leaf_count &&
           lhs.leaf_subroot == rhs.leaf_subroot &&
           lhs.nullifier_commitment == rhs.nullifier_commitment &&
           lhs.value_commitment == rhs.value_commitment &&
           lhs.statement_digest == rhs.statement_digest &&
           lhs.proof_metadata == rhs.proof_metadata &&
           lhs.proof_payload_offset == rhs.proof_payload_offset &&
           lhs.proof_payload_size == rhs.proof_payload_size;
}

[[nodiscard]] bool NativeBatchBackendMatchesMatRiCTPlus(const proof::NativeBatchBackend& backend)
{
    const auto supported_backend = proof::DescribeMatRiCTPlusNativeBatchBackend();
    return backend.version == supported_backend.version &&
           backend.backend_id == supported_backend.backend_id &&
           backend.membership_proof_kind == supported_backend.membership_proof_kind &&
           backend.amount_proof_kind == supported_backend.amount_proof_kind &&
           backend.balance_proof_kind == supported_backend.balance_proof_kind;
}

[[nodiscard]] bool NativeBatchBackendMatchesSmile(const proof::NativeBatchBackend& backend)
{
    const auto supported_backend = proof::DescribeSmileNativeBatchBackend();
    return backend.version == supported_backend.version &&
           backend.backend_id == supported_backend.backend_id &&
           backend.membership_proof_kind == supported_backend.membership_proof_kind &&
           backend.amount_proof_kind == supported_backend.amount_proof_kind &&
           backend.balance_proof_kind == supported_backend.balance_proof_kind;
}

[[nodiscard]] bool NativeBatchBackendMatchesReceiptBacked(const proof::NativeBatchBackend& backend)
{
    const auto supported_backend = proof::DescribeReceiptBackedNativeBatchBackend();
    return backend.version == supported_backend.version &&
           backend.backend_id == supported_backend.backend_id &&
           backend.membership_proof_kind == supported_backend.membership_proof_kind &&
           backend.amount_proof_kind == supported_backend.amount_proof_kind &&
           backend.balance_proof_kind == supported_backend.balance_proof_kind;
}

[[nodiscard]] std::optional<V2IngressProofShardWitness> ParseMatRiCTShardWitnessBytes(Span<const uint8_t> bytes,
                                                                                       std::string& reject_reason)
{
    DataStream shard_stream{bytes};
    V2IngressMatRiCTProofShardWitness payload;
    try {
        shard_stream >> payload;
    } catch (const std::exception&) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }
    if (!shard_stream.empty()) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }

    V2IngressProofShardWitness shard;
    shard.spends = std::move(payload.spends);
    shard.native_proof = std::move(payload.native_proof);
    return shard;
}

[[nodiscard]] std::optional<V2IngressProofShardWitness> ParseReceiptShardWitnessBytes(Span<const uint8_t> bytes,
                                                                                       std::string& reject_reason)
{
    DataStream shard_stream{bytes};
    V2IngressReceiptProofShardWitness payload;
    try {
        shard_stream >> payload;
    } catch (const std::exception&) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }
    if (!shard_stream.empty()) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }

    V2IngressProofShardWitness shard;
    shard.spends = payload.spends;
    payload.spends.clear();
    shard.receipt_witness = std::move(payload);
    return shard;
}

[[nodiscard]] std::optional<V2IngressProofShardWitness> ParseSmileShardWitnessBytes(Span<const uint8_t> bytes,
                                                                                     std::string& reject_reason)
{
    DataStream shard_stream{bytes};
    V2IngressSmileProofShardWitness payload;
    try {
        shard_stream >> payload;
    } catch (const std::exception&) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }
    if (!shard_stream.empty()) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }

    V2IngressProofShardWitness shard;
    shard.spends = payload.spends;
    payload.spends.clear();
    shard.smile_witness = std::move(payload);
    return shard;
}

[[nodiscard]] ShieldedNote BuildSyntheticCreditNote(const BridgeBatchStatement& statement,
                                                    const V2IngressLeafInput& leaf,
                                                    uint32_t index);

[[nodiscard]] std::vector<std::vector<smile2::CTPublicAccount>> BuildSmileAccountRings(
    Span<const smile2::wallet::SmileRingMember> ring_members,
    Span<const ConsumedAccountLeafSpend> consumed_spends)
{
    std::vector<std::vector<smile2::CTPublicAccount>> account_rings;
    account_rings.reserve(consumed_spends.size());
    for (const auto& spend : consumed_spends) {
        std::vector<smile2::CTPublicAccount> ring;
        ring.reserve(ring_members.size());
        for (const auto& member : ring_members) {
            ring.push_back({member.note_commitment,
                            member.public_key,
                            member.public_coin,
                            spend.account_leaf_commitment});
        }
        account_rings.push_back(std::move(ring));
    }
    return account_rings;
}

[[nodiscard]] bool SmileRingMembersEqual(const smile2::wallet::SmileRingMember& lhs,
                                         const smile2::wallet::SmileRingMember& rhs)
{
    return lhs.note_commitment == rhs.note_commitment &&
           lhs.account_leaf_commitment == rhs.account_leaf_commitment &&
           lhs.public_key.pk == rhs.public_key.pk &&
           lhs.public_key.A == rhs.public_key.A &&
           lhs.public_coin.t0 == rhs.public_coin.t0 &&
           lhs.public_coin.t_msg == rhs.public_coin.t_msg;
}

[[nodiscard]] std::optional<std::vector<smile2::wallet::SmileRingMember>> ExtractSharedSmileRingMembers(
    Span<const V2SendSpendInput> spend_inputs,
    std::string& reject_reason)
{
    if (spend_inputs.empty() || spend_inputs.front().smile_ring_members.empty()) {
        reject_reason = "bad-shielded-v2-ingress-smile-ring";
        return std::nullopt;
    }

    const auto& reference_positions = spend_inputs.front().ring_positions;
    const auto& reference_members = spend_inputs.front().smile_ring_members;
    if (!shielded::lattice::IsSupportedRingSize(reference_positions.size()) ||
        reference_members.size() != reference_positions.size()) {
        reject_reason = "bad-shielded-v2-ingress-smile-ring";
        return std::nullopt;
    }

    for (const auto& input : spend_inputs) {
        if (input.ring_positions != reference_positions ||
            input.smile_ring_members.size() != reference_members.size()) {
            reject_reason = "bad-shielded-v2-ingress-smile-ring";
            return std::nullopt;
        }
        for (size_t i = 0; i < reference_members.size(); ++i) {
            if (!SmileRingMembersEqual(input.smile_ring_members[i], reference_members[i])) {
                reject_reason = "bad-shielded-v2-ingress-smile-ring";
                return std::nullopt;
            }
        }
    }

    return reference_members;
}

[[nodiscard]] std::optional<std::vector<smile2::BDLOPCommitment>> CollectIngressSmileOutputCoins(
    Span<const OutputDescription> reserve_outputs,
    const BridgeBatchStatement& statement,
    Span<const V2IngressLeafInput> ingress_leaves,
    uint32_t first_leaf_index)
{
    std::vector<smile2::BDLOPCommitment> output_coins;
    output_coins.reserve(reserve_outputs.size() + ingress_leaves.size());

    for (const auto& output : reserve_outputs) {
        if (!output.smile_account.has_value() ||
            smile2::ComputeCompactPublicAccountHash(*output.smile_account) != output.note_commitment) {
            return std::nullopt;
        }
        output_coins.push_back(output.smile_account->public_coin);
    }

    for (size_t i = 0; i < ingress_leaves.size(); ++i) {
        const ShieldedNote note = BuildSyntheticCreditNote(statement,
                                                           ingress_leaves[i],
                                                           first_leaf_index + static_cast<uint32_t>(i));
        if (!note.IsValid()) {
            return std::nullopt;
        }
        output_coins.push_back(smile2::wallet::BuildPublicCoinFromNote(note));
    }

    return output_coins;
}

[[nodiscard]] std::optional<CAmount> SumBridgeLeafAmounts(Span<const V2IngressLeafInput> leaves)
{
    CAmount total{0};
    for (const auto& leaf : leaves) {
        const auto next_total = CheckedAdd(total, leaf.bridge_leaf.amount);
        if (!next_total || !MoneyRange(*next_total)) return std::nullopt;
        total = *next_total;
    }
    return total;
}

[[nodiscard]] std::optional<CAmount> SumLeafFees(Span<const V2IngressLeafInput> leaves)
{
    CAmount total{0};
    for (const auto& leaf : leaves) {
        const auto next_total = CheckedAdd(total, leaf.fee);
        if (!next_total || !MoneyRange(*next_total)) return std::nullopt;
        total = *next_total;
    }
    return total;
}

[[nodiscard]] std::optional<CAmount> SumNoteValues(Span<const ShieldedNote> notes)
{
    CAmount total{0};
    for (const auto& note : notes) {
        const auto next_total = CheckedAdd(total, note.value);
        if (!next_total || !MoneyRange(*next_total)) return std::nullopt;
        total = *next_total;
    }
    return total;
}

[[nodiscard]] bool StatementRequiresIngressSettlementWitness(const BridgeBatchStatement& statement)
{
    return statement.verifier_set.IsValid() || statement.proof_policy.IsValid();
}

[[nodiscard]] bool VerifyIngressSignedReceiptSet(const BridgeBatchStatement& statement,
                                                 const V2IngressSettlementWitness& witness,
                                                 std::string& reject_reason)
{
    if (!statement.verifier_set.IsValid()) {
        if (!witness.signed_receipts.empty() || !witness.signed_receipt_proofs.empty()) {
            reject_reason = "bad-shielded-v2-ingress-signed-receipts";
            return false;
        }
        return true;
    }

    if (witness.signed_receipts.size() < static_cast<size_t>(statement.verifier_set.required_signers)) {
        reject_reason = "bad-shielded-v2-ingress-signed-threshold";
        return false;
    }
    if (CountDistinctBridgeBatchReceiptAttestors(witness.signed_receipts) != witness.signed_receipts.size()) {
        reject_reason = "bad-shielded-v2-ingress-signed-duplicate";
        return false;
    }

    const uint256 statement_hash = ComputeBridgeBatchStatementHash(statement);
    if (statement_hash.IsNull()) {
        reject_reason = "bad-shielded-v2-ingress-statement";
        return false;
    }

    for (size_t i = 0; i < witness.signed_receipts.size(); ++i) {
        const auto& receipt = witness.signed_receipts[i];
        if (!VerifyBridgeBatchReceipt(receipt) ||
            ComputeBridgeBatchStatementHash(receipt.statement) != statement_hash) {
            reject_reason = "bad-shielded-v2-ingress-signed-receipts";
            return false;
        }
        if (!VerifyBridgeVerifierSetProof(statement.verifier_set,
                                          receipt.attestor,
                                          witness.signed_receipt_proofs[i])) {
            reject_reason = "bad-shielded-v2-ingress-signed-membership";
            return false;
        }
    }

    return true;
}

[[nodiscard]] bool VerifyIngressProofReceiptSet(const BridgeBatchStatement& statement,
                                                const V2IngressSettlementWitness& witness,
                                                std::string& reject_reason)
{
    if (!statement.proof_policy.IsValid()) {
        if (!witness.proof_receipts.empty() || !witness.proof_receipt_descriptor_proofs.empty()) {
            reject_reason = "bad-shielded-v2-ingress-proof-receipts";
            return false;
        }
        return true;
    }

    if (witness.proof_receipts.size() < static_cast<size_t>(statement.proof_policy.required_receipts)) {
        reject_reason = "bad-shielded-v2-ingress-proof-threshold";
        return false;
    }
    if (CountDistinctBridgeProofReceipts(witness.proof_receipts) != witness.proof_receipts.size()) {
        reject_reason = "bad-shielded-v2-ingress-proof-duplicate";
        return false;
    }

    const uint256 statement_hash = ComputeBridgeBatchStatementHash(statement);
    if (statement_hash.IsNull()) {
        reject_reason = "bad-shielded-v2-ingress-statement";
        return false;
    }

    for (size_t i = 0; i < witness.proof_receipts.size(); ++i) {
        const auto& receipt = witness.proof_receipts[i];
        const BridgeProofDescriptor descriptor{receipt.proof_system_id, receipt.verifier_key_hash};
        if (!receipt.IsValid() || receipt.statement_hash != statement_hash || !descriptor.IsValid()) {
            reject_reason = "bad-shielded-v2-ingress-proof-receipts";
            return false;
        }
        if (!VerifyBridgeProofPolicyProof(statement.proof_policy,
                                          descriptor,
                                          witness.proof_receipt_descriptor_proofs[i])) {
            reject_reason = "bad-shielded-v2-ingress-proof-descriptor";
            return false;
        }
    }

    return true;
}

[[nodiscard]] bool VerifyIngressSettlementWitness(const BridgeBatchStatement& statement,
                                                  const V2IngressSettlementWitness& witness,
                                                  std::string& reject_reason)
{
    if (!witness.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-settlement-witness";
        return false;
    }
    if (!VerifyIngressSignedReceiptSet(statement, witness, reject_reason)) {
        return false;
    }
    if (!VerifyIngressProofReceiptSet(statement, witness, reject_reason)) {
        return false;
    }

    if (statement.verifier_set.IsValid() && statement.proof_policy.IsValid()) {
        const auto anchor = BuildBridgeExternalAnchorFromHybridWitness(statement,
                                                                       witness.signed_receipts,
                                                                       witness.proof_receipts);
        if (!anchor.has_value()) {
            reject_reason = "bad-shielded-v2-ingress-hybrid-anchor";
            return false;
        }
        return true;
    }
    if (statement.verifier_set.IsValid()) {
        const auto anchor = BuildBridgeExternalAnchorFromStatement(statement, witness.signed_receipts);
        if (!anchor.has_value()) {
            reject_reason = "bad-shielded-v2-ingress-signed-anchor";
            return false;
        }
        return true;
    }

    const auto anchor = BuildBridgeExternalAnchorFromProofReceipts(statement, witness.proof_receipts);
    if (!anchor.has_value()) {
        reject_reason = "bad-shielded-v2-ingress-proof-anchor";
        return false;
    }
    return true;
}

[[nodiscard]] std::vector<BridgeBatchLeaf> ExtractBridgeLeaves(Span<const V2IngressLeafInput> leaves)
{
    std::vector<BridgeBatchLeaf> bridge_leaves;
    bridge_leaves.reserve(leaves.size());
    for (const auto& leaf : leaves) {
        bridge_leaves.push_back(leaf.bridge_leaf);
    }
    return bridge_leaves;
}

[[nodiscard]] ShieldedNote BuildSyntheticCreditNote(const BridgeBatchStatement& statement,
                                                    const V2IngressLeafInput& leaf,
                                                    uint32_t index)
{
    const uint256 statement_hash = ComputeBridgeBatchStatementHash(statement);

    ShieldedNote note;
    note.value = leaf.bridge_leaf.amount;
    note.recipient_pk_hash = HashTaggedIndex(TAG_INGRESS_CREDIT_PKH, statement_hash, index, leaf.l2_id);
    note.rho = HashTaggedIndex(TAG_INGRESS_CREDIT_RHO, statement_hash, index, leaf.bridge_leaf.authorization_hash);
    note.rcm = HashTaggedIndex(TAG_INGRESS_CREDIT_RCM, statement_hash, index, leaf.bridge_leaf.destination_id);
    return note;
}

[[nodiscard]] uint256 ComputeConsumedNullifierCommitment(Span<const uint256> nullifiers)
{
    if (nullifiers.empty()) return uint256{};
    const std::vector<uint256> nullifier_vec{nullifiers.begin(), nullifiers.end()};
    return HashTaggedObject(TAG_INGRESS_NULLIFIER_COMMITMENT, nullifier_vec);
}

[[nodiscard]] uint256 ComputeIngressProofValueCommitment(Span<const OutputDescription> reserve_outputs,
                                                         Span<const BatchLeaf> ingress_leaves,
                                                         const uint256& settlement_binding_digest)
{
    const uint256 reserve_commitment = ComputeV2IngressAggregateReserveCommitment(reserve_outputs);
    const uint256 credit_root = ComputeV2IngressL2CreditRoot(ingress_leaves);
    const uint256 fee_commitment = ComputeV2IngressAggregateFeeCommitment(ingress_leaves);
    if ((!reserve_outputs.empty() && reserve_commitment.IsNull()) ||
        credit_root.IsNull() ||
        fee_commitment.IsNull() ||
        settlement_binding_digest.IsNull()) {
        return uint256{};
    }

    HashWriter hw;
    hw << std::string{TAG_INGRESS_PROOF_VALUE_COMMITMENT}
       << reserve_commitment
       << credit_root
       << fee_commitment
       << settlement_binding_digest;
    return hw.GetSHA256();
}

[[nodiscard]] ProofShardDescriptor BuildIngressProofShard(Span<const uint256> nullifiers,
                                                          Span<const OutputDescription> reserve_outputs,
                                                          Span<const BatchLeaf> ingress_leaves,
                                                          const shielded::ringct::MatRiCTProof& proof,
                                                          const uint256& statement_digest,
                                                          const uint256& settlement_domain,
                                                          uint32_t first_leaf_index,
                                                          uint32_t proof_payload_offset,
                                                          uint32_t proof_payload_size)
{
    ProofShardDescriptor descriptor;
    descriptor.settlement_domain = settlement_domain;
    descriptor.first_leaf_index = first_leaf_index;
    descriptor.leaf_count = static_cast<uint32_t>(ingress_leaves.size());
    descriptor.leaf_subroot = ComputeBatchLeafRoot(ingress_leaves);
    descriptor.nullifier_commitment = ComputeConsumedNullifierCommitment(nullifiers);
    descriptor.value_commitment = ComputeIngressProofValueCommitment(
        reserve_outputs,
        ingress_leaves,
        statement_digest);
    descriptor.statement_digest = statement_digest;
    descriptor.proof_metadata = SerializeMatRiCTProofMetadata(proof);
    descriptor.proof_payload_offset = proof_payload_offset;
    descriptor.proof_payload_size = proof_payload_size;
    return descriptor;
}

[[nodiscard]] ProofShardDescriptor BuildIngressReceiptBackedProofShard(
    const BridgeProofReceipt& receipt,
    Span<const uint256> nullifiers,
    Span<const OutputDescription> reserve_outputs,
    Span<const BatchLeaf> ingress_leaves,
    const uint256& statement_digest,
    const uint256& settlement_domain,
    uint32_t first_leaf_index,
    uint32_t proof_payload_offset,
    uint32_t proof_payload_size)
{
    ProofShardDescriptor descriptor;
    descriptor.settlement_domain = settlement_domain;
    descriptor.first_leaf_index = first_leaf_index;
    descriptor.leaf_count = static_cast<uint32_t>(ingress_leaves.size());
    descriptor.leaf_subroot = ComputeBatchLeafRoot(ingress_leaves);
    descriptor.nullifier_commitment = ComputeConsumedNullifierCommitment(nullifiers);
    descriptor.value_commitment = ComputeIngressProofValueCommitment(
        reserve_outputs,
        ingress_leaves,
        statement_digest);
    descriptor.statement_digest = statement_digest;
    descriptor.proof_metadata = SerializeBridgeProofReceipt(receipt);
    descriptor.proof_payload_offset = proof_payload_offset;
    descriptor.proof_payload_size = proof_payload_size;
    return descriptor;
}

[[nodiscard]] std::optional<ProofShardDescriptor> BuildIngressSmileProofShardForBackend(
    const proof::NativeBatchBackend& backend,
    Span<const uint256> nullifiers,
    Span<const OutputDescription> reserve_outputs,
    Span<const BatchLeaf> ingress_leaves,
    Span<const uint8_t> smile_proof_bytes,
    const uint256& statement_digest,
    const uint256& settlement_domain,
    uint32_t first_leaf_index,
    uint32_t proof_payload_offset,
    uint32_t proof_payload_size,
    std::string& reject_reason)
{
    if (!NativeBatchBackendMatchesSmile(backend) || smile_proof_bytes.empty()) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }

    ProofShardDescriptor descriptor;
    descriptor.settlement_domain = settlement_domain;
    descriptor.first_leaf_index = first_leaf_index;
    descriptor.leaf_count = static_cast<uint32_t>(ingress_leaves.size());
    descriptor.leaf_subroot = ComputeBatchLeafRoot(ingress_leaves);
    descriptor.nullifier_commitment = ComputeConsumedNullifierCommitment(nullifiers);
    descriptor.value_commitment = ComputeIngressProofValueCommitment(
        reserve_outputs,
        ingress_leaves,
        statement_digest);
    descriptor.statement_digest = statement_digest;
    descriptor.proof_metadata = SerializeSmileProofMetadata(
        std::vector<uint8_t>{smile_proof_bytes.begin(), smile_proof_bytes.end()});
    descriptor.proof_payload_offset = proof_payload_offset;
    descriptor.proof_payload_size = proof_payload_size;
    return descriptor;
}

[[nodiscard]] std::optional<ProofShardDescriptor> BuildIngressMatRiCTProofShardForBackend(
    const proof::NativeBatchBackend& backend,
    Span<const uint256> nullifiers,
    Span<const OutputDescription> reserve_outputs,
    Span<const BatchLeaf> ingress_leaves,
    const shielded::ringct::MatRiCTProof& proof,
    const uint256& statement_digest,
    const uint256& settlement_domain,
    uint32_t first_leaf_index,
    uint32_t proof_payload_offset,
    uint32_t proof_payload_size,
    std::string& reject_reason)
{
    if (!NativeBatchBackendMatchesMatRiCTPlus(backend)) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }

    return BuildIngressProofShard(nullifiers,
                                  reserve_outputs,
                                  ingress_leaves,
                                  proof,
                                  statement_digest,
                                  settlement_domain,
                                  first_leaf_index,
                                  proof_payload_offset,
                                  proof_payload_size);
}

[[nodiscard]] std::optional<ProofShardDescriptor> BuildIngressReceiptProofShardForBackend(
    const proof::NativeBatchBackend& backend,
    const BridgeProofReceipt& receipt,
    Span<const uint256> nullifiers,
    Span<const OutputDescription> reserve_outputs,
    Span<const BatchLeaf> ingress_leaves,
    const uint256& statement_digest,
    const uint256& settlement_domain,
    uint32_t first_leaf_index,
    uint32_t proof_payload_offset,
    uint32_t proof_payload_size,
    std::string& reject_reason)
{
    if (!NativeBatchBackendMatchesReceiptBacked(backend) || !receipt.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }

    return BuildIngressReceiptBackedProofShard(receipt,
                                               nullifiers,
                                               reserve_outputs,
                                               ingress_leaves,
                                               statement_digest,
                                               settlement_domain,
                                               first_leaf_index,
                                               proof_payload_offset,
                                               proof_payload_size);
}

[[nodiscard]] bool VerifyIngressNativeProofForBackend(
    const proof::NativeBatchBackend& backend,
    const shielded::ringct::MatRiCTProof& proof,
    const std::vector<std::vector<uint256>>& ring_members,
    const std::vector<Nullifier>& input_nullifiers,
    const std::vector<uint256>& output_note_commitments,
    CAmount fee,
    const uint256& statement_digest,
    std::string& reject_reason)
{
    if (!NativeBatchBackendMatchesMatRiCTPlus(backend)) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return false;
    }

    if (!shielded::ringct::VerifyMatRiCTProof(proof,
                                              ring_members,
                                              input_nullifiers,
                                              output_note_commitments,
                                              fee,
                                              statement_digest)) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return false;
    }
    return true;
}

[[nodiscard]] bool VerifyIngressSmileProofForBackend(
    const proof::NativeBatchBackend& backend,
    Span<const uint8_t> smile_proof_bytes,
    Span<const smile2::wallet::SmileRingMember> shared_ring_members,
    Span<const ConsumedAccountLeafSpend> consumed_spends,
    Span<const uint256> input_nullifiers,
    const std::vector<smile2::BDLOPCommitment>& output_coins,
    CAmount fee,
    std::string& reject_reason,
    bool reject_rice_codec,
    bool bind_anonset_context)
{
    if (!NativeBatchBackendMatchesSmile(backend) ||
        shared_ring_members.empty() ||
        consumed_spends.empty() ||
        consumed_spends.size() != input_nullifiers.size() ||
        input_nullifiers.empty()) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return false;
    }

    smile2::CTPublicData pub;
    pub.anon_set = smile2::wallet::BuildAnonymitySet(shared_ring_members);
    std::vector<smile2::BDLOPCommitment> shared_coin_ring;
    shared_coin_ring.reserve(shared_ring_members.size());
    for (const auto& member : shared_ring_members) {
        if (!member.IsValid()) {
            reject_reason = "bad-shielded-v2-ingress-smile-ring";
            return false;
        }
        shared_coin_ring.push_back(member.public_coin);
    }
    pub.coin_rings.assign(input_nullifiers.size(), shared_coin_ring);
    pub.account_rings = BuildSmileAccountRings(shared_ring_members, consumed_spends);

    if (auto verify_err = smile2::VerifySmile2CTFromBytes(
            std::vector<uint8_t>{smile_proof_bytes.begin(), smile_proof_bytes.end()},
            input_nullifiers.size(),
            output_coins.size(),
            output_coins,
            pub,
            fee,
            reject_rice_codec,
            bind_anonset_context);
        verify_err.has_value()) {
        reject_reason = *verify_err;
        return false;
    }
    return true;
}

[[nodiscard]] TransactionBundle BuildEmptyIngressBundle(const IngressBatchPayload& payload,
                                                        const ProofEnvelope& envelope,
                                                        const Consensus::Params* consensus,
                                                        int32_t validation_height)
{
    TransactionBundle bundle;
    bundle.header.family_id = GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                                                          consensus,
                                                                          validation_height);
    bundle.header.proof_envelope = envelope;
    bundle.payload = payload;
    bundle.header.payload_digest = ComputeIngressBatchPayloadDigest(payload);
    if (UseDerivedGenericOutputChunkWire(bundle.header, bundle.payload)) {
        if (auto output_chunks = BuildDerivedGenericOutputChunks(bundle.payload); output_chunks.has_value()) {
            bundle.output_chunks = std::move(*output_chunks);
            bundle.header.output_chunk_root = bundle.output_chunks.empty()
                ? uint256::ZERO
                : ComputeOutputChunkRoot({bundle.output_chunks.data(), bundle.output_chunks.size()});
            bundle.header.output_chunk_count = bundle.output_chunks.size();
        }
    }
    return bundle;
}

struct IngressShardPlan
{
    size_t spend_index{0};
    size_t spend_count{0};
    size_t reserve_output_index{0};
    size_t reserve_output_count{0};
    size_t leaf_index{0};
    size_t leaf_count{0};

    [[nodiscard]] bool IsValid(size_t max_outputs_per_proof_shard) const
    {
        return spend_count > 0 &&
               leaf_count > 0 &&
               reserve_output_count + leaf_count <= max_outputs_per_proof_shard;
    }
};

[[nodiscard]] CAmount ComputeLeafTransferValue(const V2IngressLeafInput& leaf)
{
    return leaf.bridge_leaf.amount + leaf.fee;
}

[[nodiscard]] std::vector<CAmount> BuildPrefixTotals(Span<const CAmount> values)
{
    std::vector<CAmount> prefix_totals;
    prefix_totals.reserve(values.size() + 1);
    prefix_totals.push_back(0);
    for (const CAmount value : values) {
        prefix_totals.push_back(prefix_totals.back() + value);
    }
    return prefix_totals;
}

[[nodiscard]] CAmount PrefixDelta(const std::vector<CAmount>& prefix_totals, size_t begin, size_t count)
{
    return prefix_totals[begin + count] - prefix_totals[begin];
}

[[nodiscard]] std::optional<std::vector<IngressShardPlan>> BuildCanonicalIngressShardPlan(
    Span<const CAmount> spend_values,
    Span<const CAmount> reserve_values,
    Span<const CAmount> leaf_values,
    size_t max_outputs_per_proof_shard)
{
    if (max_outputs_per_proof_shard == 0) return std::nullopt;

    const auto spend_prefix = BuildPrefixTotals(spend_values);
    const auto reserve_prefix = BuildPrefixTotals(reserve_values);
    const auto leaf_prefix = BuildPrefixTotals(leaf_values);

    struct StateKey {
        size_t spend_index;
        size_t reserve_index;
        size_t leaf_index;
        [[nodiscard]] bool operator<(const StateKey& other) const
        {
            return std::tie(spend_index, reserve_index, leaf_index) <
                   std::tie(other.spend_index, other.reserve_index, other.leaf_index);
        }
    };

    std::map<StateKey, std::optional<std::vector<IngressShardPlan>>> memo;
    std::function<std::optional<std::vector<IngressShardPlan>>(size_t, size_t, size_t)> build =
        [&](size_t spend_index, size_t reserve_index, size_t leaf_index)
        -> std::optional<std::vector<IngressShardPlan>> {
            const StateKey key{spend_index, reserve_index, leaf_index};
            auto memo_it = memo.find(key);
            if (memo_it != memo.end()) return memo_it->second;

            const size_t remaining_spends = spend_values.size() - spend_index;
            const size_t remaining_reserves = reserve_values.size() - reserve_index;
            const size_t remaining_leaves = leaf_values.size() - leaf_index;
            if (remaining_spends == 0 || remaining_leaves == 0) {
                if (remaining_spends == 0 && remaining_reserves == 0 && remaining_leaves == 0) {
                    return memo.emplace(key, std::vector<IngressShardPlan>{}).first->second;
                }
                return memo.emplace(key, std::nullopt).first->second;
            }

            if (PrefixDelta(spend_prefix, spend_index, remaining_spends) !=
                PrefixDelta(reserve_prefix, reserve_index, remaining_reserves) +
                    PrefixDelta(leaf_prefix, leaf_index, remaining_leaves)) {
                return memo.emplace(key, std::nullopt).first->second;
            }

            const size_t max_leaf_count =
                std::min<size_t>(remaining_leaves, max_outputs_per_proof_shard);
            for (size_t leaf_count = max_leaf_count; leaf_count >= 1; --leaf_count) {
                const size_t max_reserve_count = std::min<size_t>(
                    remaining_reserves,
                    max_outputs_per_proof_shard - leaf_count);
                for (size_t reserve_count = 0; reserve_count <= max_reserve_count; ++reserve_count) {
                    const CAmount output_total =
                        PrefixDelta(reserve_prefix, reserve_index, reserve_count) +
                        PrefixDelta(leaf_prefix, leaf_index, leaf_count);
                    const CAmount target_input_total = spend_prefix[spend_index] + output_total;
                    const auto spend_end_it = std::lower_bound(
                        spend_prefix.begin() + static_cast<std::ptrdiff_t>(spend_index + 1),
                        spend_prefix.begin() + static_cast<std::ptrdiff_t>(
                            std::min(spend_values.size(), spend_index + shielded::ringct::MAX_MATRICT_INPUTS) + 1),
                        target_input_total);
                    if (spend_end_it == spend_prefix.end() || *spend_end_it != target_input_total) {
                        continue;
                    }

                    const size_t spend_end = static_cast<size_t>(std::distance(spend_prefix.begin(), spend_end_it));
                    const IngressShardPlan shard{
                        spend_index,
                        spend_end - spend_index,
                        reserve_index,
                        reserve_count,
                        leaf_index,
                        leaf_count,
                    };
                    if (!shard.IsValid(max_outputs_per_proof_shard)) continue;

                    auto remainder = build(spend_end, reserve_index + reserve_count, leaf_index + leaf_count);
                    if (!remainder.has_value()) continue;

                    std::vector<IngressShardPlan> shards;
                    shards.reserve(1 + remainder->size());
                    shards.push_back(shard);
                    shards.insert(shards.end(), remainder->begin(), remainder->end());
                    return memo.emplace(key, std::move(shards)).first->second;
                }
                if (leaf_count == 1) break;
            }

            return memo.emplace(key, std::nullopt).first->second;
        };

    return build(0, 0, 0);
}

[[nodiscard]] std::vector<CAmount> BuildSpendValues(Span<const V2SendSpendInput> spend_inputs)
{
    std::vector<CAmount> spend_values;
    spend_values.reserve(spend_inputs.size());
    for (const auto& spend_input : spend_inputs) {
        spend_values.push_back(spend_input.note.value);
    }
    return spend_values;
}

[[nodiscard]] std::vector<CAmount> BuildReserveValues(Span<const V2SendOutputInput> reserve_outputs)
{
    std::vector<CAmount> reserve_values;
    reserve_values.reserve(reserve_outputs.size());
    for (const auto& reserve_output : reserve_outputs) {
        reserve_values.push_back(reserve_output.note.value);
    }
    return reserve_values;
}

[[nodiscard]] std::vector<CAmount> BuildLeafValues(Span<const V2IngressLeafInput> ingress_leaves)
{
    std::vector<CAmount> leaf_values;
    leaf_values.reserve(ingress_leaves.size());
    for (const auto& ingress_leaf : ingress_leaves) {
        leaf_values.push_back(ComputeLeafTransferValue(ingress_leaf));
    }
    return leaf_values;
}

} // namespace

uint256 ComputeV2IngressPlaceholderReserveValueCommitment(const uint256& settlement_binding_digest,
                                                          uint32_t output_index,
                                                          const uint256& note_commitment)
{
    if (settlement_binding_digest.IsNull() || note_commitment.IsNull()) return uint256{};
    return HashTaggedIndex(
        TAG_INGRESS_PLACEHOLDER_RESERVE_VALUE,
        settlement_binding_digest,
        output_index,
        note_commitment);
}

uint256 ComputeV2IngressSyntheticCreditNoteCommitment(const BridgeBatchStatement& statement,
                                                      const V2IngressLeafInput& leaf,
                                                      uint32_t index)
{
    const ShieldedNote note = BuildSyntheticCreditNote(statement, leaf, index);
    return note.IsValid() ? note.GetCommitment() : uint256{};
}

BatchLeaf BuildV2IngressPayloadLeaf(const BridgeBatchStatement& statement,
                                    const V2IngressLeafInput& ingress_input,
                                    uint32_t index,
                                    const Consensus::Params* consensus,
                                    int32_t validation_height)
{
    BatchLeaf leaf;
    leaf.family_id = GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                                                 consensus,
                                                                 validation_height);
    leaf.l2_id = ingress_input.l2_id;
    leaf.destination_commitment = ComputeV2IngressDestinationCommitment(
        ingress_input.bridge_leaf,
        ingress_input.l2_id,
        statement.domain_id);
    leaf.amount_commitment = ComputeV2IngressPlaceholderReserveValueCommitment(
        ComputeBridgeBatchStatementHash(statement),
        index,
        ingress_input.bridge_leaf.authorization_hash);
    leaf.fee_commitment = ComputeV2IngressFeeCommitment(
        ingress_input.bridge_leaf,
        ingress_input.l2_id,
        ingress_input.fee,
        statement.domain_id);
    leaf.position = index;
    leaf.nonce = HashTaggedIndex(
        TAG_INGRESS_LEAF_NONCE,
        ComputeBridgeBatchStatementHash(statement),
        index,
        ingress_input.bridge_leaf.wallet_id);
    leaf.settlement_domain = statement.domain_id;
    return leaf;
}

uint256 ComputeV2IngressReceiptPublicValuesHash(Span<const uint256> nullifiers,
                                                Span<const OutputDescription> reserve_outputs,
                                                Span<const BatchLeaf> ingress_leaves,
                                                Span<const uint256> ingress_note_commitments,
                                                CAmount fee,
                                                const uint256& statement_digest)
{
    if (nullifiers.empty() ||
        ingress_leaves.empty() ||
        ingress_note_commitments.size() != ingress_leaves.size() ||
        fee < 0 ||
        !MoneyRange(fee) ||
        statement_digest.IsNull()) {
        return uint256{};
    }

    const std::vector<uint256> nullifier_vec{nullifiers.begin(), nullifiers.end()};
    const std::vector<OutputDescription> reserve_vec{reserve_outputs.begin(), reserve_outputs.end()};
    const std::vector<BatchLeaf> leaf_vec{ingress_leaves.begin(), ingress_leaves.end()};
    const std::vector<uint256> note_commitment_vec{ingress_note_commitments.begin(), ingress_note_commitments.end()};

    HashWriter hw;
    hw << std::string{"BTX_ShieldedV2_Ingress_Receipt_PublicValues_V1"}
       << nullifier_vec
       << reserve_vec
       << leaf_vec
       << note_commitment_vec
       << fee
       << statement_digest;
    return hw.GetSHA256();
}

bool V2IngressShardScheduleEntry::IsValid() const
{
    return IsValid(MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD);
}

bool V2IngressShardScheduleEntry::IsValid(size_t max_outputs_per_proof_shard) const
{
    return spend_count > 0 &&
           leaf_count > 0 &&
           TotalOutputCount() <= max_outputs_per_proof_shard;
}

uint32_t V2IngressShardScheduleEntry::TotalOutputCount() const
{
    return reserve_output_count + leaf_count;
}

bool V2IngressShardSchedule::IsValid(size_t expected_spend_count,
                                     size_t expected_reserve_output_count,
                                     size_t expected_leaf_count) const
{
    return IsValid(expected_spend_count,
                   expected_reserve_output_count,
                   expected_leaf_count,
                   MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD);
}

bool V2IngressShardSchedule::IsValid(size_t expected_spend_count,
                                     size_t expected_reserve_output_count,
                                     size_t expected_leaf_count,
                                     size_t max_outputs_per_proof_shard) const
{
    if (shards.empty()) return false;

    size_t spend_cursor{0};
    size_t reserve_cursor{0};
    size_t leaf_cursor{0};
    for (const auto& shard : shards) {
        if (!shard.IsValid(max_outputs_per_proof_shard)) {
            return false;
        }
        if (shard.spend_index != spend_cursor ||
            shard.reserve_output_index != reserve_cursor ||
            shard.leaf_index != leaf_cursor) {
            return false;
        }
        spend_cursor += shard.spend_count;
        reserve_cursor += shard.reserve_output_count;
        leaf_cursor += shard.leaf_count;
    }

    return spend_cursor == expected_spend_count &&
           reserve_cursor == expected_reserve_output_count &&
           leaf_cursor == expected_leaf_count;
}

size_t V2IngressShardSchedule::MaxSpendInputCount() const
{
    size_t max_count{0};
    for (const auto& shard : shards) {
        max_count = std::max(max_count, static_cast<size_t>(shard.spend_count));
    }
    return max_count;
}

size_t V2IngressShardSchedule::MaxReserveOutputCount() const
{
    size_t max_count{0};
    for (const auto& shard : shards) {
        max_count = std::max(max_count, static_cast<size_t>(shard.reserve_output_count));
    }
    return max_count;
}

size_t V2IngressShardSchedule::MaxIngressLeafCount() const
{
    size_t max_count{0};
    for (const auto& shard : shards) {
        max_count = std::max(max_count, static_cast<size_t>(shard.leaf_count));
    }
    return max_count;
}

size_t V2IngressShardSchedule::MaxOutputCount() const
{
    size_t max_count{0};
    for (const auto& shard : shards) {
        max_count = std::max(max_count, static_cast<size_t>(shard.TotalOutputCount()));
    }
    return max_count;
}

std::optional<V2IngressShardSchedule> BuildCanonicalV2IngressShardSchedule(
    Span<const CAmount> spend_values,
    Span<const CAmount> reserve_values,
    Span<const V2IngressLeafInput> ingress_leaves)
{
    return BuildCanonicalV2IngressShardSchedule(
        spend_values,
        reserve_values,
        ingress_leaves,
        proof::SelectDefaultNativeBatchBackend());
}

std::optional<V2IngressShardSchedule> BuildCanonicalV2IngressShardSchedule(
    Span<const CAmount> spend_values,
    Span<const CAmount> reserve_values,
    Span<const V2IngressLeafInput> ingress_leaves,
    const proof::NativeBatchBackend& backend)
{
    if (spend_values.empty() || reserve_values.empty() || ingress_leaves.empty()) {
        return std::nullopt;
    }
    const size_t max_outputs_per_proof_shard = GetMaxIngressOutputsPerProofShard(backend);
    if (max_outputs_per_proof_shard == 0) {
        return std::nullopt;
    }

    const auto leaf_values = BuildLeafValues(ingress_leaves);
    const auto shard_plan = BuildCanonicalIngressShardPlan(
        spend_values,
        reserve_values,
        Span<const CAmount>{leaf_values.data(), leaf_values.size()},
        max_outputs_per_proof_shard);
    if (!shard_plan.has_value() || shard_plan->empty()) {
        return std::nullopt;
    }

    V2IngressShardSchedule schedule;
    schedule.shards.reserve(shard_plan->size());
    for (const auto& shard : *shard_plan) {
        schedule.shards.push_back(V2IngressShardScheduleEntry{
            static_cast<uint32_t>(shard.spend_index),
            static_cast<uint32_t>(shard.spend_count),
            static_cast<uint32_t>(shard.reserve_output_index),
            static_cast<uint32_t>(shard.reserve_output_count),
            static_cast<uint32_t>(shard.leaf_index),
            static_cast<uint32_t>(shard.leaf_count),
        });
    }
    if (!schedule.IsValid(spend_values.size(),
                          reserve_values.size(),
                          ingress_leaves.size(),
                          max_outputs_per_proof_shard)) {
        return std::nullopt;
    }
    return schedule;
}

bool V2IngressLeafInput::IsValid() const
{
    return version == WIRE_VERSION &&
           bridge_leaf.IsValid() &&
           bridge_leaf.kind == BridgeBatchLeafKind::SHIELD_CREDIT &&
           !l2_id.IsNull() &&
           fee >= 0 &&
           MoneyRange(fee);
}

bool V2IngressSpendWitness::IsValid() const
{
    return version == WIRE_VERSION &&
           shielded::lattice::IsSupportedRingSize(ring_positions.size()) &&
           real_index == 0 &&
           note_commitment.IsNull();
}

bool V2IngressSettlementWitness::IsValid() const
{
    if (version != WIRE_VERSION) return false;
    if (signed_receipts.size() != signed_receipt_proofs.size()) return false;
    if (proof_receipts.size() != proof_receipt_descriptor_proofs.size()) return false;
    if (signed_receipts.size() > MAX_SETTLEMENT_REFS ||
        signed_receipt_proofs.size() > MAX_SETTLEMENT_REFS ||
        proof_receipts.size() > MAX_SETTLEMENT_REFS ||
        proof_receipt_descriptor_proofs.size() > MAX_SETTLEMENT_REFS) {
        return false;
    }

    return std::all_of(signed_receipts.begin(), signed_receipts.end(), [](const BridgeBatchReceipt& receipt) {
               return receipt.IsValid();
           }) &&
           std::all_of(signed_receipt_proofs.begin(),
                       signed_receipt_proofs.end(),
                       [](const BridgeVerifierSetProof& proof) {
                           return proof.IsValid();
                       }) &&
           std::all_of(proof_receipts.begin(), proof_receipts.end(), [](const BridgeProofReceipt& receipt) {
               return receipt.IsValid();
           }) &&
           std::all_of(proof_receipt_descriptor_proofs.begin(),
                       proof_receipt_descriptor_proofs.end(),
                       [](const BridgeProofPolicyProof& proof) {
                           return proof.IsValid();
                       });
}

bool V2IngressWitnessHeader::IsValid(size_t expected_leaf_count) const
{
    if (version != WIRE_VERSION ||
        !statement.IsValid() ||
        statement.direction != BridgeDirection::BRIDGE_IN ||
        ingress_leaves.size() != expected_leaf_count ||
        !std::all_of(ingress_leaves.begin(), ingress_leaves.end(), [](const V2IngressLeafInput& leaf) {
            return leaf.IsValid();
        })) {
        return false;
    }

    const bool requires_settlement_witness = StatementRequiresIngressSettlementWitness(statement);
    if (settlement_witness.has_value() != requires_settlement_witness) {
        return false;
    }

    return version == WIRE_VERSION &&
           (!settlement_witness.has_value() || settlement_witness->IsValid());
}

bool V2IngressMatRiCTProofShardWitness::IsValid(size_t expected_input_count,
                                                size_t expected_output_count) const
{
    return version == WIRE_VERSION &&
           spends.size() == expected_input_count &&
           expected_output_count > 0 &&
           expected_output_count <= MAX_MATRICT_INGRESS_OUTPUTS_PER_PROOF_SHARD &&
           std::all_of(spends.begin(), spends.end(), [](const V2IngressSpendWitness& spend) {
               return spend.IsValid();
           }) &&
           native_proof.input_commitments.size() == expected_input_count &&
           native_proof.output_commitments.size() == expected_output_count &&
           native_proof.output_range_proofs.size() == expected_output_count &&
           native_proof.output_note_commitments.size() == expected_output_count &&
           native_proof.IsValid();
}

bool V2IngressReceiptProofShardWitness::IsValid(size_t expected_input_count,
                                                size_t expected_output_count,
                                                size_t expected_leaf_count) const
{
    return version == WIRE_VERSION &&
           spends.size() == expected_input_count &&
           expected_output_count > 0 &&
           expected_output_count <= MAX_RECEIPT_BACKED_INGRESS_OUTPUTS_PER_PROOF_SHARD &&
           ingress_note_commitments.size() == expected_leaf_count &&
           reserve_output_count + ingress_note_commitments.size() == expected_output_count &&
           std::all_of(spends.begin(), spends.end(), [](const V2IngressSpendWitness& spend) {
               return spend.IsValid();
           }) &&
           std::all_of(ingress_note_commitments.begin(),
                       ingress_note_commitments.end(),
                       [](const uint256& note_commitment) { return !note_commitment.IsNull(); });
}

bool V2IngressSmileProofShardWitness::IsValid(size_t expected_input_count,
                                              size_t expected_output_count,
                                              size_t expected_leaf_count) const
{
    return version == WIRE_VERSION &&
           spends.size() == expected_input_count &&
           expected_output_count > 0 &&
           expected_output_count <= MAX_SMILE_INGRESS_OUTPUTS_PER_PROOF_SHARD &&
           leaf_count == expected_leaf_count &&
           reserve_output_count + leaf_count == expected_output_count &&
           std::all_of(spends.begin(), spends.end(), [](const V2IngressSpendWitness& spend) {
               return spend.IsValid();
           }) &&
           !smile_proof_bytes.empty() &&
           smile_proof_bytes.size() <= smile2::MAX_SMILE2_PROOF_BYTES;
}

bool V2IngressProofShardWitness::UsesMatRiCTProof() const
{
    return native_proof.has_value() &&
           !smile_witness.has_value() &&
           !receipt_witness.has_value();
}

bool V2IngressProofShardWitness::UsesSmileProof() const
{
    return !native_proof.has_value() &&
           smile_witness.has_value() &&
           !receipt_witness.has_value();
}

bool V2IngressProofShardWitness::UsesReceiptBackedProof() const
{
    return !native_proof.has_value() &&
           !smile_witness.has_value() &&
           receipt_witness.has_value();
}

size_t V2IngressProofShardWitness::OutputCount(size_t expected_leaf_count) const
{
    if (native_proof.has_value()) {
        return native_proof->output_commitments.size();
    }
    if (smile_witness.has_value()) {
        return static_cast<size_t>(smile_witness->reserve_output_count) + smile_witness->leaf_count;
    }
    if (receipt_witness.has_value()) {
        return static_cast<size_t>(receipt_witness->reserve_output_count) + expected_leaf_count;
    }
    return 0;
}

bool V2IngressProofShardWitness::IsValid(const proof::NativeBatchBackend& backend,
                                         size_t expected_input_count,
                                         size_t expected_output_count,
                                         size_t expected_leaf_count) const
{
    if (NativeBatchBackendMatchesMatRiCTPlus(backend)) {
        if (!UsesMatRiCTProof()) return false;

        V2IngressMatRiCTProofShardWitness payload;
        payload.spends = spends;
        payload.native_proof = *native_proof;
        return payload.IsValid(expected_input_count, expected_output_count);
    }
    if (NativeBatchBackendMatchesSmile(backend)) {
        if (!UsesSmileProof()) return false;

        V2IngressSmileProofShardWitness payload = *smile_witness;
        payload.spends = spends;
        return payload.IsValid(expected_input_count, expected_output_count, expected_leaf_count);
    }
    if (NativeBatchBackendMatchesReceiptBacked(backend)) {
        if (!UsesReceiptBackedProof()) return false;

        V2IngressReceiptProofShardWitness payload = *receipt_witness;
        payload.spends = spends;
        return payload.IsValid(expected_input_count, expected_output_count, expected_leaf_count);
    }
    return false;
}

bool V2IngressWitness::IsValid(const proof::NativeBatchBackend& backend,
                               size_t expected_input_count,
                               size_t expected_reserve_output_count,
                               size_t expected_leaf_count) const
{
    if (!header.IsValid(expected_leaf_count) || shards.empty() || shards.size() > MAX_PROOF_SHARDS) {
        return false;
    }

    if (NativeBatchBackendMatchesMatRiCTPlus(backend)) {
        size_t input_count{0};
        size_t output_count{0};
        for (const auto& shard : shards) {
            const size_t shard_input_count = shard.spends.size();
            const size_t shard_output_count = shard.OutputCount(/*expected_leaf_count=*/0);
            if (!shard.IsValid(backend, shard_input_count, shard_output_count, /*expected_leaf_count=*/0)) {
                return false;
            }
            input_count += shard_input_count;
            output_count += shard_output_count;
            if (input_count > expected_input_count ||
                output_count > expected_reserve_output_count + expected_leaf_count) {
                return false;
            }
        }

        return input_count == expected_input_count &&
               output_count == expected_reserve_output_count + expected_leaf_count;
    }

    if (NativeBatchBackendMatchesSmile(backend)) {
        size_t input_count{0};
        size_t reserve_output_count{0};
        size_t leaf_count{0};

        for (const auto& shard : shards) {
            const size_t shard_input_count = shard.spends.size();
            const size_t shard_leaf_count = shard.UsesSmileProof()
                ? shard.smile_witness->leaf_count
                : 0;
            const size_t shard_output_count = shard.OutputCount(shard_leaf_count);
            const size_t shard_reserve_output_count = shard_output_count - shard_leaf_count;
            if (!shard.IsValid(backend, shard_input_count, shard_output_count, shard_leaf_count)) {
                return false;
            }
            input_count += shard_input_count;
            reserve_output_count += shard_reserve_output_count;
            leaf_count += shard_leaf_count;
            if (input_count > expected_input_count ||
                reserve_output_count > expected_reserve_output_count ||
                leaf_count > expected_leaf_count) {
                return false;
            }
        }

        return input_count == expected_input_count &&
               reserve_output_count == expected_reserve_output_count &&
               leaf_count == expected_leaf_count;
    }

    size_t input_count{0};
    size_t reserve_output_count{0};
    size_t leaf_count{0};

    for (const auto& shard : shards) {
        const size_t shard_input_count = shard.spends.size();
        const size_t shard_leaf_count = shard.UsesReceiptBackedProof()
            ? shard.receipt_witness->ingress_note_commitments.size()
            : 0;
        const size_t shard_output_count = shard.OutputCount(shard_leaf_count);
        const size_t shard_reserve_output_count = shard_output_count - shard_leaf_count;
        if (!shard.IsValid(backend, shard_input_count, shard_output_count, shard_leaf_count)) {
            return false;
        }
        input_count += shard_input_count;
        reserve_output_count += shard_reserve_output_count;
        leaf_count += shard_leaf_count;
        if (input_count > expected_input_count ||
            reserve_output_count > expected_reserve_output_count ||
            leaf_count > expected_leaf_count) {
            return false;
        }
    }

    return input_count == expected_input_count &&
           reserve_output_count == expected_reserve_output_count &&
           leaf_count == expected_leaf_count;
}

bool V2IngressContext::IsValid(size_t expected_input_count,
                               size_t expected_reserve_output_count,
                               size_t expected_leaf_count) const
{
    const auto expected_statement =
        proof::DescribeNativeBatchSettlementStatement(witness.header.statement, backend);
    const bool proof_kind_matches =
        expected_statement.envelope.proof_kind == material.statement.envelope.proof_kind ||
        (expected_statement.envelope.proof_kind == ProofKind::BATCH_SMILE &&
         (material.statement.envelope.proof_kind == ProofKind::GENERIC_SMILE ||
          material.statement.envelope.proof_kind == ProofKind::GENERIC_OPAQUE));
    const bool component_kinds_match =
        (material.statement.envelope.membership_proof_kind == expected_statement.envelope.membership_proof_kind &&
         material.statement.envelope.amount_proof_kind == expected_statement.envelope.amount_proof_kind &&
         material.statement.envelope.balance_proof_kind == expected_statement.envelope.balance_proof_kind) ||
        (material.statement.envelope.membership_proof_kind == ProofComponentKind::GENERIC_OPAQUE &&
         material.statement.envelope.amount_proof_kind == ProofComponentKind::GENERIC_OPAQUE &&
         material.statement.envelope.balance_proof_kind == ProofComponentKind::GENERIC_OPAQUE);
    const bool binding_kind_matches =
        material.statement.envelope.settlement_binding_kind == expected_statement.envelope.settlement_binding_kind ||
        (shielded::v2::IsGenericShieldedSettlementBindingKind(
             material.statement.envelope.settlement_binding_kind) &&
         (expected_statement.envelope.settlement_binding_kind == SettlementBindingKind::NATIVE_BATCH ||
          expected_statement.envelope.settlement_binding_kind == SettlementBindingKind::NETTING_MANIFEST));
    return backend.IsValid() &&
           expected_statement.IsValid() &&
           material.statement.domain == expected_statement.domain &&
           proof_kind_matches &&
           component_kinds_match &&
           binding_kind_matches &&
           material.statement.envelope.statement_digest == expected_statement.envelope.statement_digest &&
           material.statement.envelope.extension_digest == expected_statement.envelope.extension_digest &&
           material.payload_location == proof::PayloadLocation::INLINE_WITNESS &&
           witness.IsValid(backend, expected_input_count, expected_reserve_output_count, expected_leaf_count) &&
           material.IsValid(expected_leaf_count);
}

bool CanBuildCanonicalV2IngressShardPlan(Span<const CAmount> spend_values,
                                         Span<const CAmount> reserve_values,
                                         Span<const V2IngressLeafInput> ingress_leaves)
{
    return BuildCanonicalV2IngressShardSchedule(spend_values, reserve_values, ingress_leaves).has_value();
}

bool CanBuildCanonicalV2IngressShardPlan(Span<const CAmount> spend_values,
                                         Span<const CAmount> reserve_values,
                                         Span<const V2IngressLeafInput> ingress_leaves,
                                         const proof::NativeBatchBackend& backend)
{
    return BuildCanonicalV2IngressShardSchedule(
               spend_values,
               reserve_values,
               ingress_leaves,
               backend)
        .has_value();
}

bool V2IngressStatementTemplate::IsValid() const
{
    if (!ids.IsValid() || domain_id.IsNull() || source_epoch == 0 || data_root.IsNull()) {
        return false;
    }
    return (!verifier_set.IsValid() || verifier_set.version == 1) &&
           (!proof_policy.IsValid() || proof_policy.version == 1);
}

bool V2IngressBuildInput::IsValid() const
{
    if (!statement.IsValid() ||
        statement.direction != BridgeDirection::BRIDGE_IN ||
        spend_inputs.empty() ||
        reserve_outputs.empty() ||
        ingress_leaves.empty() ||
        spend_inputs.size() > MAX_BATCH_NULLIFIERS ||
        ingress_leaves.size() > MAX_BATCH_LEAVES ||
        reserve_outputs.size() > MAX_BATCH_RESERVE_OUTPUTS) {
        return false;
    }

    if (!std::all_of(spend_inputs.begin(), spend_inputs.end(), [](const V2SendSpendInput& spend) {
            return spend.IsValid();
        })) {
        return false;
    }
    if (!std::all_of(ingress_leaves.begin(), ingress_leaves.end(), [](const V2IngressLeafInput& leaf) {
            return leaf.IsValid();
        })) {
        return false;
    }
    if (settlement_witness.has_value() && !settlement_witness->IsValid()) {
        return false;
    }
    if (settlement_witness.has_value() != StatementRequiresIngressSettlementWitness(statement)) {
        return false;
    }
    if (backend_override.has_value() && !backend_override->IsValid()) {
        return false;
    }

    return std::all_of(reserve_outputs.begin(), reserve_outputs.end(), [](const V2SendOutputInput& output) {
        return output.IsValid() &&
               output.note_class == NoteClass::RESERVE &&
               output.encrypted_note.scan_domain == ScanDomain::OPAQUE;
    });
}

bool V2IngressBuildResult::IsValid() const
{
    if (!tx.shielded_bundle.HasV2Bundle()) return false;
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr ||
        !BundleHasSemanticFamily(*bundle, TransactionFamily::V2_INGRESS_BATCH) ||
        !std::holds_alternative<IngressBatchPayload>(bundle->payload)) {
        return false;
    }

    const auto& payload = std::get<IngressBatchPayload>(bundle->payload);
    auto backend = proof::ResolveNativeBatchBackend(witness.header.statement, bundle->header.proof_envelope);
    return backend.has_value() &&
           witness.IsValid(*backend,
                           payload.consumed_spends.size(),
                           payload.reserve_outputs.size(),
                           payload.ingress_leaves.size());
}

uint256 ComputeV2IngressDestinationCommitment(const BridgeBatchLeaf& leaf,
                                              const uint256& l2_id,
                                              const uint256& settlement_domain)
{
    if (!leaf.IsValid() || l2_id.IsNull() || settlement_domain.IsNull()) return uint256{};

    HashWriter hw;
    hw << std::string{TAG_INGRESS_DESTINATION_COMMITMENT}
       << leaf
       << l2_id
       << settlement_domain;
    return hw.GetSHA256();
}

uint256 ComputeV2IngressFeeCommitment(const BridgeBatchLeaf& leaf,
                                      const uint256& l2_id,
                                      CAmount fee,
                                      const uint256& settlement_domain)
{
    if (!leaf.IsValid() || l2_id.IsNull() || settlement_domain.IsNull() || fee < 0 || !MoneyRange(fee)) {
        return uint256{};
    }

    HashWriter hw;
    hw << std::string{TAG_INGRESS_FEE_COMMITMENT}
       << leaf
       << l2_id
       << fee
       << settlement_domain;
    return hw.GetSHA256();
}

uint256 ComputeV2IngressL2CreditRoot(Span<const BatchLeaf> leaves)
{
    std::vector<uint256> commitments;
    commitments.reserve(leaves.size());
    for (const BatchLeaf& leaf : leaves) {
        commitments.push_back(leaf.amount_commitment);
    }
    return ComputeCommitmentRoot(Span<const uint256>{commitments.data(), commitments.size()},
                                 TAG_INGRESS_L2_CREDIT_LEAF,
                                 TAG_INGRESS_L2_CREDIT_NODE);
}

uint256 ComputeV2IngressAggregateFeeCommitment(Span<const BatchLeaf> leaves)
{
    std::vector<uint256> commitments;
    commitments.reserve(leaves.size());
    for (const BatchLeaf& leaf : leaves) {
        commitments.push_back(leaf.fee_commitment);
    }
    return ComputeCommitmentRoot(Span<const uint256>{commitments.data(), commitments.size()},
                                 TAG_INGRESS_FEE_ROOT_LEAF,
                                 TAG_INGRESS_FEE_ROOT_NODE);
}

uint256 ComputeV2IngressAggregateReserveCommitment(Span<const OutputDescription> reserve_outputs)
{
    if (reserve_outputs.empty() || !AllValid(reserve_outputs)) return uint256{};

    const std::vector<OutputDescription> outputs{reserve_outputs.begin(), reserve_outputs.end()};
    HashWriter hw;
    hw << std::string{TAG_INGRESS_RESERVE_AGGREGATE}
       << outputs;
    return hw.GetSHA256();
}

std::optional<BridgeBatchStatement> BuildV2IngressStatement(
    const V2IngressStatementTemplate& statement_template,
    Span<const V2IngressLeafInput> ingress_leaves,
    std::string& reject_reason)
{
    reject_reason.clear();

    if (!statement_template.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-statement-template";
        return std::nullopt;
    }
    if (ingress_leaves.empty() || ingress_leaves.size() > MAX_BATCH_LEAVES ||
        !std::all_of(ingress_leaves.begin(), ingress_leaves.end(), [](const V2IngressLeafInput& leaf) {
            return leaf.IsValid();
        })) {
        reject_reason = "bad-shielded-v2-ingress-statement-leaves";
        return std::nullopt;
    }

    const auto total_amount = SumBridgeLeafAmounts(ingress_leaves);
    if (!total_amount.has_value()) {
        reject_reason = "bad-shielded-v2-ingress-statement-amount";
        return std::nullopt;
    }

    const auto bridge_leaves = ExtractBridgeLeaves(ingress_leaves);
    BridgeBatchStatement statement;
    statement.direction = BridgeDirection::BRIDGE_IN;
    statement.ids = statement_template.ids;
    statement.entry_count = static_cast<uint32_t>(ingress_leaves.size());
    statement.total_amount = *total_amount;
    statement.batch_root = ComputeBridgeBatchRoot(
        Span<const BridgeBatchLeaf>{bridge_leaves.data(), bridge_leaves.size()});
    statement.domain_id = statement_template.domain_id;
    statement.source_epoch = statement_template.source_epoch;
    statement.data_root = statement_template.data_root;
    statement.verifier_set = statement_template.verifier_set;
    statement.proof_policy = statement_template.proof_policy;
    const auto aggregate_commitment = BuildDefaultBridgeBatchAggregateCommitment(statement.batch_root,
                                                                                 statement.data_root,
                                                                                 statement.proof_policy);
    if (!aggregate_commitment.has_value()) {
        reject_reason = "bad-shielded-v2-ingress-statement";
        return std::nullopt;
    }
    statement.aggregate_commitment = *aggregate_commitment;
    statement.version = 5;
    if (!statement.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-statement";
        return std::nullopt;
    }
    return statement;
}

std::optional<V2IngressWitness> ParseV2IngressWitness(const TransactionBundle& bundle,
                                                      std::string& reject_reason)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_INGRESS_BATCH) ||
        !std::holds_alternative<IngressBatchPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return std::nullopt;
    }
    if (bundle.proof_payload.empty() || bundle.proof_shards.empty()) {
        reject_reason = "bad-shielded-v2-ingress-witness-missing";
        return std::nullopt;
    }

    const uint64_t header_size = bundle.proof_shards.front().proof_payload_offset;
    if (header_size == 0 || header_size > bundle.proof_payload.size()) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }

    const std::vector<uint8_t> header_bytes{bundle.proof_payload.begin(),
                                            bundle.proof_payload.begin() + static_cast<std::ptrdiff_t>(header_size)};
    DataStream header_stream{header_bytes};
    V2IngressWitnessHeader header;
    try {
        header_stream >> header;
    } catch (const std::exception&) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }
    if (!header_stream.empty()) {
        reject_reason = "bad-shielded-v2-ingress-witness-encoding";
        return std::nullopt;
    }

    const auto& payload = std::get<IngressBatchPayload>(bundle.payload);
    V2IngressWitness witness;
    witness.header = std::move(header);
    witness.shards.reserve(bundle.proof_shards.size());

    auto backend = proof::ResolveNativeBatchBackend(witness.header.statement, bundle.header.proof_envelope);
    if (!backend.has_value()) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }

    for (const auto& descriptor : bundle.proof_shards) {
        const uint64_t payload_end =
            static_cast<uint64_t>(descriptor.proof_payload_offset) + descriptor.proof_payload_size;
        if (payload_end > bundle.proof_payload.size()) {
            reject_reason = "bad-shielded-v2-ingress-witness-encoding";
            return std::nullopt;
        }

        const std::vector<uint8_t> shard_bytes{
            bundle.proof_payload.begin() + static_cast<std::ptrdiff_t>(descriptor.proof_payload_offset),
            bundle.proof_payload.begin() + static_cast<std::ptrdiff_t>(payload_end)};
        std::optional<V2IngressProofShardWitness> shard;
        if (NativeBatchBackendMatchesSmile(*backend)) {
            shard = ParseSmileShardWitnessBytes(
                Span<const uint8_t>{shard_bytes.data(), shard_bytes.size()},
                reject_reason);
        } else if (NativeBatchBackendMatchesMatRiCTPlus(*backend)) {
            shard = ParseMatRiCTShardWitnessBytes(
                Span<const uint8_t>{shard_bytes.data(), shard_bytes.size()},
                reject_reason);
        } else if (NativeBatchBackendMatchesReceiptBacked(*backend)) {
            shard = ParseReceiptShardWitnessBytes(
                Span<const uint8_t>{shard_bytes.data(), shard_bytes.size()},
                reject_reason);
        } else {
            reject_reason = "bad-shielded-v2-ingress-backend";
            return std::nullopt;
        }
        if (!shard.has_value()) {
            return std::nullopt;
        }
        witness.shards.push_back(std::move(*shard));
    }

    if (!witness.IsValid(*backend,
                         payload.consumed_spends.size(),
                         payload.reserve_outputs.size(),
                         payload.ingress_leaves.size())) {
        reject_reason = "bad-shielded-v2-ingress-witness";
        return std::nullopt;
    }
    return witness;
}

std::optional<V2IngressContext> ParseV2IngressProof(const TransactionBundle& bundle,
                                                    std::string& reject_reason)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_INGRESS_BATCH) ||
        !std::holds_alternative<IngressBatchPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return std::nullopt;
    }
    if (bundle.proof_shards.empty()) {
        reject_reason = "bad-shielded-v2-ingress-proof-shards";
        return std::nullopt;
    }

    auto witness = ParseV2IngressWitness(bundle, reject_reason);
    if (!witness.has_value()) return std::nullopt;

    auto backend = proof::ResolveNativeBatchBackend(witness->header.statement,
                                                    bundle.header.proof_envelope);
    if (!backend.has_value()) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }

    auto statement = proof::DescribeNativeBatchSettlementStatement(witness->header.statement, *backend);
    statement.envelope.proof_kind = bundle.header.proof_envelope.proof_kind;
    statement.envelope.membership_proof_kind = bundle.header.proof_envelope.membership_proof_kind;
    statement.envelope.amount_proof_kind = bundle.header.proof_envelope.amount_proof_kind;
    statement.envelope.balance_proof_kind = bundle.header.proof_envelope.balance_proof_kind;
    statement.envelope.settlement_binding_kind = bundle.header.proof_envelope.settlement_binding_kind;
    if (!statement.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-statement";
        return std::nullopt;
    }

    const auto& payload = std::get<IngressBatchPayload>(bundle.payload);

    V2IngressContext context;
    context.material.statement = statement;
    context.material.payload_location = proof::PayloadLocation::INLINE_WITNESS;
    context.material.proof_shards = bundle.proof_shards;
    context.material.proof_payload = bundle.proof_payload;
    context.backend = *backend;
    context.witness = std::move(*witness);
    if (!context.IsValid(payload.consumed_spends.size(),
                         payload.reserve_outputs.size(),
                         payload.ingress_leaves.size())) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return std::nullopt;
    }
    return context;
}

std::optional<std::vector<std::vector<std::vector<uint256>>>> BuildV2IngressRingMembers(
    const V2IngressContext& context,
    const shielded::ShieldedMerkleTree& tree,
    std::string& reject_reason)
{
    if (NativeBatchBackendMatchesSmile(context.backend)) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }

    const auto& witness = context.witness;
    std::vector<std::vector<std::vector<uint256>>> ring_members;
    ring_members.reserve(witness.shards.size());
    std::unordered_map<uint64_t, uint256> commitment_cache;
    size_t total_spends{0};
    for (const auto& shard : witness.shards) {
        total_spends += shard.spends.size();
    }
    commitment_cache.reserve(total_spends * static_cast<size_t>(shielded::lattice::MAX_RING_SIZE));

    for (const auto& shard : witness.shards) {
        auto& shard_ring_members = ring_members.emplace_back();
        shard_ring_members.reserve(shard.spends.size());
        for (const auto& spend : shard.spends) {
            if (!spend.IsValid()) {
                reject_reason = "bad-shielded-ring-positions";
                return std::nullopt;
            }

            const size_t required_unique_members = static_cast<size_t>(
                std::min<uint64_t>(tree.Size(), static_cast<uint64_t>(spend.ring_positions.size())));
            std::set<uint64_t> unique_positions;

            std::vector<uint256> ring;
            ring.reserve(spend.ring_positions.size());
            for (const uint64_t position : spend.ring_positions) {
                unique_positions.insert(position);
                auto cache_it = commitment_cache.find(position);
                if (cache_it == commitment_cache.end()) {
                    auto commitment = tree.CommitmentAt(position);
                    if (!commitment.has_value()) {
                        reject_reason = "bad-shielded-ring-member-position";
                        return std::nullopt;
                    }
                    cache_it = commitment_cache.emplace(position, *commitment).first;
                }
                ring.push_back(cache_it->second);
            }

            if (unique_positions.size() < required_unique_members) {
                reject_reason = "bad-shielded-ring-member-insufficient-diversity";
                return std::nullopt;
            }
            if (!spend.note_commitment.IsNull()) {
                reject_reason = "bad-shielded-v2-ingress-ring-member";
                return std::nullopt;
            }

            shard_ring_members.push_back(std::move(ring));
        }
    }

    return ring_members;
}

std::optional<std::vector<std::vector<std::vector<smile2::wallet::SmileRingMember>>>>
BuildV2IngressSmileRingMembers(
    const V2IngressContext& context,
    const shielded::ShieldedMerkleTree& tree,
    const std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
    const std::map<uint256, uint256>& account_leaf_commitments,
    std::string& reject_reason)
{
    if (!NativeBatchBackendMatchesSmile(context.backend)) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }

    const auto& witness = context.witness;
    std::vector<std::vector<std::vector<smile2::wallet::SmileRingMember>>> ring_members;
    ring_members.reserve(witness.shards.size());
    std::unordered_map<uint64_t, uint256> commitment_cache;
    size_t total_spends{0};
    for (const auto& shard : witness.shards) {
        total_spends += shard.spends.size();
    }
    commitment_cache.reserve(total_spends * static_cast<size_t>(shielded::lattice::MAX_RING_SIZE));

    for (const auto& shard : witness.shards) {
        auto& shard_ring_members = ring_members.emplace_back();
        shard_ring_members.reserve(shard.spends.size());
        for (const auto& spend : shard.spends) {
            if (!spend.IsValid()) {
                reject_reason = "bad-shielded-ring-positions";
                return std::nullopt;
            }

            std::vector<smile2::wallet::SmileRingMember> ring;
            ring.reserve(spend.ring_positions.size());
            for (const uint64_t position : spend.ring_positions) {
                auto cache_it = commitment_cache.find(position);
                if (cache_it == commitment_cache.end()) {
                    auto commitment = tree.CommitmentAt(position);
                    if (!commitment.has_value()) {
                        reject_reason = "bad-shielded-ring-member-position";
                        return std::nullopt;
                    }
                    cache_it = commitment_cache.emplace(position, *commitment).first;
                }

                const auto account_it = public_accounts.find(cache_it->second);
                const auto leaf_it = account_leaf_commitments.find(cache_it->second);
                if (account_it == public_accounts.end() || leaf_it == account_leaf_commitments.end()) {
                    reject_reason = "bad-smile2-ring-member-account";
                    return std::nullopt;
                }

                auto member = smile2::wallet::BuildRingMemberFromCompactPublicAccount(
                    smile2::wallet::SMILE_GLOBAL_SEED,
                    cache_it->second,
                    account_it->second,
                    leaf_it->second);
                if (!member.has_value()) {
                    reject_reason = "bad-smile2-ring-member-account";
                    return std::nullopt;
                }
                ring.push_back(std::move(*member));
            }

            shard_ring_members.push_back(std::move(ring));
        }

        if (!shard_ring_members.empty()) {
            const auto& reference_positions = shard.spends.front().ring_positions;
            const auto& reference_ring = shard_ring_members.front();
            for (size_t spend_index = 1; spend_index < shard_ring_members.size(); ++spend_index) {
                if (shard.spends[spend_index].ring_positions != reference_positions ||
                    shard_ring_members[spend_index].size() != reference_ring.size()) {
                    reject_reason = "bad-smile2-shared-ring";
                    return std::nullopt;
                }
                for (size_t i = 0; i < reference_ring.size(); ++i) {
                    if (!SmileRingMembersEqual(shard_ring_members[spend_index][i], reference_ring[i])) {
                        reject_reason = "bad-smile2-shared-ring";
                        return std::nullopt;
                    }
                }
            }
        }
    }

    return ring_members;
}

bool VerifyV2IngressProof(const TransactionBundle& bundle,
                          const V2IngressContext& context,
                          const std::vector<std::vector<std::vector<uint256>>>& ring_members,
                          std::string& reject_reason)
{
    if (NativeBatchBackendMatchesSmile(context.backend)) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return false;
    }

    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_INGRESS_BATCH) ||
        !std::holds_alternative<IngressBatchPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return false;
    }

    const auto& payload = std::get<IngressBatchPayload>(bundle.payload);
    if (!context.IsValid(payload.consumed_spends.size(),
                         payload.reserve_outputs.size(),
                         payload.ingress_leaves.size())) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return false;
    }
    if (ring_members.size() != context.witness.shards.size()) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return false;
    }

    const auto& header = context.witness.header;
    const uint256 statement_hash = ComputeBridgeBatchStatementHash(header.statement);
    if (statement_hash.IsNull() || payload.settlement_binding_digest != statement_hash) {
        reject_reason = "bad-shielded-v2-ingress-binding";
        return false;
    }
    if (header.statement.direction != BridgeDirection::BRIDGE_IN) {
        reject_reason = "bad-shielded-v2-ingress-direction";
        return false;
    }
    if (header.settlement_witness.has_value() !=
        StatementRequiresIngressSettlementWitness(header.statement)) {
        reject_reason = "bad-shielded-v2-ingress-settlement-witness";
        return false;
    }
    if (header.settlement_witness.has_value() &&
        !VerifyIngressSettlementWitness(header.statement, *header.settlement_witness, reject_reason)) {
        return false;
    }
    if (header.statement.entry_count != header.ingress_leaves.size() ||
        header.ingress_leaves.size() != payload.ingress_leaves.size()) {
        reject_reason = "bad-shielded-v2-ingress-count";
        return false;
    }

    const auto bridge_amount = SumBridgeLeafAmounts(
        Span<const V2IngressLeafInput>{header.ingress_leaves.data(), header.ingress_leaves.size()});
    const auto total_fee = SumLeafFees(
        Span<const V2IngressLeafInput>{header.ingress_leaves.data(), header.ingress_leaves.size()});
    if (!bridge_amount.has_value() || !total_fee.has_value() ||
        header.statement.total_amount != *bridge_amount) {
        reject_reason = "bad-shielded-v2-ingress-amount";
        return false;
    }
    if (payload.fee != *total_fee) {
        reject_reason = "bad-shielded-v2-ingress-fee-total";
        return false;
    }

    const auto bridge_leaves = ExtractBridgeLeaves(
        Span<const V2IngressLeafInput>{header.ingress_leaves.data(), header.ingress_leaves.size()});
    if (ComputeBridgeBatchRoot(Span<const BridgeBatchLeaf>{bridge_leaves.data(), bridge_leaves.size()}) !=
        header.statement.batch_root) {
        reject_reason = "bad-shielded-v2-ingress-root";
        return false;
    }

    if (payload.l2_credit_root != ComputeV2IngressL2CreditRoot(
                                      Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()})) {
        reject_reason = "bad-shielded-v2-ingress-credit-root";
        return false;
    }
    if (payload.aggregate_fee_commitment != ComputeV2IngressAggregateFeeCommitment(
                                                Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()})) {
        reject_reason = "bad-shielded-v2-ingress-fee-root";
        return false;
    }
    if (payload.aggregate_reserve_commitment != ComputeV2IngressAggregateReserveCommitment(
                                                    Span<const OutputDescription>{payload.reserve_outputs.data(),
                                                                                  payload.reserve_outputs.size()})) {
        reject_reason = "bad-shielded-v2-ingress-reserve-root";
        return false;
    }

    for (size_t leaf_index = 0; leaf_index < payload.ingress_leaves.size(); ++leaf_index) {
        const auto& payload_leaf = payload.ingress_leaves[leaf_index];
        const auto& witness_leaf = header.ingress_leaves[leaf_index];

        if (payload_leaf.position != leaf_index ||
            payload_leaf.l2_id != witness_leaf.l2_id ||
            payload_leaf.settlement_domain != header.statement.domain_id) {
            reject_reason = "bad-shielded-v2-ingress-leaf";
            return false;
        }
        if (payload_leaf.destination_commitment != ComputeV2IngressDestinationCommitment(
                                                      witness_leaf.bridge_leaf,
                                                      witness_leaf.l2_id,
                                                      header.statement.domain_id)) {
            reject_reason = "bad-shielded-v2-ingress-destination";
            return false;
        }
        if (payload_leaf.fee_commitment != ComputeV2IngressFeeCommitment(
                                              witness_leaf.bridge_leaf,
                                              witness_leaf.l2_id,
                                              witness_leaf.fee,
                                              header.statement.domain_id)) {
            reject_reason = "bad-shielded-v2-ingress-fee";
            return false;
        }
    }

    const std::vector<uint256> consumed_nullifiers = ExtractConsumedNullifiers(payload.consumed_spends);
    size_t next_nullifier_index{0};
    size_t next_reserve_output_index{0};
    std::set<uint32_t> used_proof_receipt_indices;
    for (size_t shard_index = 0; shard_index < bundle.proof_shards.size(); ++shard_index) {
        const auto& shard_descriptor = bundle.proof_shards[shard_index];
        const auto& shard_witness = context.witness.shards[shard_index];
        const auto& shard_rings = ring_members[shard_index];
        if (shard_rings.size() != shard_witness.spends.size() ||
            shard_descriptor.first_leaf_index + shard_descriptor.leaf_count > payload.ingress_leaves.size()) {
            reject_reason = "bad-shielded-v2-ingress-proof-shard";
            return false;
        }

        const size_t shard_input_count = shard_witness.spends.size();
        if (next_nullifier_index + shard_input_count > consumed_nullifiers.size()) {
            reject_reason = "bad-shielded-v2-ingress-nullifier";
            return false;
        }
        const size_t shard_reserve_output_count = [&]() -> size_t {
            if (NativeBatchBackendMatchesMatRiCTPlus(context.backend)) {
                if (!shard_witness.native_proof.has_value() ||
                    shard_witness.native_proof->output_commitments.size() < shard_descriptor.leaf_count) {
                    return std::numeric_limits<size_t>::max();
                }
                return shard_witness.native_proof->output_commitments.size() - shard_descriptor.leaf_count;
            }
            if (NativeBatchBackendMatchesReceiptBacked(context.backend) &&
                shard_witness.receipt_witness.has_value()) {
                return shard_witness.receipt_witness->reserve_output_count;
            }
            return std::numeric_limits<size_t>::max();
        }();
        if (shard_reserve_output_count == std::numeric_limits<size_t>::max()) {
            reject_reason = "bad-shielded-v2-ingress-proof-shard";
            return false;
        }
        if (next_reserve_output_index + shard_reserve_output_count > payload.reserve_outputs.size()) {
            reject_reason = "bad-shielded-v2-ingress-reserve-root";
            return false;
        }

        const Span<const uint256> shard_nullifiers{
            consumed_nullifiers.data() + static_cast<std::ptrdiff_t>(next_nullifier_index),
            shard_input_count};
        const Span<const OutputDescription> shard_reserve_outputs{
            payload.reserve_outputs.data() + static_cast<std::ptrdiff_t>(next_reserve_output_index),
            shard_reserve_output_count};
        const Span<const BatchLeaf> shard_payload_leaves{
            payload.ingress_leaves.data() + static_cast<std::ptrdiff_t>(shard_descriptor.first_leaf_index),
            shard_descriptor.leaf_count};
        const Span<const V2IngressLeafInput> shard_witness_leaves{
            header.ingress_leaves.data() + static_cast<std::ptrdiff_t>(shard_descriptor.first_leaf_index),
            shard_descriptor.leaf_count};

        const auto shard_fee = SumLeafFees(shard_witness_leaves);
        if (!shard_fee.has_value()) {
            reject_reason = "bad-shielded-v2-ingress-fee-total";
            return false;
        }

        if (NativeBatchBackendMatchesMatRiCTPlus(context.backend)) {
            std::string proof_reject;
            auto proof_nullifiers = proof::ExtractBoundNullifiers(*shard_witness.native_proof,
                                                                  shard_input_count,
                                                                  proof_reject);
            if (!proof_nullifiers.has_value()) {
                reject_reason = proof_reject;
                return false;
            }
            if (!std::equal(proof_nullifiers->begin(),
                            proof_nullifiers->end(),
                            shard_nullifiers.begin(),
                            shard_nullifiers.end())) {
                reject_reason = "bad-shielded-v2-ingress-nullifier";
                return false;
            }

            std::vector<uint256> proof_output_note_commitments;
            proof_output_note_commitments.reserve(shard_witness.native_proof->output_note_commitments.size());
            for (size_t output_index = 0; output_index < shard_reserve_outputs.size(); ++output_index) {
                const auto& output = shard_reserve_outputs[output_index];
                if (shielded::ringct::CommitmentHash(shard_witness.native_proof->output_commitments[output_index]) !=
                    output.value_commitment) {
                    reject_reason = "bad-shielded-v2-ingress-reserve-commitment";
                    return false;
                }
                if (shard_witness.native_proof->output_note_commitments[output_index] != output.note_commitment) {
                    reject_reason = "bad-shielded-v2-ingress-reserve-note";
                    return false;
                }
                proof_output_note_commitments.push_back(output.note_commitment);
            }

            const size_t credit_offset = shard_reserve_outputs.size();
            for (size_t leaf_offset = 0; leaf_offset < shard_payload_leaves.size(); ++leaf_offset) {
                const auto& payload_leaf = shard_payload_leaves[leaf_offset];
                if (shielded::ringct::CommitmentHash(
                        shard_witness.native_proof->output_commitments[credit_offset + leaf_offset]) !=
                    payload_leaf.amount_commitment) {
                    reject_reason = "bad-shielded-v2-ingress-credit";
                    return false;
                }
                proof_output_note_commitments.push_back(
                    shard_witness.native_proof->output_note_commitments[credit_offset + leaf_offset]);
            }

            auto expected_shard = BuildIngressMatRiCTProofShardForBackend(context.backend,
                                                                          shard_nullifiers,
                                                                          shard_reserve_outputs,
                                                                          shard_payload_leaves,
                                                                          *shard_witness.native_proof,
                                                                          context.material.statement.envelope.statement_digest,
                                                                          header.statement.domain_id,
                                                                          shard_descriptor.first_leaf_index,
                                                                          shard_descriptor.proof_payload_offset,
                                                                          shard_descriptor.proof_payload_size,
                                                                          reject_reason);
            if (!expected_shard.has_value()) {
                return false;
            }
            if (!expected_shard->IsValid() || !ProofShardsEqual(shard_descriptor, *expected_shard)) {
                reject_reason = "bad-shielded-v2-ingress-proof-shard";
                return false;
            }

            std::vector<Nullifier> shard_nullifier_vec{shard_nullifiers.begin(), shard_nullifiers.end()};
            if (!VerifyIngressNativeProofForBackend(context.backend,
                                                    *shard_witness.native_proof,
                                                    shard_rings,
                                                    shard_nullifier_vec,
                                                    proof_output_note_commitments,
                                                    *shard_fee,
                                                    context.material.statement.envelope.statement_digest,
                                                    reject_reason)) {
                return false;
            }
        } else if (NativeBatchBackendMatchesReceiptBacked(context.backend)) {
            if (!header.settlement_witness.has_value()) {
                reject_reason = "bad-shielded-v2-ingress-settlement-witness";
                return false;
            }
            const auto& receipt_witness = *shard_witness.receipt_witness;
            if (receipt_witness.proof_receipt_index >= header.settlement_witness->proof_receipts.size() ||
                receipt_witness.proof_receipt_index >= header.settlement_witness->proof_receipt_descriptor_proofs.size()) {
                reject_reason = "bad-shielded-v2-ingress-proof-receipt-index";
                return false;
            }
            if (!used_proof_receipt_indices.insert(receipt_witness.proof_receipt_index).second) {
                reject_reason = "bad-shielded-v2-ingress-proof-receipt-index";
                return false;
            }

            const auto& receipt =
                header.settlement_witness->proof_receipts[receipt_witness.proof_receipt_index];
            const auto descriptor = BridgeProofDescriptor{
                receipt.proof_system_id,
                receipt.verifier_key_hash,
            };
            if (!descriptor.IsValid() ||
                !VerifyBridgeProofPolicyProof(header.statement.proof_policy,
                                              descriptor,
                                              header.settlement_witness->proof_receipt_descriptor_proofs[receipt_witness.proof_receipt_index])) {
                reject_reason = "bad-shielded-v2-ingress-proof-descriptor";
                return false;
            }
            const uint256 public_values_hash = ComputeV2IngressReceiptPublicValuesHash(
                shard_nullifiers,
                shard_reserve_outputs,
                shard_payload_leaves,
                Span<const uint256>{receipt_witness.ingress_note_commitments.data(),
                                    receipt_witness.ingress_note_commitments.size()},
                *shard_fee,
                context.material.statement.envelope.statement_digest);
            if (public_values_hash.IsNull() ||
                receipt.statement_hash != statement_hash ||
                receipt.public_values_hash != public_values_hash) {
                reject_reason = "bad-shielded-v2-ingress-proof-receipt";
                return false;
            }

            auto expected_shard = BuildIngressReceiptProofShardForBackend(context.backend,
                                                                          receipt,
                                                                          shard_nullifiers,
                                                                          shard_reserve_outputs,
                                                                          shard_payload_leaves,
                                                                          context.material.statement.envelope.statement_digest,
                                                                          header.statement.domain_id,
                                                                          shard_descriptor.first_leaf_index,
                                                                          shard_descriptor.proof_payload_offset,
                                                                          shard_descriptor.proof_payload_size,
                                                                          reject_reason);
            if (!expected_shard.has_value()) {
                return false;
            }
            if (!expected_shard->IsValid() || !ProofShardsEqual(shard_descriptor, *expected_shard)) {
                reject_reason = "bad-shielded-v2-ingress-proof-shard";
                return false;
            }
        } else {
            reject_reason = "bad-shielded-v2-ingress-backend";
            return false;
        }

        next_nullifier_index += shard_input_count;
        next_reserve_output_index += shard_reserve_output_count;
    }

    if (next_nullifier_index != consumed_nullifiers.size() ||
        next_reserve_output_index != payload.reserve_outputs.size()) {
        reject_reason = "bad-shielded-v2-ingress-proof-shard";
        return false;
    }

    return true;
}

bool VerifyV2IngressProof(
    const TransactionBundle& bundle,
    const V2IngressContext& context,
    const std::vector<std::vector<std::vector<smile2::wallet::SmileRingMember>>>& ring_members,
    std::string& reject_reason,
    bool reject_rice_codec,
    bool bind_anonset_context)
{
    if (!NativeBatchBackendMatchesSmile(context.backend)) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return false;
    }
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_INGRESS_BATCH) ||
        !std::holds_alternative<IngressBatchPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return false;
    }

    const auto& payload = std::get<IngressBatchPayload>(bundle.payload);
    if (!context.IsValid(payload.consumed_spends.size(),
                         payload.reserve_outputs.size(),
                         payload.ingress_leaves.size())) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return false;
    }
    if (ring_members.size() != context.witness.shards.size()) {
        reject_reason = "bad-shielded-v2-ingress-proof";
        return false;
    }

    const auto& header = context.witness.header;
    const uint256 statement_hash = ComputeBridgeBatchStatementHash(header.statement);
    if (statement_hash.IsNull() || payload.settlement_binding_digest != statement_hash) {
        reject_reason = "bad-shielded-v2-ingress-binding";
        return false;
    }
    if (header.statement.direction != BridgeDirection::BRIDGE_IN) {
        reject_reason = "bad-shielded-v2-ingress-direction";
        return false;
    }
    if (header.settlement_witness.has_value() !=
        StatementRequiresIngressSettlementWitness(header.statement)) {
        reject_reason = "bad-shielded-v2-ingress-settlement-witness";
        return false;
    }
    if (header.settlement_witness.has_value() &&
        !VerifyIngressSettlementWitness(header.statement, *header.settlement_witness, reject_reason)) {
        return false;
    }
    if (header.statement.entry_count != header.ingress_leaves.size() ||
        header.ingress_leaves.size() != payload.ingress_leaves.size()) {
        reject_reason = "bad-shielded-v2-ingress-count";
        return false;
    }

    const auto bridge_amount = SumBridgeLeafAmounts(
        Span<const V2IngressLeafInput>{header.ingress_leaves.data(), header.ingress_leaves.size()});
    const auto total_fee = SumLeafFees(
        Span<const V2IngressLeafInput>{header.ingress_leaves.data(), header.ingress_leaves.size()});
    if (!bridge_amount.has_value() || !total_fee.has_value() ||
        header.statement.total_amount != *bridge_amount) {
        reject_reason = "bad-shielded-v2-ingress-amount";
        return false;
    }
    if (payload.fee != *total_fee) {
        reject_reason = "bad-shielded-v2-ingress-fee-total";
        return false;
    }

    const auto bridge_leaves = ExtractBridgeLeaves(
        Span<const V2IngressLeafInput>{header.ingress_leaves.data(), header.ingress_leaves.size()});
    if (ComputeBridgeBatchRoot(Span<const BridgeBatchLeaf>{bridge_leaves.data(), bridge_leaves.size()}) !=
        header.statement.batch_root) {
        reject_reason = "bad-shielded-v2-ingress-root";
        return false;
    }

    if (payload.l2_credit_root != ComputeV2IngressL2CreditRoot(
                                      Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()})) {
        reject_reason = "bad-shielded-v2-ingress-credit-root";
        return false;
    }
    if (payload.aggregate_fee_commitment != ComputeV2IngressAggregateFeeCommitment(
                                                Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()})) {
        reject_reason = "bad-shielded-v2-ingress-fee-root";
        return false;
    }
    if (payload.aggregate_reserve_commitment != ComputeV2IngressAggregateReserveCommitment(
                                                    Span<const OutputDescription>{payload.reserve_outputs.data(),
                                                                                  payload.reserve_outputs.size()})) {
        reject_reason = "bad-shielded-v2-ingress-reserve-root";
        return false;
    }

    for (size_t leaf_index = 0; leaf_index < payload.ingress_leaves.size(); ++leaf_index) {
        const auto& payload_leaf = payload.ingress_leaves[leaf_index];
        const auto& witness_leaf = header.ingress_leaves[leaf_index];

        if (payload_leaf.position != leaf_index ||
            payload_leaf.l2_id != witness_leaf.l2_id ||
            payload_leaf.settlement_domain != header.statement.domain_id) {
            reject_reason = "bad-shielded-v2-ingress-leaf";
            return false;
        }
        if (payload_leaf.destination_commitment != ComputeV2IngressDestinationCommitment(
                                                      witness_leaf.bridge_leaf,
                                                      witness_leaf.l2_id,
                                                      header.statement.domain_id)) {
            reject_reason = "bad-shielded-v2-ingress-destination";
            return false;
        }
        if (payload_leaf.fee_commitment != ComputeV2IngressFeeCommitment(
                                              witness_leaf.bridge_leaf,
                                              witness_leaf.l2_id,
                                              witness_leaf.fee,
                                              header.statement.domain_id)) {
            reject_reason = "bad-shielded-v2-ingress-fee";
            return false;
        }
    }

    const std::vector<uint256> consumed_nullifiers = ExtractConsumedNullifiers(payload.consumed_spends);
    size_t next_nullifier_index{0};
    size_t next_reserve_output_index{0};
    for (size_t shard_index = 0; shard_index < bundle.proof_shards.size(); ++shard_index) {
        const auto& shard_descriptor = bundle.proof_shards[shard_index];
        const auto& shard_witness = context.witness.shards[shard_index];
        const auto& shard_rings = ring_members[shard_index];
        if (shard_rings.size() != shard_witness.spends.size() ||
            !shard_witness.smile_witness.has_value() ||
            shard_descriptor.first_leaf_index + shard_descriptor.leaf_count > payload.ingress_leaves.size()) {
            reject_reason = "bad-shielded-v2-ingress-proof-shard";
            return false;
        }

        const size_t shard_input_count = shard_witness.spends.size();
        if (next_nullifier_index + shard_input_count > consumed_nullifiers.size()) {
            reject_reason = "bad-shielded-v2-ingress-nullifier";
            return false;
        }
        const size_t shard_reserve_output_count = shard_witness.smile_witness->reserve_output_count;
        const size_t shard_leaf_count = shard_witness.smile_witness->leaf_count;
        if (shard_leaf_count != shard_descriptor.leaf_count ||
            next_reserve_output_index + shard_reserve_output_count > payload.reserve_outputs.size()) {
            reject_reason = "bad-shielded-v2-ingress-proof-shard";
            return false;
        }

        const Span<const uint256> shard_nullifiers{
            consumed_nullifiers.data() + static_cast<std::ptrdiff_t>(next_nullifier_index),
            shard_input_count};
        const Span<const OutputDescription> shard_reserve_outputs{
            payload.reserve_outputs.data() + static_cast<std::ptrdiff_t>(next_reserve_output_index),
            shard_reserve_output_count};
        const Span<const BatchLeaf> shard_payload_leaves{
            payload.ingress_leaves.data() + static_cast<std::ptrdiff_t>(shard_descriptor.first_leaf_index),
            shard_descriptor.leaf_count};
        const Span<const V2IngressLeafInput> shard_witness_leaves{
            header.ingress_leaves.data() + static_cast<std::ptrdiff_t>(shard_descriptor.first_leaf_index),
            shard_descriptor.leaf_count};

        const auto shard_fee = SumLeafFees(shard_witness_leaves);
        if (!shard_fee.has_value()) {
            reject_reason = "bad-shielded-v2-ingress-fee-total";
            return false;
        }

        smile2::SmileCTProof proof;
        if (auto parse_err = smile2::ParseSmile2Proof(shard_witness.smile_witness->smile_proof_bytes,
                                                      shard_input_count,
                                                      shard_reserve_output_count + shard_leaf_count,
                                                      proof,
                                                      reject_rice_codec);
            parse_err.has_value()) {
            reject_reason = *parse_err;
            return false;
        }

        std::vector<smile2::SmilePoly> serial_numbers;
        if (auto extract_err = smile2::ExtractSmile2SerialNumbers(proof, serial_numbers);
            extract_err.has_value()) {
            reject_reason = *extract_err;
            return false;
        }
        if (serial_numbers.size() != shard_input_count) {
            reject_reason = "bad-shielded-v2-ingress-nullifier";
            return false;
        }
        for (size_t i = 0; i < serial_numbers.size(); ++i) {
            if (smile2::ComputeSmileSerialHash(serial_numbers[i]) != shard_nullifiers[i]) {
                reject_reason = "bad-shielded-v2-ingress-nullifier";
                return false;
            }
        }

        for (const auto& ring : shard_rings) {
            if (ring.size() != shard_rings.front().size()) {
                reject_reason = "bad-smile2-shared-ring";
                return false;
            }
            for (size_t i = 0; i < ring.size(); ++i) {
                if (!SmileRingMembersEqual(ring[i], shard_rings.front()[i])) {
                    reject_reason = "bad-smile2-shared-ring";
                    return false;
                }
            }
        }

        for (size_t output_index = 0; output_index < shard_reserve_outputs.size(); ++output_index) {
            const auto& output = shard_reserve_outputs[output_index];
            if (!output.smile_account.has_value() ||
                smile2::ComputeCompactPublicAccountHash(*output.smile_account) != output.note_commitment ||
                smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin) !=
                    output.value_commitment) {
                reject_reason = "bad-shielded-v2-ingress-reserve-commitment";
                return false;
            }
        }
        for (size_t leaf_index = 0; leaf_index < shard_witness_leaves.size(); ++leaf_index) {
            const ShieldedNote note = BuildSyntheticCreditNote(
                header.statement,
                shard_witness_leaves[leaf_index],
                static_cast<uint32_t>(shard_descriptor.first_leaf_index + leaf_index));
            if (!note.IsValid() ||
                smile2::ComputeSmileOutputCoinHash(smile2::wallet::BuildPublicCoinFromNote(note)) !=
                    shard_payload_leaves[leaf_index].amount_commitment) {
                reject_reason = "bad-shielded-v2-ingress-credit";
                return false;
            }
        }

        auto expected_output_coins = CollectIngressSmileOutputCoins(shard_reserve_outputs,
                                                                    header.statement,
                                                                    shard_witness_leaves,
                                                                    shard_descriptor.first_leaf_index);
        if (!expected_output_coins.has_value()) {
            reject_reason = "bad-shielded-v2-ingress-smile-account";
            return false;
        }

        auto expected_shard = BuildIngressSmileProofShardForBackend(
            context.backend,
            shard_nullifiers,
            shard_reserve_outputs,
            shard_payload_leaves,
            Span<const uint8_t>{shard_witness.smile_witness->smile_proof_bytes.data(),
                                shard_witness.smile_witness->smile_proof_bytes.size()},
            context.material.statement.envelope.statement_digest,
            header.statement.domain_id,
            shard_descriptor.first_leaf_index,
            shard_descriptor.proof_payload_offset,
            shard_descriptor.proof_payload_size,
            reject_reason);
        if (!expected_shard.has_value()) {
            return false;
        }
        if (!expected_shard->IsValid() || !ProofShardsEqual(shard_descriptor, *expected_shard)) {
            reject_reason = "bad-shielded-v2-ingress-proof-shard";
            return false;
        }

        if (!VerifyIngressSmileProofForBackend(
                context.backend,
                Span<const uint8_t>{shard_witness.smile_witness->smile_proof_bytes.data(),
                                    shard_witness.smile_witness->smile_proof_bytes.size()},
                Span<const smile2::wallet::SmileRingMember>{shard_rings.front().data(),
                                                            shard_rings.front().size()},
                Span<const ConsumedAccountLeafSpend>{
                    payload.consumed_spends.data() + static_cast<std::ptrdiff_t>(next_nullifier_index),
                    shard_input_count},
                shard_nullifiers,
                *expected_output_coins,
                *shard_fee,
                reject_reason,
                reject_rice_codec,
                bind_anonset_context)) {
            return false;
        }

        next_nullifier_index += shard_input_count;
        next_reserve_output_index += shard_reserve_output_count;
    }

    if (next_nullifier_index != consumed_nullifiers.size() ||
        next_reserve_output_index != payload.reserve_outputs.size()) {
        reject_reason = "bad-shielded-v2-ingress-proof-shard";
        return false;
    }

    return true;
}

std::optional<V2IngressBuildResult> BuildV2IngressBatchTransaction(const CMutableTransaction& tx_template,
                                                                   const uint256& spend_anchor,
                                                                   const V2IngressBuildInput& input,
                                                                   Span<const unsigned char> spending_key,
                                                                   std::string& reject_reason,
                                                                   Span<const unsigned char> rng_entropy,
                                                                   const Consensus::Params* consensus,
                                                                   int32_t validation_height)
{
    reject_reason.clear();
    const bool bind_smile_anonset_context =
        consensus != nullptr && consensus->IsShieldedMatRiCTDisabled(validation_height);

    if (tx_template.HasShieldedBundle()) {
        reject_reason = "bad-shielded-v2-ingress-builder-existing-bundle";
        return std::nullopt;
    }
    if (!tx_template.vin.empty() || !tx_template.vout.empty()) {
        reject_reason = "bad-shielded-v2-ingress-transparent";
        return std::nullopt;
    }
    if (spend_anchor.IsNull()) {
        reject_reason = "bad-shielded-v2-ingress-spend-anchor";
        return std::nullopt;
    }
    if (!input.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-builder-input";
        return std::nullopt;
    }
    if (spending_key.size() != 32) {
        reject_reason = "bad-shielded-v2-ingress-spending-key";
        return std::nullopt;
    }

    const auto bridge_leaves = ExtractBridgeLeaves(
        Span<const V2IngressLeafInput>{input.ingress_leaves.data(), input.ingress_leaves.size()});
    const auto total_bridge_amount = SumBridgeLeafAmounts(
        Span<const V2IngressLeafInput>{input.ingress_leaves.data(), input.ingress_leaves.size()});
    const auto total_fee = SumLeafFees(
        Span<const V2IngressLeafInput>{input.ingress_leaves.data(), input.ingress_leaves.size()});
    if (!total_bridge_amount.has_value() || !total_fee.has_value()) {
        reject_reason = "bad-shielded-v2-ingress-amount";
        return std::nullopt;
    }
    if (input.statement.entry_count != input.ingress_leaves.size()) {
        reject_reason = "bad-shielded-v2-ingress-statement-count";
        return std::nullopt;
    }
    if (input.statement.total_amount != *total_bridge_amount) {
        reject_reason = "bad-shielded-v2-ingress-statement-amount";
        return std::nullopt;
    }
    if (ComputeBridgeBatchRoot(Span<const BridgeBatchLeaf>{bridge_leaves.data(), bridge_leaves.size()}) !=
        input.statement.batch_root) {
        reject_reason = "bad-shielded-v2-ingress-statement-root";
        return std::nullopt;
    }

    const auto backend = input.backend_override.value_or(proof::SelectDefaultNativeBatchBackend());
    if (!backend.IsValid() || !NativeBatchBackendMatchesSmile(backend)) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }
    const auto statement =
        consensus != nullptr
            ? proof::DescribeNativeBatchSettlementStatement(input.statement,
                                                            backend,
                                                            *consensus,
                                                            validation_height)
            : proof::DescribeNativeBatchSettlementStatement(input.statement, backend);
    if (!statement.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-statement";
        return std::nullopt;
    }

    const auto spend_values =
        BuildSpendValues(Span<const V2SendSpendInput>{input.spend_inputs.data(), input.spend_inputs.size()});
    const auto reserve_values = BuildReserveValues(
        Span<const V2SendOutputInput>{input.reserve_outputs.data(), input.reserve_outputs.size()});
    const auto leaf_values =
        BuildLeafValues(Span<const V2IngressLeafInput>{input.ingress_leaves.data(), input.ingress_leaves.size()});
    const size_t max_outputs_per_proof_shard = GetMaxIngressOutputsPerProofShard(backend);
    if (max_outputs_per_proof_shard == 0) {
        reject_reason = "bad-shielded-v2-ingress-backend";
        return std::nullopt;
    }
    const auto shard_plan = BuildCanonicalIngressShardPlan(
        Span<const CAmount>{spend_values.data(), spend_values.size()},
        Span<const CAmount>{reserve_values.data(), reserve_values.size()},
        Span<const CAmount>{leaf_values.data(), leaf_values.size()},
        max_outputs_per_proof_shard);
    if (!shard_plan.has_value() || shard_plan->empty()) {
        reject_reason = "bad-shielded-v2-ingress-shard-schedule";
        return std::nullopt;
    }
    if (NativeBatchBackendMatchesReceiptBacked(backend)) {
        if (!input.settlement_witness.has_value() ||
            input.settlement_witness->proof_receipts.size() != shard_plan->size() ||
            input.settlement_witness->proof_receipt_descriptor_proofs.size() != shard_plan->size()) {
            reject_reason = "bad-shielded-v2-ingress-proof-receipt-count";
            return std::nullopt;
        }
    }

    IngressBatchPayload payload;
    payload.spend_anchor = spend_anchor;
    payload.settlement_binding_digest = ComputeBridgeBatchStatementHash(input.statement);
    payload.reserve_output_encoding = ReserveOutputEncoding::EXPLICIT;
    if (payload.settlement_binding_digest.IsNull()) {
        reject_reason = "bad-shielded-v2-ingress-statement";
        return std::nullopt;
    }

    V2IngressWitness witness;
    witness.header.statement = input.statement;
    witness.header.ingress_leaves = input.ingress_leaves;
    witness.header.settlement_witness = input.settlement_witness;
    witness.shards.reserve(shard_plan->size());

    for (const auto& spend_input : input.spend_inputs) {
        const uint256 effective_note_commitment =
            spend_input.note_commitment.IsNull() ? spend_input.note.GetCommitment() : spend_input.note_commitment;
        uint256 nullifier;
        if (!shielded::ringct::DeriveInputNullifierForNote(nullifier,
                                                           spending_key,
                                                           spend_input.note,
                                                           effective_note_commitment)) {
            reject_reason = "bad-shielded-v2-ingress-nullifier";
            return std::nullopt;
        }
        const auto account_leaf_commitments =
            shielded::registry::CollectAccountLeafCommitmentCandidatesFromNote(spend_input.note,
                                                                               effective_note_commitment,
                                                                               *spend_input.account_leaf_hint);
        if (account_leaf_commitments.empty()) {
            reject_reason = "bad-shielded-v2-ingress-account-leaf";
            return std::nullopt;
        }
        if (!spend_input.account_registry_proof.has_value() ||
            std::find(account_leaf_commitments.begin(),
                      account_leaf_commitments.end(),
                      spend_input.account_registry_proof->account_leaf_commitment) ==
                account_leaf_commitments.end()) {
            reject_reason = "bad-shielded-v2-ingress-account-leaf-proof";
            return std::nullopt;
        }
        if (payload.account_registry_anchor.IsNull()) {
            payload.account_registry_anchor = spend_input.account_registry_anchor;
        } else if (payload.account_registry_anchor != spend_input.account_registry_anchor) {
            reject_reason = "bad-shielded-v2-ingress-account-registry-anchor";
            return std::nullopt;
        }

        ConsumedAccountLeafSpend consumed_spend;
        consumed_spend.nullifier = nullifier;
        consumed_spend.account_leaf_commitment = spend_input.account_registry_proof->account_leaf_commitment;
        consumed_spend.account_registry_proof = *spend_input.account_registry_proof;
        payload.consumed_spends.push_back(std::move(consumed_spend));
    }

    const uint256 statement_hash = payload.settlement_binding_digest;

    for (size_t output_index = 0; output_index < input.reserve_outputs.size(); ++output_index) {
        const auto& reserve_output = input.reserve_outputs[output_index];
        OutputDescription output;
        output.note_class = reserve_output.note_class;
        auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            reserve_output.note);
        if (!smile_account.has_value()) {
            reject_reason = "bad-shielded-v2-ingress-smile-account";
            return std::nullopt;
        }
        output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        output.value_commitment = ComputeV2IngressPlaceholderReserveValueCommitment(
            statement_hash,
            static_cast<uint32_t>(output_index),
            output.note_commitment);
        output.smile_account = std::move(*smile_account);
        output.encrypted_note = reserve_output.encrypted_note;
        payload.reserve_outputs.push_back(output);
    }

    for (size_t leaf_index = 0; leaf_index < input.ingress_leaves.size(); ++leaf_index) {
        const auto& ingress_input = input.ingress_leaves[leaf_index];
        payload.ingress_leaves.push_back(
            BuildV2IngressPayloadLeaf(input.statement,
                                      ingress_input,
                                      static_cast<uint32_t>(leaf_index),
                                      consensus,
                                      validation_height));
    }
    payload.fee = *total_fee;

    const std::vector<uint8_t> serialized_header = SerializeWitnessHeader(witness.header);
    if (serialized_header.empty()) {
        reject_reason = "bad-shielded-v2-ingress-witness";
        return std::nullopt;
    }
    std::vector<uint8_t> serialized_payload = serialized_header;

    for (size_t shard_index = 0; shard_index < shard_plan->size(); ++shard_index) {
        const auto& shard = (*shard_plan)[shard_index];
        const Span<const V2SendSpendInput> shard_spend_inputs{
            input.spend_inputs.data() + static_cast<std::ptrdiff_t>(shard.spend_index),
            shard.spend_count};
        const Span<const V2SendOutputInput> shard_reserve_outputs{
            input.reserve_outputs.data() + static_cast<std::ptrdiff_t>(shard.reserve_output_index),
            shard.reserve_output_count};
        const Span<const V2IngressLeafInput> shard_ingress_inputs{
            input.ingress_leaves.data() + static_cast<std::ptrdiff_t>(shard.leaf_index),
            shard.leaf_count};

        std::vector<ShieldedNote> shard_input_notes;
        shard_input_notes.reserve(shard_spend_inputs.size());

        V2IngressProofShardWitness shard_witness;
        shard_witness.spends.reserve(shard_spend_inputs.size());
        for (size_t local_spend_index = 0; local_spend_index < shard_spend_inputs.size(); ++local_spend_index) {
            const auto& spend_input = shard_spend_inputs[local_spend_index];
            V2IngressSpendWitness spend_witness;
            spend_witness.ring_positions = spend_input.ring_positions;
            shard_witness.spends.push_back(std::move(spend_witness));

            shard_input_notes.push_back(spend_input.note);
        }

        std::vector<ShieldedNote> shard_output_notes;
        shard_output_notes.reserve(shard.reserve_output_count + shard.leaf_count);
        for (size_t local_output_index = 0; local_output_index < shard_reserve_outputs.size(); ++local_output_index) {
            shard_output_notes.push_back(shard_reserve_outputs[local_output_index].note);
        }
        for (size_t local_leaf_index = 0; local_leaf_index < shard_ingress_inputs.size(); ++local_leaf_index) {
            shard_output_notes.push_back(BuildSyntheticCreditNote(
                input.statement,
                shard_ingress_inputs[local_leaf_index],
                static_cast<uint32_t>(shard.leaf_index + local_leaf_index)));
        }
        const auto shard_input_value =
            SumNoteValues(Span<const ShieldedNote>{shard_input_notes.data(), shard_input_notes.size()});
        const auto shard_output_value =
            SumNoteValues(Span<const ShieldedNote>{shard_output_notes.data(), shard_output_notes.size()});
        const auto shard_fee = SumLeafFees(shard_ingress_inputs);
        const auto shard_output_plus_fee =
            shard_output_value && shard_fee ? CheckedAdd(*shard_output_value, *shard_fee) : std::nullopt;
        if (!shard_input_value || !shard_output_plus_fee || !MoneyRange(*shard_output_plus_fee) ||
            *shard_input_value != *shard_output_plus_fee) {
            reject_reason = "bad-shielded-v2-ingress-balance";
            return std::nullopt;
        }

        std::vector<uint8_t> serialized_shard;
        std::array<unsigned char, 32> shard_rng_entropy{};
        Span<const unsigned char> shard_rng = rng_entropy;
        if (!rng_entropy.empty()) {
            HashWriter hw;
            hw << std::string{"BTX_ShieldedV2_Ingress_Shard_Rng_V1"}
               << rng_entropy
               << static_cast<uint32_t>(shard.spend_index)
               << static_cast<uint32_t>(shard.leaf_index);
            const uint256 shard_seed = hw.GetSHA256();
            std::copy(shard_seed.begin(), shard_seed.end(), shard_rng_entropy.begin());
            shard_rng = {shard_rng_entropy.data(), shard_rng_entropy.size()};
        }

        auto shared_smile_ring_members = ExtractSharedSmileRingMembers(shard_spend_inputs, reject_reason);
        if (!shared_smile_ring_members.has_value()) {
            return std::nullopt;
        }

        std::vector<smile2::wallet::SmileInputMaterial> shard_smile_inputs;
        shard_smile_inputs.reserve(shard_spend_inputs.size());
        for (size_t local_spend_index = 0; local_spend_index < shard_spend_inputs.size(); ++local_spend_index) {
            const auto& spend_input = shard_spend_inputs[local_spend_index];
            const uint256 effective_note_commitment =
                spend_input.note_commitment.IsNull() ? spend_input.note.GetCommitment() : spend_input.note_commitment;
            shard_smile_inputs.push_back({spend_input.note,
                                          effective_note_commitment,
                                          payload.consumed_spends[shard.spend_index + local_spend_index]
                                              .account_leaf_commitment,
                                          spend_input.real_index});
        }

        std::vector<uint256> serial_hashes;
        auto smile_result = smile2::wallet::CreateSmileProof(
            smile2::wallet::SMILE_GLOBAL_SEED,
            shard_smile_inputs,
            shard_output_notes,
            Span<const smile2::wallet::SmileRingMember>{shared_smile_ring_members->data(),
                                                        shared_smile_ring_members->size()},
            shard_rng,
            serial_hashes,
            *shard_fee,
            smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
            bind_smile_anonset_context);
        if (!smile_result.has_value()) {
            reject_reason = "bad-shielded-v2-ingress-smile-proof";
            return std::nullopt;
        }
        if (serial_hashes.size() != shard_spend_inputs.size()) {
            reject_reason = "bad-shielded-v2-ingress-smile-nullifier-count";
            return std::nullopt;
        }
        if (smile_result->output_coins.size() != shard_output_notes.size()) {
            reject_reason = "bad-shielded-v2-ingress-smile-output-count";
            return std::nullopt;
        }

        for (size_t local_spend_index = 0; local_spend_index < shard_spend_inputs.size(); ++local_spend_index) {
            payload.consumed_spends[shard.spend_index + local_spend_index].nullifier =
                serial_hashes[local_spend_index];
        }
        for (size_t local_output_index = 0; local_output_index < shard.reserve_output_count; ++local_output_index) {
            auto& payload_output = payload.reserve_outputs[shard.reserve_output_index + local_output_index];
            if (!payload_output.smile_account.has_value() ||
                smile2::ComputeSmileOutputCoinHash(payload_output.smile_account->public_coin) !=
                    smile2::ComputeSmileOutputCoinHash(smile_result->output_coins[local_output_index])) {
                reject_reason = "bad-shielded-v2-ingress-smile-account";
                return std::nullopt;
            }
            payload_output.value_commitment =
                smile2::ComputeSmileOutputCoinHash(smile_result->output_coins[local_output_index]);
        }
        for (size_t local_leaf_index = 0; local_leaf_index < shard.leaf_count; ++local_leaf_index) {
            payload.ingress_leaves[shard.leaf_index + local_leaf_index].amount_commitment =
                smile2::ComputeSmileOutputCoinHash(
                    smile_result->output_coins[shard.reserve_output_count + local_leaf_index]);
        }

        V2IngressSmileProofShardWitness smile_payload;
        smile_payload.spends = shard_witness.spends;
        smile_payload.reserve_output_count = static_cast<uint32_t>(shard.reserve_output_count);
        smile_payload.leaf_count = static_cast<uint32_t>(shard.leaf_count);
        smile_payload.smile_proof_bytes = std::move(smile_result->proof_bytes);
        shard_witness.smile_witness = std::move(smile_payload);
        serialized_shard = SerializeSmileShardWitness(shard_witness);
        if (serialized_shard.empty()) {
            reject_reason = "bad-shielded-v2-ingress-witness";
            return std::nullopt;
        }
        serialized_payload.insert(serialized_payload.end(), serialized_shard.begin(), serialized_shard.end());
        witness.shards.push_back(std::move(shard_witness));
    }

    payload.ingress_root = ComputeBatchLeafRoot(
        Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    payload.l2_credit_root = ComputeV2IngressL2CreditRoot(
        Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    payload.aggregate_fee_commitment = ComputeV2IngressAggregateFeeCommitment(
        Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()});
    payload.aggregate_reserve_commitment = ComputeV2IngressAggregateReserveCommitment(
        Span<const OutputDescription>{payload.reserve_outputs.data(), payload.reserve_outputs.size()});
    if (!payload.IsValid()) {
        if (payload.version != WIRE_VERSION) {
            reject_reason = "bad-shielded-v2-ingress-payload-version";
        } else if (payload.spend_anchor.IsNull()) {
            reject_reason = "bad-shielded-v2-ingress-payload-anchor";
        } else if (payload.consumed_spends.empty() ||
                   payload.consumed_spends.size() > MAX_BATCH_NULLIFIERS) {
            reject_reason = "bad-shielded-v2-ingress-payload-nullifiers";
        } else if (payload.ingress_leaves.empty() ||
                   payload.ingress_leaves.size() > MAX_BATCH_LEAVES) {
            reject_reason = "bad-shielded-v2-ingress-payload-leaves";
        } else if (payload.reserve_outputs.empty() ||
                   payload.reserve_outputs.size() > MAX_BATCH_RESERVE_OUTPUTS) {
            reject_reason = "bad-shielded-v2-ingress-payload-reserve-count";
        } else if (!IsValidReserveOutputEncoding(payload.reserve_output_encoding)) {
            reject_reason = "bad-shielded-v2-ingress-payload-reserve-encoding";
        } else if (std::any_of(payload.ingress_leaves.begin(),
                               payload.ingress_leaves.end(),
                               [](const BatchLeaf& leaf) { return !leaf.IsValid(); })) {
            reject_reason = "bad-shielded-v2-ingress-payload-leaf-shape";
        } else if (std::any_of(payload.reserve_outputs.begin(),
                               payload.reserve_outputs.end(),
                               [](const OutputDescription& output) { return !output.IsValid(); })) {
            reject_reason = "bad-shielded-v2-ingress-payload-reserve-shape";
        } else if (payload.ingress_root.IsNull()) {
            reject_reason = "bad-shielded-v2-ingress-payload-ingress-root";
        } else if (payload.l2_credit_root.IsNull()) {
            reject_reason = "bad-shielded-v2-ingress-payload-credit-root";
        } else if (payload.aggregate_reserve_commitment.IsNull()) {
            reject_reason = "bad-shielded-v2-ingress-payload-reserve-aggregate";
        } else if (payload.aggregate_fee_commitment.IsNull()) {
            reject_reason = "bad-shielded-v2-ingress-payload-fee-aggregate";
        } else if (payload.fee < 0 || !MoneyRange(payload.fee)) {
            reject_reason = "bad-shielded-v2-ingress-payload-fee";
        } else if (payload.settlement_binding_digest.IsNull()) {
            reject_reason = "bad-shielded-v2-ingress-payload-settlement-binding";
        } else if (std::any_of(payload.reserve_outputs.begin(),
                               payload.reserve_outputs.end(),
                               [](const OutputDescription& output) {
                                   return output.note_class != NoteClass::RESERVE ||
                                          output.encrypted_note.scan_domain != ScanDomain::OPAQUE;
                               })) {
            reject_reason = "bad-shielded-v2-ingress-payload-reserve-domain";
        } else if (payload.reserve_output_encoding == ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED) {
            bool mismatch{false};
            for (size_t output_index = 0; output_index < payload.reserve_outputs.size(); ++output_index) {
                const OutputDescription& output = payload.reserve_outputs[output_index];
                if (output.value_commitment != ComputeV2IngressPlaceholderReserveValueCommitment(
                                                  payload.settlement_binding_digest,
                                                  static_cast<uint32_t>(output_index),
                                                  output.note_commitment)) {
                    mismatch = true;
                    break;
                }
            }
            reject_reason = mismatch ? "bad-shielded-v2-ingress-payload-reserve-value"
                                     : "bad-shielded-v2-ingress-payload";
        } else if (std::any_of(payload.consumed_spends.begin(),
                               payload.consumed_spends.end(),
                               [](const ConsumedAccountLeafSpend& spend) { return !spend.IsValid(); })) {
            reject_reason = "bad-shielded-v2-ingress-payload-consumed-spend";
        } else {
            std::vector<uint256> sorted_nullifiers = ExtractConsumedNullifiers(payload.consumed_spends);
            std::sort(sorted_nullifiers.begin(), sorted_nullifiers.end());
            if (std::adjacent_find(sorted_nullifiers.begin(), sorted_nullifiers.end()) !=
                sorted_nullifiers.end()) {
                reject_reason = "bad-shielded-v2-ingress-payload-nullifier-uniqueness";
                return std::nullopt;
            }
            if (ComputeBatchLeafRoot(
                    Span<const BatchLeaf>{payload.ingress_leaves.data(), payload.ingress_leaves.size()}) !=
                payload.ingress_root) {
                reject_reason = "bad-shielded-v2-ingress-payload-ingress-root-mismatch";
            } else {
                bool positions_bad{false};
                for (size_t i = 0; i < payload.ingress_leaves.size(); ++i) {
                    if (payload.ingress_leaves[i].position != i) {
                        positions_bad = true;
                        break;
                    }
                }
                reject_reason = positions_bad ? "bad-shielded-v2-ingress-payload-leaf-position"
                                              : "bad-shielded-v2-ingress-payload";
            }
        }
        return std::nullopt;
    }

    CMutableTransaction tx_result{tx_template};
    tx_result.shielded_bundle.v2_bundle = BuildEmptyIngressBundle(payload,
                                                                  statement.envelope,
                                                                  consensus,
                                                                  validation_height);

    if (!tx_result.shielded_bundle.v2_bundle.has_value()) {
        reject_reason = "bad-shielded-v2-ingress-bundle";
        return std::nullopt;
    }
    auto& bundle = *tx_result.shielded_bundle.v2_bundle;
    bundle.proof_payload = std::move(serialized_payload);
    bundle.proof_shards.reserve(shard_plan->size());

    const std::vector<uint256> consumed_nullifiers = ExtractConsumedNullifiers(payload.consumed_spends);
    uint32_t next_payload_offset = static_cast<uint32_t>(serialized_header.size());
    for (size_t shard_index = 0; shard_index < shard_plan->size(); ++shard_index) {
        const auto& shard = (*shard_plan)[shard_index];
        const auto& shard_witness = witness.shards[shard_index];
        const std::vector<uint8_t> serialized_shard = SerializeSmileShardWitness(shard_witness);
        const Span<const uint256> shard_nullifiers{
            consumed_nullifiers.data() + static_cast<std::ptrdiff_t>(shard.spend_index),
            shard.spend_count};
        const Span<const OutputDescription> shard_payload_reserves{
            payload.reserve_outputs.data() + static_cast<std::ptrdiff_t>(shard.reserve_output_index),
            shard.reserve_output_count};
        const Span<const BatchLeaf> shard_payload_leaves{
            payload.ingress_leaves.data() + static_cast<std::ptrdiff_t>(shard.leaf_index),
            shard.leaf_count};
        std::optional<ProofShardDescriptor> descriptor;
        descriptor = BuildIngressSmileProofShardForBackend(
            backend,
            shard_nullifiers,
            shard_payload_reserves,
            shard_payload_leaves,
            Span<const uint8_t>{shard_witness.smile_witness->smile_proof_bytes.data(),
                                shard_witness.smile_witness->smile_proof_bytes.size()},
            statement.envelope.statement_digest,
            input.statement.domain_id,
            static_cast<uint32_t>(shard.leaf_index),
            next_payload_offset,
            static_cast<uint32_t>(serialized_shard.size()),
            reject_reason);
        if (!descriptor.has_value()) {
            return std::nullopt;
        }
        if (!descriptor->IsValid()) {
            if (descriptor->version != WIRE_VERSION) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-version";
            } else if (descriptor->leaf_count == 0) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-leaf-count";
            } else if (descriptor->settlement_domain.IsNull()) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-domain";
            } else if (descriptor->leaf_subroot.IsNull()) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-leaf-root";
            } else if (descriptor->nullifier_commitment.IsNull()) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-nullifiers";
            } else if (descriptor->value_commitment.IsNull()) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-value";
            } else if (descriptor->statement_digest.IsNull()) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-statement";
            } else if (descriptor->proof_metadata.empty() ||
                       descriptor->proof_metadata.size() > MAX_PROOF_METADATA_BYTES) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-metadata";
            } else if (descriptor->proof_payload_size == 0) {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard-payload";
            } else {
                reject_reason = "bad-shielded-v2-ingress-bundle-proof-shard";
            }
            return std::nullopt;
        }
        bundle.proof_shards.push_back(std::move(*descriptor));
        next_payload_offset += static_cast<uint32_t>(serialized_shard.size());
    }

    bundle.header.payload_digest = ComputeIngressBatchPayloadDigest(payload);
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    bundle.header.proof_shard_root = ComputeProofShardRoot(
        Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    if (!bundle.header.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-bundle-header";
        return std::nullopt;
    }
    if (bundle.header.proof_shard_count != bundle.proof_shards.size()) {
        reject_reason = "bad-shielded-v2-ingress-bundle-shard-count";
        return std::nullopt;
    }
    if (bundle.header.proof_shard_root != ComputeProofShardRoot(
            Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()})) {
        reject_reason = "bad-shielded-v2-ingress-bundle-shard-root";
        return std::nullopt;
    }
    if (!ProofShardCoverageIsCanonical(
            Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()},
            payload.ingress_leaves.size(),
            bundle.proof_payload.size())) {
        reject_reason = "bad-shielded-v2-ingress-bundle-coverage";
        return std::nullopt;
    }
    const ProofKind expected_proof_kind =
        GetWireProofKindForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                            ProofKind::BATCH_SMILE,
                                            consensus,
                                            validation_height);
    const SettlementBindingKind expected_binding_kind =
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                                        SettlementBindingKind::NATIVE_BATCH,
                                                        consensus,
                                                        validation_height);
    if (!(bundle.header.proof_envelope.proof_kind == expected_proof_kind &&
          bundle.header.proof_envelope.settlement_binding_kind == expected_binding_kind)) {
        reject_reason = "bad-shielded-v2-ingress-bundle-envelope";
        return std::nullopt;
    }
    if (!WireFamilyMatchesPayload(bundle.header.family_id, bundle.payload)) {
        reject_reason = "bad-shielded-v2-ingress-bundle-family";
        return std::nullopt;
    }
    if (ComputePayloadDigest(bundle.payload) != bundle.header.payload_digest) {
        reject_reason = "bad-shielded-v2-ingress-bundle-payload-digest";
        return std::nullopt;
    }
    if (!TransactionBundleOutputChunksAreCanonical(bundle)) {
        reject_reason = "bad-shielded-v2-ingress-bundle-output-chunks";
        return std::nullopt;
    }
    if (bundle.proof_payload.size() > MAX_PROOF_PAYLOAD_BYTES) {
        reject_reason = strprintf("bad-shielded-v2-ingress-bundle-proof-payload-size:%u",
                                  static_cast<unsigned>(bundle.proof_payload.size()));
        return std::nullopt;
    }
    if (!payload.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-bundle-payload-invalid";
        return std::nullopt;
    }
    if (std::any_of(bundle.proof_shards.begin(), bundle.proof_shards.end(), [&](const ProofShardDescriptor& descriptor) {
            return descriptor.statement_digest != bundle.header.proof_envelope.statement_digest;
        })) {
        reject_reason = "bad-shielded-v2-ingress-bundle-statement-digest";
        return std::nullopt;
    }
    if (bundle.header.netting_manifest_version != 0) {
        reject_reason = "bad-shielded-v2-ingress-bundle-netting-manifest";
        return std::nullopt;
    }
    if (!bundle.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-bundle";
        return std::nullopt;
    }

    std::string verify_reject_reason;
    auto context = ParseV2IngressProof(bundle, verify_reject_reason);
    if (!context.has_value()) {
        reject_reason = verify_reject_reason;
        return std::nullopt;
    }

    V2IngressBuildResult result;
    result.tx = std::move(tx_result);
    result.witness = std::move(witness);
    if (!result.IsValid()) {
        reject_reason = "bad-shielded-v2-ingress-result";
        return std::nullopt;
    }
    return result;
}

} // namespace shielded::v2
