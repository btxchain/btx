// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_V2_INGRESS_H
#define BTX_SHIELDED_V2_INGRESS_H

#include <consensus/amount.h>
#include <consensus/params.h>
#include <primitives/transaction.h>
#include <shielded/bridge.h>
#include <shielded/merkle_tree.h>
#include <shielded/ringct/matrict.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_proof.h>
#include <shielded/v2_send.h>

#include <span.h>

#include <optional>
#include <map>
#include <limits>
#include <string>
#include <vector>

namespace shielded::v2 {

static constexpr size_t MAX_MATRICT_INGRESS_OUTPUTS_PER_PROOF_SHARD{8};
static constexpr size_t MAX_SMILE_INGRESS_OUTPUTS_PER_PROOF_SHARD{8};
static constexpr size_t MAX_RECEIPT_BACKED_INGRESS_OUTPUTS_PER_PROOF_SHARD{64};
static constexpr size_t MAX_INGRESS_OUTPUTS_PER_PROOF_SHARD{
    MAX_SMILE_INGRESS_OUTPUTS_PER_PROOF_SHARD};

[[nodiscard]] inline size_t GetMaxIngressOutputsPerProofShard(
    const proof::NativeBatchBackend& backend)
{
    const auto matches = [](const proof::NativeBatchBackend& lhs,
                            const proof::NativeBatchBackend& rhs) {
        return lhs.version == rhs.version &&
               lhs.backend_id == rhs.backend_id &&
               lhs.membership_proof_kind == rhs.membership_proof_kind &&
               lhs.amount_proof_kind == rhs.amount_proof_kind &&
               lhs.balance_proof_kind == rhs.balance_proof_kind;
    };

    if (matches(backend, proof::DescribeMatRiCTPlusNativeBatchBackend())) {
        return MAX_MATRICT_INGRESS_OUTPUTS_PER_PROOF_SHARD;
    }
    if (matches(backend, proof::DescribeSmileNativeBatchBackend())) {
        return MAX_SMILE_INGRESS_OUTPUTS_PER_PROOF_SHARD;
    }
    if (matches(backend, proof::DescribeReceiptBackedNativeBatchBackend())) {
        return MAX_RECEIPT_BACKED_INGRESS_OUTPUTS_PER_PROOF_SHARD;
    }
    return 0;
}

struct V2IngressLeafInput
{
    uint8_t version{WIRE_VERSION};
    BridgeBatchLeaf bridge_leaf;
    uint256 l2_id;
    CAmount fee{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2IngressLeafInput::Serialize invalid version");
        ::Serialize(s, bridge_leaf);
        ::Serialize(s, l2_id);
        ::Serialize(s, fee);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2IngressLeafInput::Unserialize invalid version");
        ::Unserialize(s, bridge_leaf);
        ::Unserialize(s, l2_id);
        ::Unserialize(s, fee);
    }
};

struct V2IngressSpendWitness
{
    uint8_t version{WIRE_VERSION};
    // These fields are serialized as redacted placeholders so ingress spends
    // do not reveal the real ring member outside the proof system itself.
    uint32_t real_index{0};
    uint256 note_commitment;
    std::vector<uint64_t> ring_positions;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2IngressSpendWitness::Serialize invalid version");
        constexpr uint32_t REDACTED_REAL_INDEX{0};
        ::Serialize(s, REDACTED_REAL_INDEX);
        ::Serialize(s, note_commitment);
        detail::SerializeBoundedCompactSize(
            s,
            ring_positions.size(),
            shielded::lattice::MAX_RING_SIZE,
            "V2IngressSpendWitness::Serialize oversized ring_positions");
        for (const uint64_t position : ring_positions) {
            ::Serialize(s, position);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2IngressSpendWitness::Unserialize invalid version");
        ::Unserialize(s, real_index);
        ::Unserialize(s, note_commitment);
        const uint64_t ring_position_count = detail::UnserializeBoundedCompactSize(
            s,
            shielded::lattice::MAX_RING_SIZE,
            "V2IngressSpendWitness::Unserialize oversized ring_positions");
        ring_positions.assign(ring_position_count, 0);
        for (uint64_t& position : ring_positions) {
            ::Unserialize(s, position);
        }
    }
};

struct V2IngressSettlementWitness
{
    uint8_t version{WIRE_VERSION};
    std::vector<BridgeBatchReceipt> signed_receipts;
    std::vector<BridgeVerifierSetProof> signed_receipt_proofs;
    std::vector<BridgeProofReceipt> proof_receipts;
    std::vector<BridgeProofPolicyProof> proof_receipt_descriptor_proofs;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2IngressSettlementWitness::Serialize invalid version");
        detail::SerializeBoundedCompactSize(
            s,
            signed_receipts.size(),
            MAX_SETTLEMENT_REFS,
            "V2IngressSettlementWitness::Serialize oversized signed_receipts");
        for (const BridgeBatchReceipt& receipt : signed_receipts) {
            ::Serialize(s, receipt);
        }
        detail::SerializeBoundedCompactSize(
            s,
            signed_receipt_proofs.size(),
            MAX_SETTLEMENT_REFS,
            "V2IngressSettlementWitness::Serialize oversized signed_receipt_proofs");
        for (const BridgeVerifierSetProof& proof : signed_receipt_proofs) {
            ::Serialize(s, proof);
        }
        detail::SerializeBoundedCompactSize(
            s,
            proof_receipts.size(),
            MAX_SETTLEMENT_REFS,
            "V2IngressSettlementWitness::Serialize oversized proof_receipts");
        for (const BridgeProofReceipt& receipt : proof_receipts) {
            ::Serialize(s, receipt);
        }
        detail::SerializeBoundedCompactSize(
            s,
            proof_receipt_descriptor_proofs.size(),
            MAX_SETTLEMENT_REFS,
            "V2IngressSettlementWitness::Serialize oversized proof_receipt_descriptor_proofs");
        for (const BridgeProofPolicyProof& proof : proof_receipt_descriptor_proofs) {
            ::Serialize(s, proof);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2IngressSettlementWitness::Unserialize invalid version");
        const uint64_t signed_receipt_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_SETTLEMENT_REFS,
            "V2IngressSettlementWitness::Unserialize oversized signed_receipts");
        signed_receipts.assign(signed_receipt_count, {});
        for (BridgeBatchReceipt& receipt : signed_receipts) {
            ::Unserialize(s, receipt);
        }
        const uint64_t signed_receipt_proof_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_SETTLEMENT_REFS,
            "V2IngressSettlementWitness::Unserialize oversized signed_receipt_proofs");
        signed_receipt_proofs.assign(signed_receipt_proof_count, {});
        for (BridgeVerifierSetProof& proof : signed_receipt_proofs) {
            ::Unserialize(s, proof);
        }
        const uint64_t proof_receipt_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_SETTLEMENT_REFS,
            "V2IngressSettlementWitness::Unserialize oversized proof_receipts");
        proof_receipts.assign(proof_receipt_count, {});
        for (BridgeProofReceipt& receipt : proof_receipts) {
            ::Unserialize(s, receipt);
        }
        const uint64_t descriptor_proof_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_SETTLEMENT_REFS,
            "V2IngressSettlementWitness::Unserialize oversized proof_receipt_descriptor_proofs");
        proof_receipt_descriptor_proofs.assign(descriptor_proof_count, {});
        for (BridgeProofPolicyProof& proof : proof_receipt_descriptor_proofs) {
            ::Unserialize(s, proof);
        }
    }
};

struct V2IngressWitnessHeader
{
    uint8_t version{WIRE_VERSION};
    BridgeBatchStatement statement;
    std::vector<V2IngressLeafInput> ingress_leaves;
    std::optional<V2IngressSettlementWitness> settlement_witness;

    [[nodiscard]] bool IsValid(size_t expected_leaf_count) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2IngressWitnessHeader::Serialize invalid version");
        ::Serialize(s, statement);
        detail::SerializeBoundedCompactSize(
            s,
            ingress_leaves.size(),
            MAX_BATCH_LEAVES,
            "V2IngressWitnessHeader::Serialize oversized ingress_leaves");
        for (const V2IngressLeafInput& leaf : ingress_leaves) {
            ::Serialize(s, leaf);
        }
        const bool has_settlement_witness = settlement_witness.has_value();
        ::Serialize(s, has_settlement_witness);
        if (has_settlement_witness) {
            ::Serialize(s, *settlement_witness);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2IngressWitnessHeader::Unserialize invalid version");
        ::Unserialize(s, statement);
        const uint64_t leaf_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_BATCH_LEAVES,
            "V2IngressWitnessHeader::Unserialize oversized ingress_leaves");
        ingress_leaves.assign(leaf_count, {});
        for (V2IngressLeafInput& leaf : ingress_leaves) {
            ::Unserialize(s, leaf);
        }
        bool has_settlement_witness{false};
        ::Unserialize(s, has_settlement_witness);
        if (has_settlement_witness) {
            settlement_witness.emplace();
            ::Unserialize(s, *settlement_witness);
        } else {
            settlement_witness.reset();
        }
    }
};

struct V2IngressMatRiCTProofShardWitness
{
    uint8_t version{WIRE_VERSION};
    std::vector<V2IngressSpendWitness> spends;
    shielded::ringct::MatRiCTProof native_proof;

    [[nodiscard]] bool IsValid(size_t expected_input_count,
                               size_t expected_output_count) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2IngressProofShardWitness::Serialize invalid version");
        detail::SerializeBoundedCompactSize(
            s,
            spends.size(),
            shielded::ringct::MAX_MATRICT_INPUTS,
            "V2IngressProofShardWitness::Serialize oversized spends");
        for (const V2IngressSpendWitness& spend : spends) {
            ::Serialize(s, spend);
        }
        ::Serialize(s, native_proof);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2IngressProofShardWitness::Unserialize invalid version");
        const uint64_t spend_count = detail::UnserializeBoundedCompactSize(
            s,
            shielded::ringct::MAX_MATRICT_INPUTS,
            "V2IngressProofShardWitness::Unserialize oversized spends");
        spends.assign(spend_count, {});
        for (V2IngressSpendWitness& spend : spends) {
            ::Unserialize(s, spend);
        }
        ::Unserialize(s, native_proof);
    }
};

struct V2IngressReceiptProofShardWitness
{
    uint8_t version{WIRE_VERSION};
    std::vector<V2IngressSpendWitness> spends;
    uint32_t reserve_output_count{0};
    std::vector<uint256> ingress_note_commitments;
    uint32_t proof_receipt_index{0};

    [[nodiscard]] bool IsValid(size_t expected_input_count,
                               size_t expected_output_count,
                               size_t expected_leaf_count) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2IngressReceiptProofShardWitness::Serialize invalid version");
        detail::SerializeBoundedCompactSize(
            s,
            spends.size(),
            shielded::ringct::MAX_MATRICT_INPUTS,
            "V2IngressReceiptProofShardWitness::Serialize oversized spends");
        for (const V2IngressSpendWitness& spend : spends) {
            ::Serialize(s, spend);
        }
        ::Serialize(s, reserve_output_count);
        detail::SerializeBoundedCompactSize(
            s,
            ingress_note_commitments.size(),
            MAX_RECEIPT_BACKED_INGRESS_OUTPUTS_PER_PROOF_SHARD,
            "V2IngressReceiptProofShardWitness::Serialize oversized ingress_note_commitments");
        for (const uint256& note_commitment : ingress_note_commitments) {
            ::Serialize(s, note_commitment);
        }
        ::Serialize(s, proof_receipt_index);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2IngressReceiptProofShardWitness::Unserialize invalid version");
        const uint64_t spend_count = detail::UnserializeBoundedCompactSize(
            s,
            shielded::ringct::MAX_MATRICT_INPUTS,
            "V2IngressReceiptProofShardWitness::Unserialize oversized spends");
        spends.assign(spend_count, {});
        for (V2IngressSpendWitness& spend : spends) {
            ::Unserialize(s, spend);
        }
        ::Unserialize(s, reserve_output_count);
        const uint64_t ingress_note_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_RECEIPT_BACKED_INGRESS_OUTPUTS_PER_PROOF_SHARD,
            "V2IngressReceiptProofShardWitness::Unserialize oversized ingress_note_commitments");
        ingress_note_commitments.assign(ingress_note_count, {});
        for (uint256& note_commitment : ingress_note_commitments) {
            ::Unserialize(s, note_commitment);
        }
        ::Unserialize(s, proof_receipt_index);
    }
};

struct V2IngressSmileProofShardWitness
{
    uint8_t version{WIRE_VERSION};
    std::vector<V2IngressSpendWitness> spends;
    uint32_t reserve_output_count{0};
    uint32_t leaf_count{0};
    std::vector<uint8_t> smile_proof_bytes;

    [[nodiscard]] bool IsValid(size_t expected_input_count,
                               size_t expected_output_count,
                               size_t expected_leaf_count) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2IngressSmileProofShardWitness::Serialize invalid version");
        detail::SerializeBoundedCompactSize(
            s,
            spends.size(),
            shielded::ringct::MAX_MATRICT_INPUTS,
            "V2IngressSmileProofShardWitness::Serialize oversized spends");
        for (const V2IngressSpendWitness& spend : spends) {
            ::Serialize(s, spend);
        }
        ::Serialize(s, reserve_output_count);
        ::Serialize(s, leaf_count);
        detail::SerializeBoundedCompactSize(
            s,
            smile_proof_bytes.size(),
            smile2::MAX_SMILE2_PROOF_BYTES,
            "V2IngressSmileProofShardWitness::Serialize oversized smile_proof_bytes");
        for (const uint8_t byte : smile_proof_bytes) {
            ::Serialize(s, byte);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2IngressSmileProofShardWitness::Unserialize invalid version");
        const uint64_t spend_count = detail::UnserializeBoundedCompactSize(
            s,
            shielded::ringct::MAX_MATRICT_INPUTS,
            "V2IngressSmileProofShardWitness::Unserialize oversized spends");
        spends.assign(spend_count, {});
        for (V2IngressSpendWitness& spend : spends) {
            ::Unserialize(s, spend);
        }
        ::Unserialize(s, reserve_output_count);
        ::Unserialize(s, leaf_count);
        const uint64_t proof_size = detail::UnserializeBoundedCompactSize(
            s,
            smile2::MAX_SMILE2_PROOF_BYTES,
            "V2IngressSmileProofShardWitness::Unserialize oversized smile_proof_bytes");
        smile_proof_bytes.assign(proof_size, 0);
        for (uint8_t& byte : smile_proof_bytes) {
            ::Unserialize(s, byte);
        }
    }
};

struct V2IngressProofShardWitness
{
    std::vector<V2IngressSpendWitness> spends;
    std::optional<shielded::ringct::MatRiCTProof> native_proof;
    std::optional<V2IngressSmileProofShardWitness> smile_witness;
    std::optional<V2IngressReceiptProofShardWitness> receipt_witness;

    [[nodiscard]] bool UsesMatRiCTProof() const;
    [[nodiscard]] bool UsesSmileProof() const;
    [[nodiscard]] bool UsesReceiptBackedProof() const;
    [[nodiscard]] size_t OutputCount(size_t expected_leaf_count) const;
    [[nodiscard]] bool IsValid(const proof::NativeBatchBackend& backend,
                               size_t expected_input_count,
                               size_t expected_output_count,
                               size_t expected_leaf_count) const;
};

struct V2IngressWitness
{
    V2IngressWitnessHeader header;
    std::vector<V2IngressProofShardWitness> shards;

    [[nodiscard]] bool IsValid(const proof::NativeBatchBackend& backend,
                               size_t expected_input_count,
                               size_t expected_reserve_output_count,
                               size_t expected_leaf_count) const;
};

struct V2IngressContext
{
    proof::ProofMaterial material;
    proof::NativeBatchBackend backend;
    V2IngressWitness witness;

    [[nodiscard]] bool IsValid(size_t expected_input_count,
                               size_t expected_reserve_output_count,
                               size_t expected_leaf_count) const;
};

struct V2IngressStatementTemplate
{
    BridgePlanIds ids;
    uint256 domain_id;
    uint32_t source_epoch{0};
    uint256 data_root;
    BridgeVerifierSetCommitment verifier_set;
    BridgeProofPolicyCommitment proof_policy;

    [[nodiscard]] bool IsValid() const;
};

struct V2IngressBuildInput
{
    BridgeBatchStatement statement;
    std::vector<V2SendSpendInput> spend_inputs;
    std::vector<V2SendOutputInput> reserve_outputs;
    std::vector<V2IngressLeafInput> ingress_leaves;
    std::optional<V2IngressSettlementWitness> settlement_witness;
    std::optional<proof::NativeBatchBackend> backend_override;

    [[nodiscard]] bool IsValid() const;
};

struct V2IngressBuildResult
{
    CMutableTransaction tx;
    V2IngressWitness witness;

    [[nodiscard]] bool IsValid() const;
};

struct V2IngressShardScheduleEntry
{
    uint32_t spend_index{0};
    uint32_t spend_count{0};
    uint32_t reserve_output_index{0};
    uint32_t reserve_output_count{0};
    uint32_t leaf_index{0};
    uint32_t leaf_count{0};

    [[nodiscard]] bool IsValid() const;
    [[nodiscard]] bool IsValid(size_t max_outputs_per_proof_shard) const;
    [[nodiscard]] uint32_t TotalOutputCount() const;
};

struct V2IngressShardSchedule
{
    std::vector<V2IngressShardScheduleEntry> shards;

    [[nodiscard]] bool IsValid(size_t expected_spend_count,
                               size_t expected_reserve_output_count,
                               size_t expected_leaf_count) const;
    [[nodiscard]] bool IsValid(size_t expected_spend_count,
                               size_t expected_reserve_output_count,
                               size_t expected_leaf_count,
                               size_t max_outputs_per_proof_shard) const;
    [[nodiscard]] size_t MaxSpendInputCount() const;
    [[nodiscard]] size_t MaxReserveOutputCount() const;
    [[nodiscard]] size_t MaxIngressLeafCount() const;
    [[nodiscard]] size_t MaxOutputCount() const;
};

[[nodiscard]] uint256 ComputeV2IngressDestinationCommitment(const BridgeBatchLeaf& leaf,
                                                            const uint256& l2_id,
                                                            const uint256& settlement_domain);
[[nodiscard]] uint256 ComputeV2IngressFeeCommitment(const BridgeBatchLeaf& leaf,
                                                    const uint256& l2_id,
                                                    CAmount fee,
                                                    const uint256& settlement_domain);
[[nodiscard]] uint256 ComputeV2IngressSyntheticCreditNoteCommitment(const BridgeBatchStatement& statement,
                                                                    const V2IngressLeafInput& leaf,
                                                                    uint32_t index);
[[nodiscard]] BatchLeaf BuildV2IngressPayloadLeaf(const BridgeBatchStatement& statement,
                                                  const V2IngressLeafInput& ingress_input,
                                                  uint32_t index,
                                                  const Consensus::Params* consensus = nullptr,
                                                  int32_t validation_height = std::numeric_limits<int32_t>::max());
[[nodiscard]] uint256 ComputeV2IngressReceiptPublicValuesHash(Span<const uint256> nullifiers,
                                                              Span<const OutputDescription> reserve_outputs,
                                                              Span<const BatchLeaf> ingress_leaves,
                                                              Span<const uint256> ingress_note_commitments,
                                                              CAmount fee,
                                                              const uint256& statement_digest);
[[nodiscard]] std::optional<V2IngressShardSchedule> BuildCanonicalV2IngressShardSchedule(
    Span<const CAmount> spend_values,
    Span<const CAmount> reserve_values,
    Span<const V2IngressLeafInput> ingress_leaves);
[[nodiscard]] std::optional<V2IngressShardSchedule> BuildCanonicalV2IngressShardSchedule(
    Span<const CAmount> spend_values,
    Span<const CAmount> reserve_values,
    Span<const V2IngressLeafInput> ingress_leaves,
    const proof::NativeBatchBackend& backend);
[[nodiscard]] bool CanBuildCanonicalV2IngressShardPlan(
    Span<const CAmount> spend_values,
    Span<const CAmount> reserve_values,
    Span<const V2IngressLeafInput> ingress_leaves);
[[nodiscard]] bool CanBuildCanonicalV2IngressShardPlan(
    Span<const CAmount> spend_values,
    Span<const CAmount> reserve_values,
    Span<const V2IngressLeafInput> ingress_leaves,
    const proof::NativeBatchBackend& backend);
[[nodiscard]] std::optional<BridgeBatchStatement> BuildV2IngressStatement(
    const V2IngressStatementTemplate& statement_template,
    Span<const V2IngressLeafInput> ingress_leaves,
    std::string& reject_reason);

[[nodiscard]] std::optional<V2IngressWitness> ParseV2IngressWitness(
    const TransactionBundle& bundle,
    std::string& reject_reason);
[[nodiscard]] std::optional<V2IngressContext> ParseV2IngressProof(
    const TransactionBundle& bundle,
    std::string& reject_reason);
[[nodiscard]] std::optional<std::vector<std::vector<std::vector<uint256>>>> BuildV2IngressRingMembers(
    const V2IngressContext& context,
    const shielded::ShieldedMerkleTree& tree,
    std::string& reject_reason);
[[nodiscard]] std::optional<std::vector<std::vector<std::vector<smile2::wallet::SmileRingMember>>>>
BuildV2IngressSmileRingMembers(
    const V2IngressContext& context,
    const shielded::ShieldedMerkleTree& tree,
    const std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
    const std::map<uint256, uint256>& account_leaf_commitments,
    std::string& reject_reason);
[[nodiscard]] bool VerifyV2IngressProof(const TransactionBundle& bundle,
                                        const V2IngressContext& context,
                                        const std::vector<std::vector<std::vector<uint256>>>& ring_members,
                                        std::string& reject_reason);
[[nodiscard]] bool VerifyV2IngressProof(
    const TransactionBundle& bundle,
    const V2IngressContext& context,
    const std::vector<std::vector<std::vector<smile2::wallet::SmileRingMember>>>& ring_members,
    std::string& reject_reason,
    bool reject_rice_codec = false,
    bool bind_anonset_context = false);

[[nodiscard]] std::optional<V2IngressBuildResult> BuildV2IngressBatchTransaction(
    const CMutableTransaction& tx_template,
    const uint256& spend_anchor,
    const V2IngressBuildInput& input,
    Span<const unsigned char> spending_key,
    std::string& reject_reason,
    Span<const unsigned char> rng_entropy = {},
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max());

} // namespace shielded::v2

#endif // BTX_SHIELDED_V2_INGRESS_H
