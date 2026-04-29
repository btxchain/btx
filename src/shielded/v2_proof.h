// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_V2_PROOF_H
#define BTX_SHIELDED_V2_PROOF_H

#include <consensus/params.h>
#include <primitives/transaction.h>
#include <shielded/bridge.h>
#include <shielded/bundle.h>
#include <shielded/merkle_tree.h>
#include <shielded/ringct/matrict.h>
#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_types.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace shielded::v2::proof {

enum class VerificationDomain : uint8_t {
    DIRECT_SPEND = 1,
    BATCH_SETTLEMENT = 2,
    SPEND_PATH_RECOVERY = 3,
};

enum class PayloadLocation : uint8_t {
    INLINE_NON_WITNESS = 0,
    INLINE_WITNESS = 1,
    L1_DATA_AVAILABILITY = 2,
    OFFCHAIN = 3,
};

[[nodiscard]] bool IsValidVerificationDomain(VerificationDomain domain);
[[nodiscard]] bool IsValidPayloadLocation(PayloadLocation location);

[[nodiscard]] const char* GetVerificationDomainName(VerificationDomain domain);
[[nodiscard]] const char* GetPayloadLocationName(PayloadLocation location);

struct ProofStatement
{
    VerificationDomain domain{VerificationDomain::DIRECT_SPEND};
    ProofEnvelope envelope{};

    [[nodiscard]] bool IsValid() const;
};

struct ProofMaterial
{
    ProofStatement statement;
    PayloadLocation payload_location{PayloadLocation::INLINE_WITNESS};
    std::vector<ProofShardDescriptor> proof_shards;
    std::vector<uint8_t> proof_payload;

    [[nodiscard]] bool IsValid(size_t leaf_count) const;
};

struct DirectSpendContext
{
    ProofMaterial material;
    std::shared_ptr<const shielded::ringct::MatRiCTProof> native_proof;

    [[nodiscard]] bool IsValid(size_t expected_input_count) const;
};

struct V2SendSpendWitness
{
    uint8_t version{WIRE_VERSION};
    // Redacted on-chain placeholder. The MatRiCT proof authenticates the real
    // member against ring_positions without serializing its index publicly.
    uint32_t real_index{0};
    std::vector<uint64_t> ring_positions;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2SendSpendWitness::Serialize invalid version");
        constexpr uint32_t REDACTED_REAL_INDEX{0};
        ::Serialize(s, REDACTED_REAL_INDEX);
        detail::SerializeBoundedCompactSize(s, ring_positions.size(), shielded::lattice::MAX_RING_SIZE, "V2SendSpendWitness::Serialize oversized ring_positions");
        for (const uint64_t position : ring_positions) {
            ::Serialize(s, position);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2SendSpendWitness::Unserialize invalid version");
        ::Unserialize(s, real_index);
        const uint64_t ring_position_count = detail::UnserializeBoundedCompactSize(s, shielded::lattice::MAX_RING_SIZE, "V2SendSpendWitness::Unserialize oversized ring_positions");
        ring_positions.assign(ring_position_count, 0);
        for (uint64_t& position : ring_positions) {
            ::Unserialize(s, position);
        }
    }
};

struct V2SendWitness
{
    uint8_t version{WIRE_VERSION};
    std::vector<V2SendSpendWitness> spends;
    shielded::ringct::MatRiCTProof native_proof;

    /** When true, smile_proof_bytes holds a serialized SMILE v2 proof
     *  and native_proof is default-constructed (unused). */
    bool use_smile{false};
    std::vector<uint8_t> smile_proof_bytes;
    std::vector<smile2::BDLOPCommitment> smile_output_coins;

    [[nodiscard]] bool IsValid(size_t expected_input_count, size_t expected_output_count) const;

    /** Discriminant byte written after the spend witnesses to distinguish
     *  MatRiCT (0x00) from SMILE (0x01) proof payloads on the wire. */
    static constexpr uint8_t PROOF_TAG_MATRICT{0x00};
    static constexpr uint8_t PROOF_TAG_SMILE{0x01};

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "V2SendWitness::Serialize invalid version");
        detail::SerializeBoundedCompactSize(s, spends.size(), MAX_DIRECT_SPENDS, "V2SendWitness::Serialize oversized spends");
        for (const V2SendSpendWitness& spend : spends) {
            ::Serialize(s, spend);
        }
        if (use_smile) {
            ::Serialize(s, PROOF_TAG_SMILE);
            detail::SerializeBytes(s,
                                   smile_proof_bytes,
                                   smile2::MAX_SMILE2_PROOF_BYTES,
                                   "V2SendWitness::Serialize oversized smile_proof_bytes");
            detail::SerializeBoundedCompactSize(s,
                                               smile_output_coins.size(),
                                               MAX_DIRECT_OUTPUTS,
                                               "V2SendWitness::Serialize oversized smile_output_coins");
            for (const auto& output_coin : smile_output_coins) {
                smile2::SerializeCompactPublicCoin(s, output_coin);
            }
        } else {
            ::Serialize(s, PROOF_TAG_MATRICT);
            ::Serialize(s, native_proof);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "V2SendWitness::Unserialize invalid version");
        const uint64_t spend_count = detail::UnserializeBoundedCompactSize(s, MAX_DIRECT_SPENDS, "V2SendWitness::Unserialize oversized spends");
        spends.assign(spend_count, {});
        for (V2SendSpendWitness& spend : spends) {
            ::Unserialize(s, spend);
        }
        uint8_t proof_tag{0};
        ::Unserialize(s, proof_tag);
        if (proof_tag == PROOF_TAG_SMILE) {
            use_smile = true;
            detail::UnserializeBytes(s,
                                     smile_proof_bytes,
                                     smile2::MAX_SMILE2_PROOF_BYTES,
                                     "V2SendWitness::Unserialize oversized smile_proof_bytes");
            const uint64_t output_coin_count = detail::UnserializeBoundedCompactSize(
                s,
                MAX_DIRECT_OUTPUTS,
                "V2SendWitness::Unserialize oversized smile_output_coins");
            smile_output_coins.assign(output_coin_count, {});
            for (auto& output_coin : smile_output_coins) {
                smile2::UnserializeCompactPublicCoin(s, output_coin);
            }
        } else if (proof_tag == PROOF_TAG_MATRICT) {
            use_smile = false;
            ::Unserialize(s, native_proof);
        } else {
            throw std::runtime_error("V2SendWitness::Unserialize unknown proof tag");
        }
    }
};

struct SpendPathRecoverySpendWitness
{
    uint8_t version{WIRE_VERSION};
    std::vector<uint64_t> ring_positions;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s,
                                 version,
                                 "SpendPathRecoverySpendWitness::Serialize invalid version");
        detail::SerializeBoundedCompactSize(
            s,
            ring_positions.size(),
            1,
            "SpendPathRecoverySpendWitness::Serialize oversized ring_positions");
        for (const uint64_t position : ring_positions) {
            ::Serialize(s, position);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s,
                                   version,
                                   "SpendPathRecoverySpendWitness::Unserialize invalid version");
        const uint64_t ring_position_count = detail::UnserializeBoundedCompactSize(
            s,
            1,
            "SpendPathRecoverySpendWitness::Unserialize oversized ring_positions");
        ring_positions.assign(ring_position_count, 0);
        for (uint64_t& position : ring_positions) {
            ::Unserialize(s, position);
        }
    }
};

struct SpendPathRecoveryWitness
{
    uint8_t version{WIRE_VERSION};
    std::vector<SpendPathRecoverySpendWitness> spends;
    shielded::ringct::MatRiCTProof native_proof;

    [[nodiscard]] bool IsValid(size_t expected_input_count, size_t expected_output_count) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s,
                                 version,
                                 "SpendPathRecoveryWitness::Serialize invalid version");
        detail::SerializeBoundedCompactSize(
            s,
            spends.size(),
            MAX_DIRECT_SPENDS,
            "SpendPathRecoveryWitness::Serialize oversized spends");
        for (const SpendPathRecoverySpendWitness& spend : spends) {
            ::Serialize(s, spend);
        }
        ::Serialize(s, native_proof);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s,
                                   version,
                                   "SpendPathRecoveryWitness::Unserialize invalid version");
        const uint64_t spend_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_DIRECT_SPENDS,
            "SpendPathRecoveryWitness::Unserialize oversized spends");
        spends.assign(spend_count, {});
        for (SpendPathRecoverySpendWitness& spend : spends) {
            ::Unserialize(s, spend);
        }
        ::Unserialize(s, native_proof);
    }
};

struct V2SendContext
{
    ProofMaterial material;
    V2SendWitness witness;

    [[nodiscard]] bool IsValid(size_t expected_input_count, size_t expected_output_count) const;
};

struct SpendPathRecoveryContext
{
    ProofMaterial material;
    SpendPathRecoveryWitness witness;

    [[nodiscard]] bool IsValid(size_t expected_input_count, size_t expected_output_count) const;
};

struct NativeBatchBackend
{
    uint8_t version{1};
    uint256 backend_id;
    ProofComponentKind membership_proof_kind{ProofComponentKind::MATRICT};
    ProofComponentKind amount_proof_kind{ProofComponentKind::RANGE};
    ProofComponentKind balance_proof_kind{ProofComponentKind::BALANCE};

    [[nodiscard]] bool IsValid() const;
};

struct SettlementContext
{
    ProofMaterial material;
    std::optional<BridgeProofReceipt> imported_receipt;
    std::optional<BridgeProofClaim> imported_claim;
    std::optional<BridgeProofDescriptor> descriptor;
    std::optional<BridgeVerificationBundle> verification_bundle;

    [[nodiscard]] bool IsValid() const;
};

struct SettlementWitness
{
    uint8_t version{WIRE_VERSION};
    BridgeBatchStatement statement;
    std::vector<BridgeBatchReceipt> signed_receipts;
    std::vector<BridgeVerifierSetProof> signed_receipt_proofs;
    std::vector<BridgeProofReceipt> proof_receipts;
    std::vector<BridgeProofAdapter> imported_adapters;
    std::optional<BridgeProofPolicyProof> descriptor_proof;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "SettlementWitness::Serialize invalid version");
        ::Serialize(s, statement);
        detail::SerializeBoundedCompactSize(s, signed_receipts.size(), MAX_SETTLEMENT_REFS, "SettlementWitness::Serialize oversized signed_receipts");
        for (const BridgeBatchReceipt& receipt : signed_receipts) {
            ::Serialize(s, receipt);
        }
        detail::SerializeBoundedCompactSize(s, signed_receipt_proofs.size(), MAX_SETTLEMENT_REFS, "SettlementWitness::Serialize oversized signed_receipt_proofs");
        for (const BridgeVerifierSetProof& proof : signed_receipt_proofs) {
            ::Serialize(s, proof);
        }
        detail::SerializeBoundedCompactSize(s, proof_receipts.size(), MAX_SETTLEMENT_REFS, "SettlementWitness::Serialize oversized proof_receipts");
        for (const BridgeProofReceipt& receipt : proof_receipts) {
            ::Serialize(s, receipt);
        }
        detail::SerializeBoundedCompactSize(s, imported_adapters.size(), MAX_SETTLEMENT_REFS, "SettlementWitness::Serialize oversized imported_adapters");
        for (const BridgeProofAdapter& adapter : imported_adapters) {
            ::Serialize(s, adapter);
        }
        const bool has_descriptor_proof = descriptor_proof.has_value();
        ::Serialize(s, has_descriptor_proof);
        if (has_descriptor_proof) {
            ::Serialize(s, *descriptor_proof);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "SettlementWitness::Unserialize invalid version");
        ::Unserialize(s, statement);
        const uint64_t signed_receipt_count =
            detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "SettlementWitness::Unserialize oversized signed_receipts");
        signed_receipts.assign(signed_receipt_count, {});
        for (BridgeBatchReceipt& receipt : signed_receipts) {
            ::Unserialize(s, receipt);
        }
        const uint64_t signed_receipt_proof_count =
            detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "SettlementWitness::Unserialize oversized signed_receipt_proofs");
        signed_receipt_proofs.assign(signed_receipt_proof_count, {});
        for (BridgeVerifierSetProof& proof : signed_receipt_proofs) {
            ::Unserialize(s, proof);
        }
        const uint64_t proof_receipt_count =
            detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "SettlementWitness::Unserialize oversized proof_receipts");
        proof_receipts.assign(proof_receipt_count, {});
        for (BridgeProofReceipt& receipt : proof_receipts) {
            ::Unserialize(s, receipt);
        }
        const uint64_t adapter_count =
            detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "SettlementWitness::Unserialize oversized imported_adapters");
        imported_adapters.assign(adapter_count, {});
        for (BridgeProofAdapter& adapter : imported_adapters) {
            ::Unserialize(s, adapter);
        }
        bool has_descriptor_proof{false};
        ::Unserialize(s, has_descriptor_proof);
        if (has_descriptor_proof) {
            descriptor_proof.emplace();
            ::Unserialize(s, *descriptor_proof);
        } else {
            descriptor_proof.reset();
        }
    }
};

[[nodiscard]] ProofStatement DescribeLegacyDirectSpendStatement(const CTransaction& tx);
[[nodiscard]] ProofStatement DescribeLegacyDirectSpendStatement(const CTransaction& tx,
                                                               const Consensus::Params& consensus,
                                                               int32_t validation_height);
[[nodiscard]] uint256 ComputeV2SendStatementDigest(const CTransaction& tx);
[[nodiscard]] uint256 ComputeV2SendStatementDigest(const CTransaction& tx,
                                                   const Consensus::Params& consensus,
                                                   int32_t validation_height);
[[nodiscard]] uint256 ComputeV2SendExtensionDigest(const CTransaction& tx);
[[nodiscard]] uint256 ComputeSpendPathRecoveryStatementDigest(const CTransaction& tx);
[[nodiscard]] ProofStatement DescribeV2SendStatement(
    const CTransaction& tx,
    std::optional<uint256> extension_digest_override = std::nullopt);
[[nodiscard]] ProofStatement DescribeV2SendStatement(
    const CTransaction& tx,
    const Consensus::Params& consensus,
    int32_t validation_height,
    std::optional<uint256> extension_digest_override = std::nullopt);
[[nodiscard]] ProofStatement DescribeSpendPathRecoveryStatement(
    const CTransaction& tx,
    std::optional<uint256> extension_digest_override = std::nullopt);
[[nodiscard]] NativeBatchBackend DescribeSmileNativeBatchBackend();
[[nodiscard]] NativeBatchBackend DescribeMatRiCTPlusNativeBatchBackend();
[[nodiscard]] NativeBatchBackend DescribeReceiptBackedNativeBatchBackend();
[[nodiscard]] NativeBatchBackend SelectDefaultNativeBatchBackend();
[[nodiscard]] std::optional<NativeBatchBackend> ResolveNativeBatchBackend(
    const BridgeBatchStatement& statement,
    const ProofEnvelope& envelope);
[[nodiscard]] uint256 ComputeNativeBatchStatementDigest(const BridgeBatchStatement& statement,
                                                        const NativeBatchBackend& backend);
[[nodiscard]] ProofStatement DescribeNativeBatchSettlementStatement(const BridgeBatchStatement& statement,
                                                                   const NativeBatchBackend& backend);
[[nodiscard]] ProofStatement DescribeNativeBatchSettlementStatement(const BridgeBatchStatement& statement,
                                                                   const NativeBatchBackend& backend,
                                                                   const Consensus::Params& consensus,
                                                                   int32_t validation_height);
[[nodiscard]] uint256 ComputeSettlementExternalAnchorDigest(const BridgeExternalAnchor& anchor);

[[nodiscard]] std::optional<std::shared_ptr<const shielded::ringct::MatRiCTProof>> ParseLegacyDirectSpendNativeProof(
    const CShieldedBundle& bundle,
    std::string& reject_reason);
[[nodiscard]] std::optional<V2SendWitness> ParseV2SendWitness(const shielded::v2::TransactionBundle& bundle,
                                                              std::string& reject_reason);
[[nodiscard]] std::optional<SpendPathRecoveryWitness> ParseSpendPathRecoveryWitness(
    const shielded::v2::TransactionBundle& bundle,
    std::string& reject_reason);
[[nodiscard]] std::optional<std::shared_ptr<const shielded::ringct::MatRiCTProof>> ParseV2SendNativeProof(
    const shielded::v2::TransactionBundle& bundle,
    std::string& reject_reason);
[[nodiscard]] std::optional<SettlementWitness> ParseSettlementWitness(const std::vector<uint8_t>& proof_payload,
                                                                      std::string& reject_reason);
[[nodiscard]] std::optional<BridgeProofReceipt> ParseImportedSettlementReceipt(const ProofEnvelope& envelope,
                                                                               const ProofShardDescriptor& descriptor,
                                                                               std::string& reject_reason);
[[nodiscard]] std::optional<BridgeProofClaim> ParseImportedSettlementClaim(const ProofEnvelope& envelope,
                                                                           const ProofShardDescriptor& descriptor,
                                                                           std::string& reject_reason);

[[nodiscard]] DirectSpendContext BindLegacyDirectSpendProof(
    const CShieldedBundle& bundle,
    const ProofStatement& statement,
    std::shared_ptr<const shielded::ringct::MatRiCTProof> native_proof);

[[nodiscard]] std::optional<DirectSpendContext> ParseLegacyDirectSpendProof(
    const CShieldedBundle& bundle,
    const ProofStatement& statement,
    std::string& reject_reason);
[[nodiscard]] V2SendContext BindV2SendProof(const shielded::v2::TransactionBundle& bundle,
                                            const ProofStatement& statement,
                                            V2SendWitness witness);
[[nodiscard]] std::optional<V2SendContext> ParseV2SendProof(const shielded::v2::TransactionBundle& bundle,
                                                            const ProofStatement& statement,
                                                            std::string& reject_reason);
[[nodiscard]] SpendPathRecoveryContext BindSpendPathRecoveryProof(
    const shielded::v2::TransactionBundle& bundle,
    const ProofStatement& statement,
    SpendPathRecoveryWitness witness);
[[nodiscard]] std::optional<SpendPathRecoveryContext> ParseSpendPathRecoveryProof(
    const shielded::v2::TransactionBundle& bundle,
    const ProofStatement& statement,
    std::string& reject_reason);

[[nodiscard]] std::optional<std::vector<Nullifier>> ExtractBoundNullifiers(
    const shielded::ringct::MatRiCTProof& proof,
    size_t expected_input_count,
    std::string& reject_reason);

[[nodiscard]] std::optional<std::vector<Nullifier>> ExtractBoundNullifiers(
    const DirectSpendContext& context,
    size_t expected_input_count,
    std::string& reject_reason);
[[nodiscard]] std::optional<std::vector<Nullifier>> ExtractBoundNullifiers(
    const V2SendContext& context,
    size_t expected_input_count,
    size_t expected_output_count,
    std::string& reject_reason,
    bool reject_rice_codec = false);
[[nodiscard]] std::optional<std::vector<Nullifier>> ExtractBoundNullifiers(
    const SpendPathRecoveryContext& context,
    size_t expected_input_count,
    size_t expected_output_count,
    std::string& reject_reason,
    bool reject_rice_codec = false);

[[nodiscard]] std::optional<std::vector<std::vector<uint256>>> BuildLegacyDirectSpendRingMembers(
    const CShieldedBundle& bundle,
    const shielded::ShieldedMerkleTree& tree,
    std::string& reject_reason);
[[nodiscard]] std::optional<std::vector<std::vector<uint256>>> BuildV2SendRingMembers(
    const shielded::v2::TransactionBundle& bundle,
    const V2SendContext& context,
    const shielded::ShieldedMerkleTree& tree,
    std::string& reject_reason);
[[nodiscard]] std::optional<std::vector<std::vector<uint256>>> BuildSpendPathRecoveryRingMembers(
    const shielded::v2::TransactionBundle& bundle,
    const SpendPathRecoveryContext& context,
    const shielded::ShieldedMerkleTree& tree,
    std::string& reject_reason);
[[nodiscard]] std::optional<std::vector<std::vector<smile2::wallet::SmileRingMember>>> BuildV2SendSmileRingMembers(
    const shielded::v2::TransactionBundle& bundle,
    const V2SendContext& context,
    const shielded::ShieldedMerkleTree& tree,
    const std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
    const std::map<uint256, uint256>& account_leaf_commitments,
    std::string& reject_reason);
[[nodiscard]] std::optional<std::vector<std::vector<smile2::wallet::SmileRingMember>>> BuildSpendPathRecoverySmileRingMembers(
    const shielded::v2::TransactionBundle& bundle,
    const SpendPathRecoveryContext& context,
    const shielded::ShieldedMerkleTree& tree,
    const std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
    const std::map<uint256, uint256>& account_leaf_commitments,
    std::string& reject_reason);

[[nodiscard]] bool VerifyLegacyDirectSpendProof(
    const DirectSpendContext& context,
    const std::vector<std::vector<uint256>>& ring_members,
    const std::vector<Nullifier>& input_nullifiers,
    const std::vector<uint256>& output_note_commitments,
    CAmount value_balance);
[[nodiscard]] bool VerifyV2SendProof(const shielded::v2::TransactionBundle& bundle,
                                     const V2SendContext& context,
                                     const std::vector<std::vector<uint256>>& ring_members);
[[nodiscard]] bool VerifyV2SendProof(
    const shielded::v2::TransactionBundle& bundle,
    const V2SendContext& context,
    const std::vector<std::vector<smile2::wallet::SmileRingMember>>& ring_members,
    bool reject_rice_codec = false,
    bool bind_anonset_context = false);
[[nodiscard]] bool VerifySpendPathRecoveryProof(
    const shielded::v2::TransactionBundle& bundle,
    const SpendPathRecoveryContext& context,
    const std::vector<std::vector<uint256>>& ring_members);
[[nodiscard]] bool VerifySpendPathRecoveryProof(
    const shielded::v2::TransactionBundle& bundle,
    const SpendPathRecoveryContext& context,
    const std::vector<std::vector<smile2::wallet::SmileRingMember>>& ring_members,
    bool reject_rice_codec = false,
    bool bind_anonset_context = false);
[[nodiscard]] bool VerifySettlementContext(const SettlementContext& context,
                                           const SettlementWitness& witness,
                                           std::string& reject_reason);

[[nodiscard]] PayloadLocation ToPayloadLocation(BridgeAggregatePayloadLocation location);
[[nodiscard]] BridgeAggregatePayloadLocation ToBridgePayloadLocation(PayloadLocation location);

[[nodiscard]] SettlementContext DescribeImportedSettlementReceipt(
    const BridgeProofReceipt& receipt,
    PayloadLocation payload_location,
    const std::vector<uint8_t>& proof_payload = {},
    std::optional<BridgeProofDescriptor> descriptor = std::nullopt,
    std::optional<BridgeVerificationBundle> verification_bundle = std::nullopt);
[[nodiscard]] SettlementContext DescribeImportedSettlementReceipt(
    const BridgeProofReceipt& receipt,
    PayloadLocation payload_location,
    const std::vector<uint8_t>& proof_payload,
    const Consensus::Params& consensus,
    int32_t validation_height,
    std::optional<BridgeProofDescriptor> descriptor = std::nullopt,
    std::optional<BridgeVerificationBundle> verification_bundle = std::nullopt);

[[nodiscard]] SettlementContext DescribeImportedSettlementClaim(
    const BridgeProofClaim& claim,
    PayloadLocation payload_location,
    const std::vector<uint8_t>& proof_payload = {});
[[nodiscard]] SettlementContext DescribeImportedSettlementClaim(
    const BridgeProofClaim& claim,
    PayloadLocation payload_location,
    const std::vector<uint8_t>& proof_payload,
    const Consensus::Params& consensus,
    int32_t validation_height);

} // namespace shielded::v2::proof

#endif // BTX_SHIELDED_V2_PROOF_H
