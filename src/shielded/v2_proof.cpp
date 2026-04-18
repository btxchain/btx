// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_proof.h>

#include <consensus/amount.h>
#include <hash.h>
#include <logging.h>
#include <serialize.h>
#include <shielded/lattice/params.h>
#include <shielded/matrict_plus_backend.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/v2_bundle.h>
#include <shielded/smile2/wallet_bridge.h>
#include <streams.h>

#include <algorithm>
#include <exception>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace shielded::v2::proof {
namespace {

using shielded::ringct::MatRiCTProof;

constexpr std::string_view TAG_DIRECT_LEAF_SUBROOT{"BTX_ShieldedV2_Direct_Leaf_Subroot_V1"};
constexpr std::string_view TAG_DIRECT_NULLIFIER_COMMIT{"BTX_ShieldedV2_Direct_Nullifier_Commit_V1"};
constexpr std::string_view TAG_DIRECT_VALUE_COMMIT{"BTX_ShieldedV2_Direct_Value_Commit_V1"};
constexpr std::string_view TAG_V2_SEND_EXTENSION{"BTX_ShieldedV2_Send_Extension_V1"};
constexpr std::string_view TAG_V2_SEND_STATEMENT{"BTX_ShieldedV2_Send_Statement_V1"};
constexpr std::string_view TAG_V2_SEND_STATEMENT_CHAIN_BOUND{"BTX_ShieldedV2_Send_Statement_V2"};
constexpr std::string_view TAG_RECEIPT_VALUE_COMMIT{"BTX_ShieldedV2_Receipt_Value_Commit_V1"};
constexpr std::string_view TAG_CLAIM_VALUE_COMMIT{"BTX_ShieldedV2_Claim_Value_Commit_V1"};
constexpr std::string_view TAG_NATIVE_BATCH_STATEMENT{"BTX_ShieldedV2_Native_Batch_Statement_V1"};
constexpr std::string_view TAG_SETTLEMENT_EXTERNAL_ANCHOR{"BTX_ShieldedV2_Settlement_External_Anchor_V1"};

template <typename T>
[[nodiscard]] uint256 HashTaggedObject(std::string_view tag, const T& obj)
{
    HashWriter hw;
    hw << std::string{tag} << obj;
    return hw.GetSHA256();
}

[[nodiscard]] std::vector<uint8_t> ToByteVector(const DataStream& ds)
{
    if (ds.empty()) return {};
    const auto* begin = reinterpret_cast<const uint8_t*>(ds.data());
    return {begin, begin + ds.size()};
}

template <typename T>
[[nodiscard]] std::vector<uint8_t> SerializeToBytes(const T& obj)
{
    DataStream ds;
    ::Serialize(ds, obj);
    return ToByteVector(ds);
}

[[nodiscard]] bool UseChainBoundSendStatement(const Consensus::Params& consensus, int32_t validation_height)
{
    return consensus.IsShieldedMatRiCTDisabled(validation_height);
}

[[nodiscard]] uint32_t SendStatementForkHeight(const Consensus::Params& consensus)
{
    const int32_t disable_height = consensus.nShieldedMatRiCTDisableHeight;
    if (disable_height < 0 || disable_height == std::numeric_limits<int32_t>::max()) {
        return 0;
    }
    return static_cast<uint32_t>(disable_height);
}

[[nodiscard]] bool IsDirectSmileLikeProofKind(ProofKind kind)
{
    return kind == ProofKind::DIRECT_SMILE ||
           kind == ProofKind::GENERIC_SMILE ||
           kind == ProofKind::GENERIC_OPAQUE;
}

[[nodiscard]] bool IsBatchSmileLikeProofKind(ProofKind kind)
{
    return kind == ProofKind::BATCH_SMILE ||
           kind == ProofKind::GENERIC_SMILE ||
           kind == ProofKind::GENERIC_OPAQUE;
}

[[nodiscard]] bool IsImportedReceiptLikeProofKind(ProofKind kind)
{
    return kind == ProofKind::IMPORTED_RECEIPT ||
           kind == ProofKind::GENERIC_BRIDGE ||
           kind == ProofKind::GENERIC_OPAQUE;
}

[[nodiscard]] bool IsImportedClaimLikeProofKind(ProofKind kind)
{
    return kind == ProofKind::IMPORTED_CLAIM ||
           kind == ProofKind::GENERIC_BRIDGE ||
           kind == ProofKind::GENERIC_OPAQUE;
}

[[nodiscard]] bool EnvelopeHasNoProofComponents(const ProofEnvelope& envelope)
{
    return envelope.membership_proof_kind == ProofComponentKind::NONE &&
           envelope.amount_proof_kind == ProofComponentKind::NONE &&
           envelope.balance_proof_kind == ProofComponentKind::NONE;
}

[[nodiscard]] bool EnvelopeHasGenericOpaqueProofComponents(const ProofEnvelope& envelope)
{
    return envelope.membership_proof_kind == ProofComponentKind::GENERIC_OPAQUE &&
           envelope.amount_proof_kind == ProofComponentKind::GENERIC_OPAQUE &&
           envelope.balance_proof_kind == ProofComponentKind::GENERIC_OPAQUE;
}

[[nodiscard]] std::vector<uint8_t> SerializeMatRiCTProofMetadata(const MatRiCTProof& proof)
{
    DataStream meta;
    ::Serialize(meta, COMPACTSIZE(static_cast<uint64_t>(proof.input_commitments.size())));
    ::Serialize(meta, COMPACTSIZE(static_cast<uint64_t>(proof.output_commitments.size())));
    ::Serialize(meta, COMPACTSIZE(static_cast<uint64_t>(proof.output_range_proofs.size())));
    ::Serialize(meta, proof.challenge_seed);
    return ToByteVector(meta);
}

[[nodiscard]] std::vector<uint8_t> SerializeClaimMetadata(const BridgeProofClaim& claim)
{
    DataStream meta;
    ::Serialize(meta, static_cast<uint8_t>(claim.kind));
    ::Serialize(meta, static_cast<uint8_t>(claim.direction));
    ::Serialize(meta, claim.ids);
    ::Serialize(meta, claim.entry_count);
    ::Serialize(meta, claim.total_amount);
    ::Serialize(meta, claim.source_epoch);
    return ToByteVector(meta);
}

[[nodiscard]] std::vector<uint8_t> SerializeProofReceiptMetadata(const BridgeProofReceipt& receipt)
{
    DataStream meta;
    ::Serialize(meta, receipt.proof_system_id);
    ::Serialize(meta, receipt.verifier_key_hash);
    ::Serialize(meta, receipt.public_values_hash);
    return ToByteVector(meta);
}

[[nodiscard]] std::optional<std::tuple<BridgeProofClaimKind,
                                       BridgeDirection,
                                       BridgePlanIds,
                                       uint32_t,
                                       CAmount,
                                       uint32_t>>
DeserializeClaimMetadata(Span<const uint8_t> bytes)
{
    DataStream ds{std::vector<uint8_t>{bytes.begin(), bytes.end()}};
    try {
        uint8_t kind_u8{0};
        uint8_t direction_u8{0};
        BridgePlanIds ids;
        uint32_t entry_count{0};
        CAmount total_amount{0};
        uint32_t source_epoch{0};
        ::Unserialize(ds, kind_u8);
        ::Unserialize(ds, direction_u8);
        ::Unserialize(ds, ids);
        ::Unserialize(ds, entry_count);
        ::Unserialize(ds, total_amount);
        ::Unserialize(ds, source_epoch);
        if (!ds.empty()) return std::nullopt;
        return std::tuple{static_cast<BridgeProofClaimKind>(kind_u8),
                          static_cast<BridgeDirection>(direction_u8),
                          ids,
                          entry_count,
                          total_amount,
                          source_epoch};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<std::tuple<uint256, uint256, uint256>>
DeserializeProofReceiptMetadata(Span<const uint8_t> bytes)
{
    DataStream ds{std::vector<uint8_t>{bytes.begin(), bytes.end()}};
    try {
        uint256 proof_system_id;
        uint256 verifier_key_hash;
        uint256 public_values_hash;
        ::Unserialize(ds, proof_system_id);
        ::Unserialize(ds, verifier_key_hash);
        ::Unserialize(ds, public_values_hash);
        if (!ds.empty()) return std::nullopt;
        return std::tuple{proof_system_id, verifier_key_hash, public_values_hash};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

[[nodiscard]] uint256 HashRingMembers(const std::vector<std::vector<uint256>>& ring_members)
{
    HashWriter hw;
    hw << ring_members;
    return hw.GetSHA256();
}

[[nodiscard]] bool HasCanonicalSmileOutputCoin(const smile2::BDLOPCommitment& output_coin)
{
    return output_coin.t0.size() == smile2::BDLOP_RAND_DIM_BASE &&
           output_coin.t_msg.size() == 1;
}

[[nodiscard]] std::optional<smile2::CompactPublicKeyData> ResolveOutputPublicKeyData(
    const OutputDescription& output)
{
    if (output.smile_public_key.has_value() && output.smile_public_key->IsValid()) {
        return output.smile_public_key;
    }
    if (output.smile_account.has_value() && output.smile_account->IsValid()) {
        return smile2::ExtractCompactPublicKeyData(*output.smile_account);
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::vector<smile2::CompactPublicAccount>> ReconstructSmileOutputAccounts(
    const SendPayload& payload,
    Span<const smile2::BDLOPCommitment> output_coins)
{
    if (payload.outputs.size() != output_coins.size()) {
        return std::nullopt;
    }

    std::vector<smile2::CompactPublicAccount> accounts;
    accounts.reserve(payload.outputs.size());
    for (size_t output_index = 0; output_index < payload.outputs.size(); ++output_index) {
        const auto key_data = ResolveOutputPublicKeyData(payload.outputs[output_index]);
        if (!key_data.has_value() || !HasCanonicalSmileOutputCoin(output_coins[output_index])) {
            return std::nullopt;
        }
        auto reconstructed = smile2::BuildCompactPublicAccountFromPublicParts(
            *key_data,
            output_coins[output_index]);
        if (!reconstructed.has_value() ||
            smile2::ComputeCompactPublicAccountHash(*reconstructed) !=
                payload.outputs[output_index].note_commitment ||
            smile2::ComputeSmileOutputCoinHash(output_coins[output_index]) !=
                payload.outputs[output_index].value_commitment) {
            return std::nullopt;
        }
        accounts.push_back(std::move(*reconstructed));
    }
    return accounts;
}

[[nodiscard]] std::optional<std::vector<smile2::BDLOPCommitment>> CollectSmileOutputCoins(
    const V2SendWitness& witness,
    size_t expected_output_count)
{
    if (!witness.use_smile || witness.smile_output_coins.size() != expected_output_count) {
        return std::nullopt;
    }

    std::vector<smile2::BDLOPCommitment> output_coins;
    output_coins.reserve(witness.smile_output_coins.size());
    for (const auto& output_coin : witness.smile_output_coins) {
        if (!HasCanonicalSmileOutputCoin(output_coin)) {
            return std::nullopt;
        }
        output_coins.push_back(output_coin);
    }
    return output_coins;
}

[[nodiscard]] bool DescriptorHasBasicValidity(const ProofShardDescriptor& descriptor)
{
    if (descriptor.version != WIRE_VERSION) return false;
    if (descriptor.leaf_count == 0) return false;
    if (descriptor.proof_metadata.size() > MAX_PROOF_METADATA_BYTES) return false;
    const uint64_t payload_end =
        static_cast<uint64_t>(descriptor.proof_payload_offset) + descriptor.proof_payload_size;
    if (payload_end > std::numeric_limits<uint32_t>::max()) return false;
    return true;
}

[[nodiscard]] ProofEnvelope MakeEnvelope(ProofKind proof_kind,
                                         ProofComponentKind membership_kind,
                                         ProofComponentKind amount_kind,
                                         ProofComponentKind balance_kind,
                                         SettlementBindingKind settlement_binding_kind,
                                         const uint256& statement_digest,
                                         const uint256& extension_digest = uint256{})
{
    ProofEnvelope envelope;
    envelope.proof_kind = proof_kind;
    envelope.membership_proof_kind = membership_kind;
    envelope.amount_proof_kind = amount_kind;
    envelope.balance_proof_kind = balance_kind;
    envelope.settlement_binding_kind = settlement_binding_kind;
    envelope.statement_digest = statement_digest;
    envelope.extension_digest = extension_digest;
    return envelope;
}

[[nodiscard]] ProofShardDescriptor BuildLegacyDirectProofShard(const MatRiCTProof& proof,
                                                               const ProofStatement& statement,
                                                               uint32_t payload_size)
{
    ProofShardDescriptor descriptor;
    descriptor.first_leaf_index = 0;
    descriptor.leaf_count = static_cast<uint32_t>(proof.input_commitments.size());
    descriptor.leaf_subroot = HashTaggedObject(TAG_DIRECT_LEAF_SUBROOT, proof.input_commitments);
    descriptor.nullifier_commitment = HashTaggedObject(TAG_DIRECT_NULLIFIER_COMMIT, proof.ring_signature.key_images);

    HashWriter value_hw;
    value_hw << std::string{TAG_DIRECT_VALUE_COMMIT}
             << proof.balance_proof
             << proof.output_commitments
             << proof.output_note_commitments;
    descriptor.value_commitment = value_hw.GetSHA256();
    descriptor.statement_digest = statement.envelope.statement_digest;
    descriptor.proof_metadata = SerializeMatRiCTProofMetadata(proof);
    descriptor.proof_payload_offset = 0;
    descriptor.proof_payload_size = payload_size;
    return descriptor;
}

[[nodiscard]] ProofShardDescriptor BuildSmileDirectProofShard(const std::vector<uint8_t>& smile_bytes,
                                                              const SendPayload& payload,
                                                              Span<const uint256> smile_output_coin_hashes,
                                                              const ProofStatement& statement,
                                                              uint32_t payload_size)
{
    ProofShardDescriptor descriptor;
    descriptor.first_leaf_index = 0;
    descriptor.leaf_count = static_cast<uint32_t>(payload.spends.size());

    HashWriter leaf_hw;
    leaf_hw << std::string{TAG_DIRECT_LEAF_SUBROOT}
            << smile_bytes
            << payload.spend_anchor;
    for (const auto& spend : payload.spends) {
        leaf_hw << spend.merkle_anchor
                << spend.nullifier;
    }
    descriptor.leaf_subroot = leaf_hw.GetSHA256();

    HashWriter null_hw;
    null_hw << std::string{TAG_DIRECT_NULLIFIER_COMMIT}
            << smile_bytes
            << payload.spend_anchor;
    for (const auto& spend : payload.spends) {
        null_hw << spend.nullifier;
    }
    descriptor.nullifier_commitment = null_hw.GetSHA256();

    HashWriter value_hw;
    value_hw << std::string{TAG_DIRECT_VALUE_COMMIT}
             << smile_bytes
             << payload.fee;
    for (const auto& output : payload.outputs) {
        value_hw << static_cast<uint8_t>(output.note_class)
                 << output.note_commitment
                 << output.value_commitment;
    }
    value_hw << std::vector<uint256>{smile_output_coin_hashes.begin(), smile_output_coin_hashes.end()};
    descriptor.value_commitment = value_hw.GetSHA256();

    descriptor.statement_digest = statement.envelope.statement_digest;
    // SMILE proof metadata: just store the proof size.
    DataStream meta;
    ::Serialize(meta, COMPACTSIZE(static_cast<uint64_t>(smile_bytes.size())));
    descriptor.proof_metadata = ToByteVector(meta);
    descriptor.proof_payload_offset = 0;
    descriptor.proof_payload_size = payload_size;
    return descriptor;
}

[[nodiscard]] bool ProofEnvelopesMatch(const ProofEnvelope& lhs, const ProofEnvelope& rhs)
{
    return lhs.version == rhs.version &&
           lhs.proof_kind == rhs.proof_kind &&
           lhs.membership_proof_kind == rhs.membership_proof_kind &&
           lhs.amount_proof_kind == rhs.amount_proof_kind &&
           lhs.balance_proof_kind == rhs.balance_proof_kind &&
           lhs.settlement_binding_kind == rhs.settlement_binding_kind &&
           lhs.statement_digest == rhs.statement_digest &&
           lhs.extension_digest == rhs.extension_digest;
}

[[nodiscard]] bool NativeBatchBackendMatches(const NativeBatchBackend& lhs,
                                             const NativeBatchBackend& rhs)
{
    return lhs.version == rhs.version &&
           lhs.backend_id == rhs.backend_id &&
           lhs.membership_proof_kind == rhs.membership_proof_kind &&
           lhs.amount_proof_kind == rhs.amount_proof_kind &&
           lhs.balance_proof_kind == rhs.balance_proof_kind;
}

[[nodiscard]] ProofShardDescriptor BuildReceiptProofShard(const BridgeProofReceipt& receipt,
                                                          uint32_t payload_size)
{
    ProofShardDescriptor descriptor;
    descriptor.first_leaf_index = 0;
    descriptor.leaf_count = 1;
    descriptor.leaf_subroot = receipt.proof_commitment;
    descriptor.nullifier_commitment = receipt.public_values_hash;

    HashWriter value_hw;
    value_hw << std::string{TAG_RECEIPT_VALUE_COMMIT}
             << receipt.proof_system_id
             << receipt.verifier_key_hash;
    descriptor.value_commitment = value_hw.GetSHA256();
    descriptor.statement_digest = receipt.statement_hash;
    descriptor.proof_metadata = SerializeProofReceiptMetadata(receipt);
    descriptor.proof_payload_offset = 0;
    descriptor.proof_payload_size = payload_size;
    return descriptor;
}

[[nodiscard]] ProofShardDescriptor BuildClaimProofShard(const BridgeProofClaim& claim,
                                                        uint32_t payload_size)
{
    ProofShardDescriptor descriptor;
    descriptor.settlement_domain = claim.domain_id;
    descriptor.first_leaf_index = 0;
    descriptor.leaf_count = 1;
    descriptor.leaf_subroot = claim.batch_root;
    descriptor.nullifier_commitment = claim.data_root;

    HashWriter value_hw;
    value_hw << std::string{TAG_CLAIM_VALUE_COMMIT}
             << claim.entry_count
             << claim.total_amount;
    descriptor.value_commitment = value_hw.GetSHA256();
    descriptor.statement_digest = claim.statement_hash;
    descriptor.proof_metadata = SerializeClaimMetadata(claim);
    descriptor.proof_payload_offset = 0;
    descriptor.proof_payload_size = payload_size;
    return descriptor;
}

[[nodiscard]] std::optional<MatRiCTProof> ParseMatRiCTProof(
    const std::vector<uint8_t>& proof_bytes,
    size_t expected_input_count,
    size_t expected_output_count,
    std::string& reject_reason)
{
    if (proof_bytes.empty()) {
        reject_reason = "bad-shielded-proof-missing";
        return std::nullopt;
    }
    if (proof_bytes.size() > MAX_SHIELDED_PROOF_BYTES) {
        reject_reason = "bad-shielded-proof-oversize";
        return std::nullopt;
    }

    DataStream ds{proof_bytes};
    MatRiCTProof proof;
    try {
        ds >> proof;
    } catch (const std::exception&) {
        reject_reason = "bad-shielded-proof-encoding";
        return std::nullopt;
    }
    if (!ds.empty()) {
        reject_reason = "bad-shielded-proof-encoding";
        return std::nullopt;
    }
    if (proof.input_commitments.size() != expected_input_count) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    if (proof.output_commitments.size() != expected_output_count ||
        proof.output_range_proofs.size() != expected_output_count ||
        proof.output_note_commitments.size() != expected_output_count) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    if (!proof.IsValid()) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    const size_t ring_size =
        proof.ring_signature.input_proofs.empty() ? 0 : proof.ring_signature.input_proofs.front().responses.size();
    if (!proof.ring_signature.IsValid(expected_input_count, ring_size)) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    return proof;
}

[[nodiscard]] bool ReceiptHasRequiredFields(const BridgeProofReceipt& receipt)
{
    return !receipt.statement_hash.IsNull() &&
           !receipt.proof_system_id.IsNull() &&
           !receipt.verifier_key_hash.IsNull() &&
           !receipt.public_values_hash.IsNull() &&
           !receipt.proof_commitment.IsNull();
}

[[nodiscard]] bool ClaimHasRequiredFields(const BridgeProofClaim& claim)
{
    return !claim.statement_hash.IsNull() &&
           !claim.domain_id.IsNull() &&
           claim.entry_count > 0 &&
           MoneyRange(claim.total_amount) &&
           !claim.batch_root.IsNull() &&
           !claim.data_root.IsNull();
}

[[nodiscard]] bool DescriptorMatchesReceipt(const BridgeProofDescriptor& descriptor,
                                            const BridgeProofReceipt& receipt)
{
    return descriptor.proof_system_id == receipt.proof_system_id &&
           descriptor.verifier_key_hash == receipt.verifier_key_hash &&
           !descriptor.proof_system_id.IsNull() &&
           !descriptor.verifier_key_hash.IsNull();
}

[[nodiscard]] bool AdapterMatchesClaim(const BridgeBatchStatement& statement,
                                       const BridgeProofAdapter& adapter,
                                       const BridgeProofClaim& claim)
{
    if (!adapter.IsValid() || !claim.IsValid()) return false;
    const auto expected_claim = BuildBridgeProofClaimFromAdapter(statement, adapter);
    return expected_claim.has_value() &&
           SerializeBridgeProofClaim(*expected_claim) == SerializeBridgeProofClaim(claim);
}

[[nodiscard]] bool AdapterMatchesReceipt(const BridgeBatchStatement& statement,
                                         const BridgeProofAdapter& adapter,
                                         const BridgeProofReceipt& receipt)
{
    if (!adapter.IsValid() || !receipt.IsValid()) return false;
    const auto expected_receipt = BuildBridgeProofReceiptFromAdapter(statement,
                                                                     adapter,
                                                                     receipt.verifier_key_hash,
                                                                     receipt.proof_commitment);
    return expected_receipt.has_value() &&
           SerializeBridgeProofReceipt(*expected_receipt) == SerializeBridgeProofReceipt(receipt);
}

[[nodiscard]] bool DescriptorMatchesAllReceipts(const BridgeProofDescriptor& descriptor,
                                                Span<const BridgeProofReceipt> receipts)
{
    return std::all_of(receipts.begin(), receipts.end(), [&](const BridgeProofReceipt& receipt) {
        return DescriptorMatchesReceipt(descriptor, receipt);
    });
}

[[nodiscard]] bool ContainsProofReceipt(Span<const BridgeProofReceipt> receipts,
                                        const BridgeProofReceipt& target)
{
    const uint256 target_hash = ComputeBridgeProofReceiptHash(target);
    if (target_hash.IsNull()) return false;

    return std::any_of(receipts.begin(), receipts.end(), [&](const BridgeProofReceipt& receipt) {
        return ComputeBridgeProofReceiptHash(receipt) == target_hash;
    });
}

[[nodiscard]] bool HasSignedReceiptMembershipProofs(const BridgeBatchStatement& statement,
                                                    Span<const BridgeBatchReceipt> receipts,
                                                    Span<const BridgeVerifierSetProof> proofs)
{
    if (!statement.verifier_set.IsValid() || receipts.size() != proofs.size()) return false;
    for (size_t i = 0; i < receipts.size(); ++i) {
        if (!VerifyBridgeVerifierSetProof(statement.verifier_set, receipts[i].attestor, proofs[i])) return false;
    }
    return true;
}

[[nodiscard]] bool VerifyProofReceiptSet(const BridgeBatchStatement& statement,
                                         const BridgeProofDescriptor& descriptor,
                                         Span<const BridgeProofReceipt> receipts,
                                         const BridgeProofReceipt& imported_receipt,
                                         std::string& reject_reason)
{
    if (receipts.empty()) {
        reject_reason = "bad-v2-settlement-proof-receipts";
        return false;
    }
    if (CountDistinctBridgeProofReceipts(receipts) != receipts.size()) {
        reject_reason = "bad-v2-settlement-proof-receipts";
        return false;
    }
    if (!DescriptorMatchesAllReceipts(descriptor, receipts)) {
        reject_reason = "bad-v2-settlement-proof-descriptor";
        return false;
    }
    if (!ContainsProofReceipt(receipts, imported_receipt)) {
        reject_reason = "bad-v2-settlement-missing-imported-receipt";
        return false;
    }
    if (statement.proof_policy.IsValid() &&
        receipts.size() < static_cast<size_t>(statement.proof_policy.required_receipts)) {
        reject_reason = "bad-v2-settlement-proof-threshold";
        return false;
    }
    return true;
}

} // namespace

bool IsValidVerificationDomain(VerificationDomain domain)
{
    switch (domain) {
    case VerificationDomain::DIRECT_SPEND:
    case VerificationDomain::BATCH_SETTLEMENT:
        return true;
    }
    return false;
}

bool IsValidPayloadLocation(PayloadLocation location)
{
    switch (location) {
    case PayloadLocation::INLINE_NON_WITNESS:
    case PayloadLocation::INLINE_WITNESS:
    case PayloadLocation::L1_DATA_AVAILABILITY:
    case PayloadLocation::OFFCHAIN:
        return true;
    }
    return false;
}

const char* GetVerificationDomainName(VerificationDomain domain)
{
    switch (domain) {
    case VerificationDomain::DIRECT_SPEND:
        return "direct_spend";
    case VerificationDomain::BATCH_SETTLEMENT:
        return "batch_settlement";
    }
    return "unknown";
}

const char* GetPayloadLocationName(PayloadLocation location)
{
    switch (location) {
    case PayloadLocation::INLINE_NON_WITNESS:
        return "inline_non_witness";
    case PayloadLocation::INLINE_WITNESS:
        return "inline_witness";
    case PayloadLocation::L1_DATA_AVAILABILITY:
        return "l1_data_availability";
    case PayloadLocation::OFFCHAIN:
        return "offchain";
    }
    return "unknown";
}

bool ProofStatement::IsValid() const
{
    if (!IsValidVerificationDomain(domain)) return false;
    if (envelope.version != WIRE_VERSION) return false;
    if (!IsValidProofKind(envelope.proof_kind) ||
        !IsValidProofComponentKind(envelope.membership_proof_kind) ||
        !IsValidProofComponentKind(envelope.amount_proof_kind) ||
        !IsValidProofComponentKind(envelope.balance_proof_kind) ||
        !IsValidSettlementBindingKind(envelope.settlement_binding_kind)) {
        return false;
    }

    if (envelope.proof_kind == ProofKind::NONE) {
        return domain == VerificationDomain::DIRECT_SPEND &&
               EnvelopeHasNoProofComponents(envelope) &&
               (envelope.settlement_binding_kind == SettlementBindingKind::NONE ||
                shielded::v2::IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind)) &&
               envelope.statement_digest.IsNull();
    }

    if (envelope.statement_digest.IsNull()) {
        return false;
    }

    switch (domain) {
    case VerificationDomain::DIRECT_SPEND:
        return (envelope.proof_kind == ProofKind::DIRECT_MATRICT ||
                IsDirectSmileLikeProofKind(envelope.proof_kind)) &&
               envelope.membership_proof_kind != ProofComponentKind::NONE &&
               envelope.amount_proof_kind != ProofComponentKind::NONE &&
               envelope.balance_proof_kind != ProofComponentKind::NONE &&
               (envelope.settlement_binding_kind == SettlementBindingKind::NONE ||
                shielded::v2::IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind));
    case VerificationDomain::BATCH_SETTLEMENT:
        if (envelope.proof_kind == ProofKind::GENERIC_OPAQUE) {
            const bool no_components = EnvelopeHasNoProofComponents(envelope);
            const bool opaque_components = EnvelopeHasGenericOpaqueProofComponents(envelope);
            if (!no_components && !opaque_components) {
                return false;
            }

            const bool shielded_binding =
                envelope.settlement_binding_kind == SettlementBindingKind::NATIVE_BATCH ||
                envelope.settlement_binding_kind == SettlementBindingKind::NETTING_MANIFEST ||
                shielded::v2::IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind);
            const bool bridge_binding =
                envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_RECEIPT ||
                envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_CLAIM ||
                shielded::v2::IsGenericBridgeSettlementBindingKind(envelope.settlement_binding_kind);
            return (no_components && bridge_binding) ||
                   (opaque_components && (shielded_binding || bridge_binding));
        }
        if (envelope.proof_kind == ProofKind::BATCH_MATRICT) {
            return envelope.membership_proof_kind != ProofComponentKind::NONE &&
                   envelope.amount_proof_kind != ProofComponentKind::NONE &&
                   envelope.balance_proof_kind != ProofComponentKind::NONE &&
                   (envelope.settlement_binding_kind == SettlementBindingKind::NATIVE_BATCH ||
                    envelope.settlement_binding_kind == SettlementBindingKind::NETTING_MANIFEST ||
                    shielded::v2::IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind));
        }
        if (IsBatchSmileLikeProofKind(envelope.proof_kind)) {
            return envelope.membership_proof_kind != ProofComponentKind::NONE &&
                   envelope.amount_proof_kind != ProofComponentKind::NONE &&
                   envelope.balance_proof_kind != ProofComponentKind::NONE &&
                   (envelope.settlement_binding_kind == SettlementBindingKind::NATIVE_BATCH ||
                    envelope.settlement_binding_kind == SettlementBindingKind::NETTING_MANIFEST ||
                    shielded::v2::IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind));
        }
        if (IsImportedReceiptLikeProofKind(envelope.proof_kind)) {
            return (EnvelopeHasNoProofComponents(envelope) ||
                    EnvelopeHasGenericOpaqueProofComponents(envelope)) &&
                   (envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_RECEIPT ||
                    shielded::v2::IsGenericBridgeSettlementBindingKind(envelope.settlement_binding_kind));
        }
        if (IsImportedClaimLikeProofKind(envelope.proof_kind)) {
            return (EnvelopeHasNoProofComponents(envelope) ||
                    EnvelopeHasGenericOpaqueProofComponents(envelope)) &&
                   (envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_CLAIM ||
                    shielded::v2::IsGenericBridgeSettlementBindingKind(envelope.settlement_binding_kind));
        }
        return false;
    }
    return false;
}

bool ProofMaterial::IsValid(size_t leaf_count) const
{
    if (!statement.IsValid() || !IsValidPayloadLocation(payload_location)) {
        return false;
    }

    if (statement.envelope.proof_kind == ProofKind::NONE) {
        return leaf_count == 0 && proof_shards.empty() && proof_payload.empty();
    }

    if (proof_shards.empty()) {
        return false;
    }

    uint64_t next_leaf{0};
    for (const ProofShardDescriptor& descriptor : proof_shards) {
        if (!DescriptorHasBasicValidity(descriptor) ||
            descriptor.statement_digest != statement.envelope.statement_digest ||
            descriptor.first_leaf_index != next_leaf) {
            return false;
        }

        const uint64_t payload_end =
            static_cast<uint64_t>(descriptor.proof_payload_offset) + descriptor.proof_payload_size;
        if (payload_end > proof_payload.size()) {
            return false;
        }
        next_leaf += descriptor.leaf_count;
    }

    return next_leaf == leaf_count;
}

bool DirectSpendContext::IsValid(size_t expected_input_count) const
{
    if (!native_proof ||
        material.statement.domain != VerificationDomain::DIRECT_SPEND ||
        material.statement.envelope.proof_kind != ProofKind::DIRECT_MATRICT ||
        material.payload_location != PayloadLocation::INLINE_WITNESS ||
        native_proof->input_commitments.size() != expected_input_count ||
        !material.IsValid(expected_input_count)) {
        return false;
    }

    DataStream ds;
    ds << *native_proof;
    return ToByteVector(ds) == material.proof_payload;
}

bool V2SendSpendWitness::IsValid() const
{
    return version == WIRE_VERSION &&
           shielded::lattice::IsSupportedRingSize(ring_positions.size()) &&
           real_index == 0;
}

bool V2SendWitness::IsValid(size_t expected_input_count, size_t expected_output_count) const
{
    const size_t ring_size =
        spends.empty() ? 0 : spends.front().ring_positions.size();
    if (version != WIRE_VERSION ||
        spends.size() != expected_input_count ||
        !std::all_of(spends.begin(), spends.end(), [](const V2SendSpendWitness& spend) {
            return spend.IsValid();
        }) ||
        !std::all_of(spends.begin(), spends.end(), [ring_size](const V2SendSpendWitness& spend) {
            return spend.ring_positions.size() == ring_size;
        })) {
        return false;
    }

    if (expected_input_count == 0) {
        return !use_smile &&
               smile_proof_bytes.empty() &&
               smile_output_coins.empty() &&
               native_proof.input_commitments.empty() &&
               native_proof.output_commitments.empty() &&
               native_proof.output_range_proofs.empty() &&
               native_proof.output_note_commitments.empty() &&
               expected_output_count <= shielded::v2::MAX_DIRECT_OUTPUTS;
    }

    if (use_smile) {
        // SMILE witness validity: proof bytes are present and bounded, and
        // output coin commitments are carried alongside the proof on the
        // hard-fork witness.
        return !smile_proof_bytes.empty() &&
               smile_proof_bytes.size() <= smile2::MAX_SMILE2_PROOF_BYTES &&
               smile_output_coins.size() == expected_output_count &&
               std::all_of(smile_output_coins.begin(),
                           smile_output_coins.end(),
                           [](const smile2::BDLOPCommitment& output_coin) {
                               return HasCanonicalSmileOutputCoin(output_coin);
                           }) &&
               expected_output_count <= shielded::v2::MAX_DIRECT_OUTPUTS;
    }

    // MatRiCT witness validity (original checks).
    return native_proof.input_commitments.size() == expected_input_count &&
           native_proof.output_commitments.size() == expected_output_count &&
           native_proof.output_range_proofs.size() == expected_output_count &&
           native_proof.output_note_commitments.size() == expected_output_count &&
           native_proof.IsValid();
}

bool V2SendContext::IsValid(size_t expected_input_count, size_t expected_output_count) const
{
    if (material.statement.domain != VerificationDomain::DIRECT_SPEND ||
        material.payload_location != PayloadLocation::INLINE_WITNESS ||
        !witness.IsValid(expected_input_count, expected_output_count) ||
        !material.IsValid(expected_input_count)) {
        return false;
    }

    if (material.statement.envelope.proof_kind == ProofKind::NONE) {
        return expected_input_count == 0 &&
               !witness.use_smile &&
               material.proof_payload.empty();
    }

    if (witness.use_smile) {
        if (!IsDirectSmileLikeProofKind(material.statement.envelope.proof_kind)) {
            return false;
        }
    } else if (material.statement.envelope.proof_kind != ProofKind::DIRECT_MATRICT) {
        return false;
    }

    return SerializeToBytes(witness) == material.proof_payload;
}

bool NativeBatchBackend::IsValid() const
{
    if (version != 1 || backend_id.IsNull()) return false;
    if (membership_proof_kind == ProofComponentKind::NONE ||
        amount_proof_kind == ProofComponentKind::NONE ||
        balance_proof_kind == ProofComponentKind::NONE) {
        return false;
    }
    return IsValidProofComponentKind(membership_proof_kind) &&
           IsValidProofComponentKind(amount_proof_kind) &&
           IsValidProofComponentKind(balance_proof_kind);
}

bool SettlementContext::IsValid() const
{
    if (material.statement.domain != VerificationDomain::BATCH_SETTLEMENT || !material.IsValid(/*leaf_count=*/1)) {
        return false;
    }
    if (imported_receipt.has_value() == imported_claim.has_value()) {
        return false;
    }

    if (imported_receipt.has_value()) {
        if (!ReceiptHasRequiredFields(*imported_receipt) ||
            !IsImportedReceiptLikeProofKind(material.statement.envelope.proof_kind) ||
            (material.statement.envelope.settlement_binding_kind != SettlementBindingKind::BRIDGE_RECEIPT &&
             !shielded::v2::IsGenericBridgeSettlementBindingKind(
                 material.statement.envelope.settlement_binding_kind)) ||
            material.statement.envelope.statement_digest != imported_receipt->statement_hash) {
            return false;
        }
        if (descriptor.has_value() && !DescriptorMatchesReceipt(*descriptor, *imported_receipt)) {
            return false;
        }
        return true;
    }

    if (!ClaimHasRequiredFields(*imported_claim) ||
        !IsImportedClaimLikeProofKind(material.statement.envelope.proof_kind) ||
        (material.statement.envelope.settlement_binding_kind != SettlementBindingKind::BRIDGE_CLAIM &&
         !shielded::v2::IsGenericBridgeSettlementBindingKind(
             material.statement.envelope.settlement_binding_kind)) ||
        material.statement.envelope.statement_digest != imported_claim->statement_hash) {
        return false;
    }
    return !descriptor.has_value() && !verification_bundle.has_value();
}

bool SettlementWitness::IsValid() const
{
    if (version != WIRE_VERSION || !statement.IsValid()) return false;
    if (signed_receipts.size() != signed_receipt_proofs.size()) return false;
    if (signed_receipts.size() > MAX_SETTLEMENT_REFS ||
        signed_receipt_proofs.size() > MAX_SETTLEMENT_REFS ||
        proof_receipts.size() > MAX_SETTLEMENT_REFS ||
        imported_adapters.size() > MAX_SETTLEMENT_REFS) {
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
           std::all_of(imported_adapters.begin(), imported_adapters.end(), [](const BridgeProofAdapter& adapter) {
               return adapter.IsValid();
           }) &&
           (!descriptor_proof.has_value() || descriptor_proof->IsValid());
}

ProofStatement DescribeLegacyDirectSpendStatement(const CTransaction& tx)
{
    ProofStatement statement;
    statement.domain = VerificationDomain::DIRECT_SPEND;
    // Legacy direct-spend and unshield transactions still commit to the
    // historical MatRiCT binding hash and proof system.
    statement.envelope = MakeEnvelope(ProofKind::DIRECT_MATRICT,
                                      ProofComponentKind::MATRICT,
                                      ProofComponentKind::RANGE,
                                      ProofComponentKind::BALANCE,
                                      SettlementBindingKind::NONE,
                                      shielded::ringct::ComputeMatRiCTBindingHash(tx));
    return statement;
}

ProofStatement DescribeLegacyDirectSpendStatement(const CTransaction& tx,
                                                  const Consensus::Params& consensus,
                                                  int32_t validation_height)
{
    ProofStatement statement;
    statement.domain = VerificationDomain::DIRECT_SPEND;
    statement.envelope = MakeEnvelope(ProofKind::DIRECT_MATRICT,
                                      ProofComponentKind::MATRICT,
                                      ProofComponentKind::RANGE,
                                      ProofComponentKind::BALANCE,
                                      SettlementBindingKind::NONE,
                                      shielded::ringct::ComputeMatRiCTBindingHash(
                                          tx,
                                          consensus,
                                          validation_height));
    return statement;
}

uint256 ComputeV2SendStatementDigest(const CTransaction& tx)
{
    if (!tx.HasShieldedBundle()) return uint256{};
    const CShieldedBundle& shielded_bundle = tx.GetShieldedBundle();
    if (!shielded_bundle.HasV2Bundle()) return uint256{};
    const auto* v2_bundle = shielded_bundle.GetV2Bundle();
    if (v2_bundle == nullptr || !BundleHasSemanticFamily(*v2_bundle, TransactionFamily::V2_SEND)) {
        return uint256{};
    }

    CMutableTransaction tx_stripped{tx};
    if (!tx_stripped.shielded_bundle.v2_bundle.has_value()) return uint256{};
    auto& stripped_v2_bundle = *tx_stripped.shielded_bundle.v2_bundle;
    stripped_v2_bundle.proof_payload.clear();
    stripped_v2_bundle.header.proof_envelope.statement_digest = uint256{};

    const CTransaction immutable_tx_stripped{tx_stripped};
    HashWriter hw;
    hw << std::string{TAG_V2_SEND_STATEMENT} << TX_WITH_WITNESS(immutable_tx_stripped);
    return hw.GetSHA256();
}

uint256 ComputeV2SendStatementDigest(const CTransaction& tx,
                                     const Consensus::Params& consensus,
                                     int32_t validation_height)
{
    if (!tx.HasShieldedBundle()) return uint256{};
    const CShieldedBundle& shielded_bundle = tx.GetShieldedBundle();
    if (!shielded_bundle.HasV2Bundle()) return uint256{};
    const auto* v2_bundle = shielded_bundle.GetV2Bundle();
    if (v2_bundle == nullptr || !BundleHasSemanticFamily(*v2_bundle, TransactionFamily::V2_SEND)) {
        return uint256{};
    }

    CMutableTransaction tx_stripped{tx};
    if (!tx_stripped.shielded_bundle.v2_bundle.has_value()) return uint256{};
    auto& stripped_v2_bundle = *tx_stripped.shielded_bundle.v2_bundle;
    stripped_v2_bundle.proof_payload.clear();
    stripped_v2_bundle.header.proof_envelope.statement_digest = uint256{};

    const CTransaction immutable_tx_stripped{tx_stripped};
    HashWriter hw;
    if (UseChainBoundSendStatement(consensus, validation_height)) {
        hw << std::string{TAG_V2_SEND_STATEMENT_CHAIN_BOUND};
        hw << consensus.hashGenesisBlock;
        hw << SendStatementForkHeight(consensus);
    } else {
        hw << std::string{TAG_V2_SEND_STATEMENT};
    }
    hw << TX_WITH_WITNESS(immutable_tx_stripped);
    return hw.GetSHA256();
}

uint256 ComputeV2SendExtensionDigest(const CTransaction& tx)
{
    if (!tx.HasShieldedBundle()) return uint256{};
    const CShieldedBundle& shielded_bundle = tx.GetShieldedBundle();
    if (!shielded_bundle.HasV2Bundle()) return uint256{};
    const auto* v2_bundle = shielded_bundle.GetV2Bundle();
    if (v2_bundle == nullptr || !BundleHasSemanticFamily(*v2_bundle, TransactionFamily::V2_SEND)) {
        return uint256{};
    }

    CMutableTransaction tx_stripped{tx};
    if (!tx_stripped.shielded_bundle.v2_bundle.has_value()) return uint256{};
    auto& stripped_v2_bundle = *tx_stripped.shielded_bundle.v2_bundle;
    stripped_v2_bundle.proof_payload.clear();
    stripped_v2_bundle.header.proof_envelope.statement_digest = uint256{};
    stripped_v2_bundle.header.proof_envelope.extension_digest = uint256{};

    const CTransaction immutable_tx_stripped{tx_stripped};
    HashWriter hw;
    hw << std::string{TAG_V2_SEND_EXTENSION} << TX_WITH_WITNESS(immutable_tx_stripped);
    return hw.GetSHA256();
}

ProofStatement DescribeV2SendStatement(const CTransaction& tx,
                                       std::optional<uint256> extension_digest_override)
{
    ProofStatement statement;
    statement.domain = VerificationDomain::DIRECT_SPEND;
    const auto* v2_bundle = tx.HasShieldedBundle() ? tx.GetShieldedBundle().GetV2Bundle() : nullptr;
    if (v2_bundle != nullptr &&
        BundleHasSemanticFamily(*v2_bundle, TransactionFamily::V2_SEND) &&
        std::holds_alternative<SendPayload>(v2_bundle->payload) &&
        std::get<SendPayload>(v2_bundle->payload).spends.empty()) {
        statement.envelope = MakeEnvelope(ProofKind::NONE,
                                          ProofComponentKind::NONE,
                                          ProofComponentKind::NONE,
                                          ProofComponentKind::NONE,
                                          SettlementBindingKind::NONE,
                                          uint256{});
        return statement;
    }
    const uint256 digest = ComputeV2SendStatementDigest(tx);
    uint256 extension_digest;
    if (extension_digest_override.has_value()) {
        extension_digest = *extension_digest_override;
    } else if (tx.HasShieldedBundle()) {
        const auto* v2_bundle = tx.GetShieldedBundle().GetV2Bundle();
        if (v2_bundle != nullptr) {
            extension_digest = v2_bundle->header.proof_envelope.extension_digest;
        }
    }
    statement.envelope = MakeEnvelope(ProofKind::DIRECT_SMILE,
                                      ProofComponentKind::SMILE_MEMBERSHIP,
                                      ProofComponentKind::SMILE_BALANCE,
                                      ProofComponentKind::SMILE_BALANCE,
                                      SettlementBindingKind::NONE,
                                      digest,
                                      extension_digest);
    return statement;
}

ProofStatement DescribeV2SendStatement(const CTransaction& tx,
                                       const Consensus::Params& consensus,
                                       int32_t validation_height,
                                       std::optional<uint256> extension_digest_override)
{
    ProofStatement statement;
    statement.domain = VerificationDomain::DIRECT_SPEND;
    const auto* v2_bundle = tx.HasShieldedBundle() ? tx.GetShieldedBundle().GetV2Bundle() : nullptr;
    if (v2_bundle != nullptr &&
        BundleHasSemanticFamily(*v2_bundle, TransactionFamily::V2_SEND) &&
        std::holds_alternative<SendPayload>(v2_bundle->payload) &&
        std::get<SendPayload>(v2_bundle->payload).spends.empty()) {
        statement.envelope = MakeEnvelope(ProofKind::NONE,
                                          ProofComponentKind::NONE,
                                          ProofComponentKind::NONE,
                                          ProofComponentKind::NONE,
                                          SettlementBindingKind::NONE,
                                          uint256{});
        return statement;
    }
    const uint256 digest = ComputeV2SendStatementDigest(tx, consensus, validation_height);
    uint256 extension_digest;
    if (extension_digest_override.has_value()) {
        extension_digest = *extension_digest_override;
    } else if (tx.HasShieldedBundle()) {
        const auto* v2_bundle_ptr = tx.GetShieldedBundle().GetV2Bundle();
        if (v2_bundle_ptr != nullptr) {
            extension_digest = v2_bundle_ptr->header.proof_envelope.extension_digest;
        }
    }
    statement.envelope = MakeEnvelope(GetWireProofKindForValidationHeight(TransactionFamily::V2_SEND,
                                                                         ProofKind::DIRECT_SMILE,
                                                                         &consensus,
                                                                         validation_height),
                                      GetWireProofComponentKindForValidationHeight(
                                          ProofComponentKind::SMILE_MEMBERSHIP,
                                          &consensus,
                                          validation_height),
                                      GetWireProofComponentKindForValidationHeight(
                                          ProofComponentKind::SMILE_BALANCE,
                                          &consensus,
                                          validation_height),
                                      GetWireProofComponentKindForValidationHeight(
                                          ProofComponentKind::SMILE_BALANCE,
                                          &consensus,
                                          validation_height),
                                      GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_SEND,
                                                                                      SettlementBindingKind::NONE,
                                                                                      &consensus,
                                                                                      validation_height),
                                      digest,
                                      extension_digest);
    return statement;
}

NativeBatchBackend DescribeSmileNativeBatchBackend()
{
    NativeBatchBackend backend;

    HashWriter hw;
    hw << std::string{"BTX_ShieldedV2_NativeBatch_SmileBackend_V1"};
    backend.backend_id = hw.GetSHA256();
    backend.membership_proof_kind = ProofComponentKind::SMILE_MEMBERSHIP;
    backend.amount_proof_kind = ProofComponentKind::SMILE_BALANCE;
    backend.balance_proof_kind = ProofComponentKind::SMILE_BALANCE;
    return backend;
}

NativeBatchBackend DescribeMatRiCTPlusNativeBatchBackend()
{
    NativeBatchBackend backend;
    backend.backend_id = shielded::matrictplus::GetBackendId();
    backend.membership_proof_kind = ProofComponentKind::MATRICT;
    backend.amount_proof_kind = ProofComponentKind::RANGE;
    backend.balance_proof_kind = ProofComponentKind::BALANCE;
    return backend;
}

NativeBatchBackend DescribeReceiptBackedNativeBatchBackend()
{
    NativeBatchBackend backend;

    HashWriter hw;
    hw << std::string{"BTX_ShieldedV2_NativeBatch_ReceiptBackend_V1"};
    backend.backend_id = hw.GetSHA256();
    backend.membership_proof_kind = ProofComponentKind::RECEIPT;
    backend.amount_proof_kind = ProofComponentKind::RECEIPT;
    backend.balance_proof_kind = ProofComponentKind::RECEIPT;
    return backend;
}

NativeBatchBackend SelectDefaultNativeBatchBackend()
{
    return DescribeSmileNativeBatchBackend();
}

std::optional<NativeBatchBackend> ResolveNativeBatchBackend(const BridgeBatchStatement& statement,
                                                            const ProofEnvelope& envelope)
{
    if (!statement.IsValid() || !envelope.IsValid()) return std::nullopt;

    for (const NativeBatchBackend& backend : {DescribeSmileNativeBatchBackend()}) {
        const auto descriptor = DescribeNativeBatchSettlementStatement(statement, backend);
        if (!descriptor.IsValid()) {
            continue;
        }
        const bool proof_kind_matches =
            descriptor.envelope.proof_kind == envelope.proof_kind ||
            (descriptor.envelope.proof_kind == ProofKind::BATCH_SMILE &&
             (envelope.proof_kind == ProofKind::GENERIC_SMILE ||
              envelope.proof_kind == ProofKind::GENERIC_OPAQUE));
        const bool component_kinds_match =
            (descriptor.envelope.membership_proof_kind == envelope.membership_proof_kind &&
             descriptor.envelope.amount_proof_kind == envelope.amount_proof_kind &&
             descriptor.envelope.balance_proof_kind == envelope.balance_proof_kind) ||
            EnvelopeHasGenericOpaqueProofComponents(envelope);
        if (proof_kind_matches &&
            component_kinds_match &&
            (descriptor.envelope.settlement_binding_kind == envelope.settlement_binding_kind ||
             (shielded::v2::IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind) &&
              (descriptor.envelope.settlement_binding_kind == SettlementBindingKind::NATIVE_BATCH ||
               descriptor.envelope.settlement_binding_kind == SettlementBindingKind::NETTING_MANIFEST))) &&
            descriptor.envelope.statement_digest == envelope.statement_digest &&
            descriptor.envelope.extension_digest == envelope.extension_digest) {
            return backend;
        }
    }
    return std::nullopt;
}

uint256 ComputeNativeBatchStatementDigest(const BridgeBatchStatement& statement,
                                          const NativeBatchBackend& backend)
{
    if (!statement.IsValid() || !backend.IsValid()) return uint256{};

    HashWriter hw;
    hw << std::string{TAG_NATIVE_BATCH_STATEMENT}
       << ComputeBridgeBatchStatementHash(statement)
       << backend.version
       << backend.backend_id
       << static_cast<uint8_t>(backend.membership_proof_kind)
       << static_cast<uint8_t>(backend.amount_proof_kind)
       << static_cast<uint8_t>(backend.balance_proof_kind);
    return hw.GetSHA256();
}

ProofStatement DescribeNativeBatchSettlementStatement(const BridgeBatchStatement& statement,
                                                      const NativeBatchBackend& backend)
{
    ProofStatement descriptor;
    descriptor.domain = VerificationDomain::BATCH_SETTLEMENT;
    const ProofKind proof_kind = NativeBatchBackendMatches(backend, DescribeSmileNativeBatchBackend())
        ? ProofKind::BATCH_SMILE
        : ProofKind::BATCH_MATRICT;
    descriptor.envelope = MakeEnvelope(proof_kind,
                                       backend.membership_proof_kind,
                                       backend.amount_proof_kind,
                                       backend.balance_proof_kind,
                                       SettlementBindingKind::NATIVE_BATCH,
                                       ComputeNativeBatchStatementDigest(statement, backend),
                                       statement.aggregate_commitment.IsValid()
                                           ? ComputeBridgeBatchAggregateCommitmentHash(statement.aggregate_commitment)
                                           : uint256{});
    return descriptor;
}

ProofStatement DescribeNativeBatchSettlementStatement(const BridgeBatchStatement& statement,
                                                      const NativeBatchBackend& backend,
                                                      const Consensus::Params& consensus,
                                                      int32_t validation_height)
{
    auto descriptor = DescribeNativeBatchSettlementStatement(statement, backend);
    descriptor.envelope.proof_kind =
        GetWireProofKindForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                            descriptor.envelope.proof_kind,
                                            &consensus,
                                            validation_height);
    descriptor.envelope.membership_proof_kind =
        GetWireProofComponentKindForValidationHeight(descriptor.envelope.membership_proof_kind,
                                                     &consensus,
                                                     validation_height);
    descriptor.envelope.amount_proof_kind =
        GetWireProofComponentKindForValidationHeight(descriptor.envelope.amount_proof_kind,
                                                     &consensus,
                                                     validation_height);
    descriptor.envelope.balance_proof_kind =
        GetWireProofComponentKindForValidationHeight(descriptor.envelope.balance_proof_kind,
                                                     &consensus,
                                                     validation_height);
    descriptor.envelope.settlement_binding_kind =
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_INGRESS_BATCH,
                                                        SettlementBindingKind::NATIVE_BATCH,
                                                        &consensus,
                                                        validation_height);
    return descriptor;
}

uint256 ComputeSettlementExternalAnchorDigest(const BridgeExternalAnchor& anchor)
{
    if (!anchor.IsValid()) return uint256{};
    return HashTaggedObject(TAG_SETTLEMENT_EXTERNAL_ANCHOR, anchor);
}

std::optional<std::shared_ptr<const MatRiCTProof>> ParseLegacyDirectSpendNativeProof(
    const CShieldedBundle& bundle,
    std::string& reject_reason)
{
    auto parsed = ParseMatRiCTProof(bundle.proof,
                                    bundle.shielded_inputs.size(),
                                    bundle.shielded_outputs.size(),
                                    reject_reason);
    if (!parsed.has_value()) return std::nullopt;
    return std::make_shared<MatRiCTProof>(std::move(*parsed));
}

std::optional<V2SendWitness> ParseV2SendWitness(const shielded::v2::TransactionBundle& bundle,
                                                std::string& reject_reason)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_SEND) ||
        !std::holds_alternative<SendPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    const auto& payload = std::get<SendPayload>(bundle.payload);
    if (bundle.header.proof_envelope.proof_kind == ProofKind::NONE) {
        if (!payload.spends.empty() || !bundle.proof_payload.empty()) {
            reject_reason = "bad-shielded-proof";
            return std::nullopt;
        }
        V2SendWitness witness;
        if (!witness.IsValid(/*expected_input_count=*/0, payload.outputs.size())) {
            reject_reason = "bad-shielded-proof";
            return std::nullopt;
        }
        return witness;
    }
    if (bundle.proof_payload.empty()) {
        reject_reason = "bad-shielded-proof-missing";
        return std::nullopt;
    }

    DataStream ds{bundle.proof_payload};
    V2SendWitness witness;
    try {
        ds >> witness;
    } catch (const std::exception&) {
        reject_reason = "bad-shielded-proof-encoding";
        return std::nullopt;
    }
    if (!ds.empty()) {
        reject_reason = "bad-shielded-proof-encoding";
        return std::nullopt;
    }

    for (const auto& spend : witness.spends) {
        if (!shielded::lattice::IsSupportedRingSize(spend.ring_positions.size())) {
            reject_reason = "bad-shielded-ring-positions";
            return std::nullopt;
        }
    }

    if (!witness.IsValid(payload.spends.size(), payload.outputs.size())) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    return witness;
}

std::optional<std::shared_ptr<const MatRiCTProof>> ParseV2SendNativeProof(
    const shielded::v2::TransactionBundle& bundle,
    std::string& reject_reason)
{
    auto witness = ParseV2SendWitness(bundle, reject_reason);
    if (!witness.has_value()) return std::nullopt;
    return std::make_shared<MatRiCTProof>(std::move(witness->native_proof));
}

std::optional<SettlementWitness> ParseSettlementWitness(const std::vector<uint8_t>& proof_payload,
                                                        std::string& reject_reason)
{
    if (proof_payload.empty()) {
        reject_reason = "bad-v2-settlement-witness-missing";
        return std::nullopt;
    }

    DataStream ds{proof_payload};
    SettlementWitness witness;
    try {
        ds >> witness;
    } catch (const std::exception&) {
        reject_reason = "bad-v2-settlement-witness-encoding";
        return std::nullopt;
    }
    if (!ds.empty()) {
        reject_reason = "bad-v2-settlement-witness-encoding";
        return std::nullopt;
    }
    if (!witness.IsValid()) {
        reject_reason = "bad-v2-settlement-witness";
        return std::nullopt;
    }
    return witness;
}

std::optional<BridgeProofReceipt> ParseImportedSettlementReceipt(const ProofEnvelope& envelope,
                                                                 const ProofShardDescriptor& descriptor,
                                                                 std::string& reject_reason)
{
    if (!IsImportedReceiptLikeProofKind(envelope.proof_kind) ||
        (envelope.settlement_binding_kind != SettlementBindingKind::BRIDGE_RECEIPT &&
         !shielded::v2::IsGenericBridgeSettlementBindingKind(envelope.settlement_binding_kind)) ||
        envelope.statement_digest.IsNull()) {
        reject_reason = "bad-v2-settlement-receipt";
        return std::nullopt;
    }

    const auto metadata = DeserializeProofReceiptMetadata(
        Span<const uint8_t>{descriptor.proof_metadata.data(), descriptor.proof_metadata.size()});
    if (!metadata.has_value()) {
        reject_reason = "bad-v2-settlement-receipt";
        return std::nullopt;
    }

    BridgeProofReceipt receipt;
    receipt.statement_hash = envelope.statement_digest;
    receipt.proof_commitment = descriptor.leaf_subroot;
    receipt.proof_system_id = std::get<0>(*metadata);
    receipt.verifier_key_hash = std::get<1>(*metadata);
    receipt.public_values_hash = std::get<2>(*metadata);

    HashWriter value_hw;
    value_hw << std::string{TAG_RECEIPT_VALUE_COMMIT}
             << receipt.proof_system_id
             << receipt.verifier_key_hash;
    if (descriptor.statement_digest != receipt.statement_hash ||
        descriptor.nullifier_commitment != receipt.public_values_hash ||
        descriptor.value_commitment != value_hw.GetSHA256() ||
        !receipt.IsValid()) {
        reject_reason = "bad-v2-settlement-receipt";
        return std::nullopt;
    }

    return receipt;
}

std::optional<BridgeProofClaim> ParseImportedSettlementClaim(const ProofEnvelope& envelope,
                                                             const ProofShardDescriptor& descriptor,
                                                             std::string& reject_reason)
{
    if (!IsImportedClaimLikeProofKind(envelope.proof_kind) ||
        (envelope.settlement_binding_kind != SettlementBindingKind::BRIDGE_CLAIM &&
         !shielded::v2::IsGenericBridgeSettlementBindingKind(envelope.settlement_binding_kind)) ||
        envelope.statement_digest.IsNull()) {
        reject_reason = "bad-v2-settlement-claim";
        return std::nullopt;
    }

    const auto metadata = DeserializeClaimMetadata(
        Span<const uint8_t>{descriptor.proof_metadata.data(), descriptor.proof_metadata.size()});
    if (!metadata.has_value()) {
        reject_reason = "bad-v2-settlement-claim";
        return std::nullopt;
    }

    BridgeProofClaim claim;
    claim.statement_hash = envelope.statement_digest;
    claim.kind = std::get<0>(*metadata);
    claim.direction = std::get<1>(*metadata);
    claim.ids = std::get<2>(*metadata);
    claim.entry_count = std::get<3>(*metadata);
    claim.total_amount = std::get<4>(*metadata);
    claim.source_epoch = std::get<5>(*metadata);
    claim.domain_id = descriptor.settlement_domain;
    claim.batch_root = descriptor.leaf_subroot;
    claim.data_root = descriptor.nullifier_commitment;

    HashWriter value_hw;
    value_hw << std::string{TAG_CLAIM_VALUE_COMMIT}
             << claim.entry_count
             << claim.total_amount;
    if (descriptor.statement_digest != claim.statement_hash ||
        descriptor.value_commitment != value_hw.GetSHA256() ||
        !claim.IsValid()) {
        reject_reason = "bad-v2-settlement-claim";
        return std::nullopt;
    }

    return claim;
}

DirectSpendContext BindLegacyDirectSpendProof(const CShieldedBundle& bundle,
                                              const ProofStatement& statement,
                                              std::shared_ptr<const MatRiCTProof> native_proof)
{
    DirectSpendContext context;
    context.material.statement = statement;
    context.material.payload_location = PayloadLocation::INLINE_WITNESS;
    context.material.proof_payload = bundle.proof;
    if (native_proof) {
        context.material.proof_shards.push_back(
            BuildLegacyDirectProofShard(*native_proof, statement, static_cast<uint32_t>(bundle.proof.size())));
    }
    context.native_proof = std::move(native_proof);
    return context;
}

std::optional<DirectSpendContext> ParseLegacyDirectSpendProof(const CShieldedBundle& bundle,
                                                              const ProofStatement& statement,
                                                              std::string& reject_reason)
{
    auto native_proof = ParseLegacyDirectSpendNativeProof(bundle, reject_reason);
    if (!native_proof.has_value()) return std::nullopt;
    return BindLegacyDirectSpendProof(bundle, statement, *native_proof);
}

V2SendContext BindV2SendProof(const shielded::v2::TransactionBundle& bundle,
                              const ProofStatement& statement,
                              V2SendWitness witness)
{
    V2SendContext context;
    context.material.statement = statement;
    context.material.payload_location = PayloadLocation::INLINE_WITNESS;
    context.material.proof_payload = bundle.proof_payload;
    if (statement.envelope.proof_kind == ProofKind::NONE) {
        context.witness = std::move(witness);
        return context;
    }
    if (witness.use_smile) {
        const auto& payload = std::get<SendPayload>(bundle.payload);
        const auto output_coins = CollectSmileOutputCoins(witness, payload.outputs.size());
        if (!output_coins.has_value()) {
            context.witness = std::move(witness);
            return context;
        }
        std::vector<uint256> smile_output_coin_hashes;
        smile_output_coin_hashes.reserve(output_coins->size());
        for (const auto& coin : *output_coins) {
            smile_output_coin_hashes.push_back(smile2::ComputeSmileOutputCoinHash(coin));
        }
        context.material.proof_shards.push_back(
            BuildSmileDirectProofShard(witness.smile_proof_bytes,
                                       payload,
                                       Span<const uint256>{smile_output_coin_hashes.data(),
                                                           smile_output_coin_hashes.size()},
                                       statement,
                                       static_cast<uint32_t>(bundle.proof_payload.size())));
    } else {
        context.material.proof_shards.push_back(
            BuildLegacyDirectProofShard(witness.native_proof,
                                        statement,
                                        static_cast<uint32_t>(bundle.proof_payload.size())));
    }
    context.witness = std::move(witness);
    return context;
}

std::optional<V2SendContext> ParseV2SendProof(const shielded::v2::TransactionBundle& bundle,
                                              const ProofStatement& statement,
                                              std::string& reject_reason)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_SEND) ||
        !std::holds_alternative<SendPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    if (!ProofEnvelopesMatch(bundle.header.proof_envelope, statement.envelope)) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }

    auto witness = ParseV2SendWitness(bundle, reject_reason);
    if (!witness.has_value()) return std::nullopt;
    if (statement.envelope.proof_kind == ProofKind::NONE) {
        auto context = BindV2SendProof(bundle, statement, std::move(*witness));
        const auto& payload = std::get<SendPayload>(bundle.payload);
        if (!context.IsValid(payload.spends.size(), payload.outputs.size())) {
            reject_reason = "bad-shielded-proof";
            return std::nullopt;
        }
        return context;
    }
    if (IsDirectSmileLikeProofKind(statement.envelope.proof_kind) && !witness->use_smile) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    if (statement.envelope.proof_kind == ProofKind::DIRECT_MATRICT && witness->use_smile) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    auto context = BindV2SendProof(bundle, statement, std::move(*witness));
    const auto& payload = std::get<SendPayload>(bundle.payload);
    if (!context.IsValid(payload.spends.size(), payload.outputs.size())) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    return context;
}

std::optional<std::vector<Nullifier>> ExtractBoundNullifiers(const MatRiCTProof& proof,
                                                             size_t expected_input_count,
                                                             std::string& reject_reason)
{
    const size_t ring_size =
        proof.ring_signature.input_proofs.empty() ? 0 : proof.ring_signature.input_proofs.front().responses.size();
    if (!proof.ring_signature.IsValid(expected_input_count, ring_size)) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }

    std::vector<Nullifier> out;
    out.reserve(proof.ring_signature.key_images.size());
    for (const auto& key_image : proof.ring_signature.key_images) {
        const Nullifier nf = shielded::ringct::ComputeNullifierFromKeyImage(key_image);
        if (nf.IsNull()) {
            reject_reason = "bad-shielded-proof";
            return std::nullopt;
        }
        out.push_back(nf);
    }
    if (out.size() != expected_input_count) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    return out;
}

std::optional<std::vector<Nullifier>> ExtractBoundNullifiers(const DirectSpendContext& context,
                                                             size_t expected_input_count,
                                                             std::string& reject_reason)
{
    if (!context.native_proof) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }
    return ExtractBoundNullifiers(*context.native_proof, expected_input_count, reject_reason);
}

std::optional<std::vector<Nullifier>> ExtractBoundNullifiers(const V2SendContext& context,
                                                             size_t expected_input_count,
                                                             size_t expected_output_count,
                                                             std::string& reject_reason,
                                                             bool reject_rice_codec)
{
    if (context.witness.use_smile) {
        smile2::SmileCTProof proof;
        auto parse_err = smile2::ParseSmile2Proof(context.witness.smile_proof_bytes,
                                                  expected_input_count,
                                                  expected_output_count,
                                                  proof,
                                                  reject_rice_codec);
        if (parse_err.has_value()) {
            reject_reason = *parse_err;
            return std::nullopt;
        }

        std::vector<smile2::SmilePoly> serial_numbers;
        auto extract_err = smile2::ExtractSmile2SerialNumbers(proof, serial_numbers);
        if (extract_err.has_value()) {
            reject_reason = *extract_err;
            return std::nullopt;
        }
        if (serial_numbers.size() != expected_input_count) {
            reject_reason = "bad-smile2-proof-serial-count";
            return std::nullopt;
        }

        std::vector<Nullifier> out;
        out.reserve(serial_numbers.size());
        for (const auto& serial : serial_numbers) {
            const Nullifier nf = smile2::ComputeSmileSerialHash(serial);
            if (nf.IsNull()) {
                reject_reason = "bad-smile2-proof-nullifier";
                return std::nullopt;
            }
            out.push_back(nf);
        }
        return out;
    }
    return ExtractBoundNullifiers(context.witness.native_proof, expected_input_count, reject_reason);
}

std::optional<std::vector<std::vector<uint256>>> BuildLegacyDirectSpendRingMembers(
    const CShieldedBundle& bundle,
    const shielded::ShieldedMerkleTree& tree,
    std::string& reject_reason)
{
    std::vector<std::vector<uint256>> ring_members;
    ring_members.reserve(bundle.shielded_inputs.size());
    std::unordered_map<uint64_t, uint256> commitment_cache;
    commitment_cache.reserve(bundle.shielded_inputs.size() *
                             static_cast<size_t>(shielded::lattice::MAX_RING_SIZE));
    for (const CShieldedInput& spend : bundle.shielded_inputs) {
        if (!shielded::lattice::IsSupportedRingSize(spend.ring_positions.size())) {
            reject_reason = "bad-shielded-ring-positions";
            return std::nullopt;
        }

        const size_t required_unique_members = static_cast<size_t>(
            std::min<uint64_t>(tree.Size(), static_cast<uint64_t>(spend.ring_positions.size())));
        std::set<uint64_t> unique_positions;

        std::vector<uint256> ring;
        ring.reserve(spend.ring_positions.size());
        for (const uint64_t pos : spend.ring_positions) {
            unique_positions.insert(pos);
            auto cache_it = commitment_cache.find(pos);
            if (cache_it == commitment_cache.end()) {
                auto commitment = tree.CommitmentAt(pos);
                if (!commitment.has_value()) {
                    reject_reason = "bad-shielded-ring-member-position";
                    return std::nullopt;
                }
                cache_it = commitment_cache.emplace(pos, *commitment).first;
            }
            ring.push_back(cache_it->second);
        }

        if (unique_positions.size() < required_unique_members) {
            reject_reason = "bad-shielded-ring-member-insufficient-diversity";
            return std::nullopt;
        }
        ring_members.push_back(std::move(ring));
    }
    return ring_members;
}

std::optional<std::vector<std::vector<uint256>>> BuildV2SendRingMembers(
    const shielded::v2::TransactionBundle& bundle,
    const V2SendContext& context,
    const shielded::ShieldedMerkleTree& tree,
    std::string& reject_reason)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_SEND) ||
        !std::holds_alternative<SendPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }

    const auto& payload = std::get<SendPayload>(bundle.payload);
    if (!context.IsValid(payload.spends.size(), payload.outputs.size())) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }

    std::vector<std::vector<uint256>> ring_members;
    ring_members.reserve(payload.spends.size());
    std::unordered_map<uint64_t, uint256> commitment_cache;
    commitment_cache.reserve(payload.spends.size() *
                             static_cast<size_t>(shielded::lattice::MAX_RING_SIZE));

    for (size_t spend_index = 0; spend_index < payload.spends.size(); ++spend_index) {
        const auto& spend = payload.spends[spend_index];
        const auto& witness_spend = context.witness.spends[spend_index];
        if (!witness_spend.IsValid()) {
            reject_reason = "bad-shielded-ring-positions";
            return std::nullopt;
        }

        const size_t required_unique_members = static_cast<size_t>(
            std::min<uint64_t>(tree.Size(), static_cast<uint64_t>(witness_spend.ring_positions.size())));
        std::set<uint64_t> unique_positions;

        std::vector<uint256> ring;
        ring.reserve(witness_spend.ring_positions.size());
        for (const uint64_t pos : witness_spend.ring_positions) {
            unique_positions.insert(pos);
            auto cache_it = commitment_cache.find(pos);
            if (cache_it == commitment_cache.end()) {
                auto commitment = tree.CommitmentAt(pos);
                if (!commitment.has_value()) {
                    LogPrintf("BuildV2SendRingMembers failed: missing commitment at pos=%u tree_size=%u has_index=%d spend_index=%u family=%u\n",
                              static_cast<unsigned int>(pos),
                              static_cast<unsigned int>(tree.Size()),
                              tree.HasCommitmentIndex() ? 1 : 0,
                              static_cast<unsigned int>(spend_index),
                              static_cast<unsigned int>(GetBundleSemanticFamily(bundle)));
                    reject_reason = "bad-shielded-ring-member-position";
                    return std::nullopt;
                }
                cache_it = commitment_cache.emplace(pos, *commitment).first;
            }
            ring.push_back(cache_it->second);
        }

        if (unique_positions.size() < required_unique_members) {
            reject_reason = "bad-shielded-ring-member-insufficient-diversity";
            return std::nullopt;
        }
        if (!spend.note_commitment.IsNull()) {
            reject_reason = "bad-shielded-proof";
            return std::nullopt;
        }

        ring_members.push_back(std::move(ring));
    }

    return ring_members;
}

std::optional<std::vector<std::vector<smile2::wallet::SmileRingMember>>> BuildV2SendSmileRingMembers(
    const shielded::v2::TransactionBundle& bundle,
    const V2SendContext& context,
    const shielded::ShieldedMerkleTree& tree,
    const std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
    const std::map<uint256, uint256>& account_leaf_commitments,
    std::string& reject_reason)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_SEND) ||
        !std::holds_alternative<SendPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }

    const auto& payload = std::get<SendPayload>(bundle.payload);
    if (!context.IsValid(payload.spends.size(), payload.outputs.size()) || !context.witness.use_smile) {
        reject_reason = "bad-shielded-proof";
        return std::nullopt;
    }

    std::vector<std::vector<smile2::wallet::SmileRingMember>> ring_members;
    ring_members.reserve(payload.spends.size());
    std::unordered_map<uint64_t, uint256> commitment_cache;
    commitment_cache.reserve(payload.spends.size() *
                             static_cast<size_t>(shielded::lattice::MAX_RING_SIZE));

    for (size_t spend_index = 0; spend_index < payload.spends.size(); ++spend_index) {
        const auto& witness_spend = context.witness.spends[spend_index];
        if (!witness_spend.IsValid()) {
            reject_reason = "bad-shielded-ring-positions";
            return std::nullopt;
        }

        std::vector<smile2::wallet::SmileRingMember> ring;
        ring.reserve(witness_spend.ring_positions.size());
        for (const uint64_t pos : witness_spend.ring_positions) {
            auto cache_it = commitment_cache.find(pos);
            if (cache_it == commitment_cache.end()) {
                auto commitment = tree.CommitmentAt(pos);
                if (!commitment.has_value()) {
                    reject_reason = "bad-shielded-ring-member-position";
                    return std::nullopt;
                }
                cache_it = commitment_cache.emplace(pos, *commitment).first;
            }

            const auto account_it = public_accounts.find(cache_it->second);
            const auto leaf_it = account_leaf_commitments.find(cache_it->second);
            if (account_it == public_accounts.end()) {
                reject_reason = "bad-smile2-ring-member-public-account";
                return std::nullopt;
            }
            if (leaf_it == account_leaf_commitments.end()) {
                reject_reason = "bad-smile2-ring-member-account-leaf";
                return std::nullopt;
            }

            auto member = smile2::wallet::BuildRingMemberFromCompactPublicAccount(
                smile2::wallet::SMILE_GLOBAL_SEED,
                cache_it->second,
                account_it->second,
                leaf_it->second);
            if (!member.has_value()) {
                reject_reason = "bad-smile2-ring-member-account-leaf";
                return std::nullopt;
            }
            ring.push_back(std::move(*member));
        }

        ring_members.push_back(std::move(ring));
    }

    if (!ring_members.empty()) {
        const auto& reference_positions = context.witness.spends.front().ring_positions;
        const auto& reference_ring = ring_members.front();
        for (size_t spend_index = 1; spend_index < ring_members.size(); ++spend_index) {
            if (context.witness.spends[spend_index].ring_positions != reference_positions ||
                ring_members[spend_index].size() != reference_ring.size()) {
                reject_reason = "bad-smile2-shared-ring";
                return std::nullopt;
            }
            for (size_t i = 0; i < reference_ring.size(); ++i) {
                if (ring_members[spend_index][i].note_commitment != reference_ring[i].note_commitment ||
                    ring_members[spend_index][i].account_leaf_commitment !=
                        reference_ring[i].account_leaf_commitment) {
                    reject_reason = "bad-smile2-shared-ring";
                    return std::nullopt;
                }
            }
        }
    }

    return ring_members;
}

bool VerifyLegacyDirectSpendProof(const DirectSpendContext& context,
                                  const std::vector<std::vector<uint256>>& ring_members,
                                  const std::vector<Nullifier>& input_nullifiers,
                                  const std::vector<uint256>& output_note_commitments,
                                  CAmount value_balance)
{
    if (!context.native_proof ||
        context.material.statement.domain != VerificationDomain::DIRECT_SPEND ||
        context.material.statement.envelope.proof_kind != ProofKind::DIRECT_MATRICT) {
        return false;
    }

    return shielded::ringct::VerifyMatRiCTProof(*context.native_proof,
                                                ring_members,
                                                input_nullifiers,
                                                output_note_commitments,
                                                value_balance,
                                                context.material.statement.envelope.statement_digest);
}

bool VerifyV2SendProof(const shielded::v2::TransactionBundle& bundle,
                       const V2SendContext& context,
                       const std::vector<std::vector<uint256>>& ring_members)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_SEND) ||
        !std::holds_alternative<SendPayload>(bundle.payload)) {
        LogPrintf("VerifyV2SendProof rejected invalid bundle family=%u wire_family=%u\n",
                  static_cast<unsigned int>(GetBundleSemanticFamily(bundle)),
                  static_cast<unsigned int>(bundle.header.family_id));
        return false;
    }

    const auto& payload = std::get<SendPayload>(bundle.payload);
    if (!context.IsValid(payload.spends.size(), payload.outputs.size())) {
        LogPrintf("VerifyV2SendProof invalid context spends=%u outputs=%u witness_spends=%u\n",
                  static_cast<unsigned int>(payload.spends.size()),
                  static_cast<unsigned int>(payload.outputs.size()),
                  static_cast<unsigned int>(context.witness.spends.size()));
        return false;
    }

    const ProofKind proof_kind = context.material.statement.envelope.proof_kind;

    if (proof_kind == ProofKind::NONE) {
        return payload.spends.empty() && ring_members.empty();
    }

    if (IsDirectSmileLikeProofKind(proof_kind)) {
        return false;
    }

    // ----- MatRiCT verification path (legacy) -----
    std::vector<Nullifier> input_nullifiers;
    input_nullifiers.reserve(payload.spends.size());
    for (size_t i = 0; i < payload.spends.size(); ++i) {
        const auto& spend = payload.spends[i];
        if (!spend.value_commitment.IsNull() &&
            CommitmentHash(context.witness.native_proof.input_commitments[i]) != spend.value_commitment) {
            LogPrintf("VerifyV2SendProof input commitment mismatch spend=%u expected=%s actual=%s statement=%s\n",
                      static_cast<unsigned int>(i),
                      spend.value_commitment.ToString(),
                      CommitmentHash(context.witness.native_proof.input_commitments[i]).ToString(),
                      context.material.statement.envelope.statement_digest.ToString());
            return false;
        }
        input_nullifiers.push_back(spend.nullifier);
    }

    std::vector<uint256> output_note_commitments;
    output_note_commitments.reserve(payload.outputs.size());
    for (size_t i = 0; i < payload.outputs.size(); ++i) {
        const auto& output = payload.outputs[i];
        if (CommitmentHash(context.witness.native_proof.output_commitments[i]) != output.value_commitment) {
            LogPrintf("VerifyV2SendProof output commitment mismatch output=%u expected=%s actual=%s statement=%s\n",
                      static_cast<unsigned int>(i),
                      output.value_commitment.ToString(),
                      CommitmentHash(context.witness.native_proof.output_commitments[i]).ToString(),
                      context.material.statement.envelope.statement_digest.ToString());
            return false;
        }
        output_note_commitments.push_back(output.note_commitment);
    }

    const bool verified = shielded::ringct::VerifyMatRiCTProof(context.witness.native_proof,
                                                               ring_members,
                                                               input_nullifiers,
                                                               output_note_commitments,
                                                               payload.value_balance,
                                                               context.material.statement.envelope.statement_digest);
    if (!verified) {
        LogPrintf("VerifyV2SendProof MatRiCT verification failed statement=%s fee=%lld inputs=%u outputs=%u rings=%u ring_hash=%s\n",
                  context.material.statement.envelope.statement_digest.ToString(),
                  static_cast<long long>(payload.fee),
                  static_cast<unsigned int>(input_nullifiers.size()),
                  static_cast<unsigned int>(output_note_commitments.size()),
                  static_cast<unsigned int>(ring_members.size()),
                  HashRingMembers(ring_members).ToString());
    }
    return verified;
}

bool VerifyV2SendProof(
    const shielded::v2::TransactionBundle& bundle,
    const V2SendContext& context,
    const std::vector<std::vector<smile2::wallet::SmileRingMember>>& ring_members,
    bool reject_rice_codec,
    bool bind_anonset_context)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_SEND) ||
        !std::holds_alternative<SendPayload>(bundle.payload)) {
        return false;
    }

    const auto& payload = std::get<SendPayload>(bundle.payload);
    if (!context.IsValid(payload.spends.size(), payload.outputs.size()) ||
        !IsDirectSmileLikeProofKind(context.material.statement.envelope.proof_kind) ||
        !context.witness.use_smile ||
        ring_members.size() != payload.spends.size()) {
        return false;
    }

    std::string reject_reason;
    auto bound_nullifiers = ExtractBoundNullifiers(context,
                                                   payload.spends.size(),
                                                   payload.outputs.size(),
                                                   reject_reason,
                                                   reject_rice_codec);
    if (!bound_nullifiers.has_value()) {
        return false;
    }
    for (size_t i = 0; i < payload.spends.size(); ++i) {
        if ((*bound_nullifiers)[i] != payload.spends[i].nullifier) {
            return false;
        }
    }

    const auto output_coins = CollectSmileOutputCoins(context.witness, payload.outputs.size());
    if (!output_coins.has_value()) {
        return false;
    }
    if (!ReconstructSmileOutputAccounts(payload, *output_coins).has_value()) {
        return false;
    }

    if (ring_members.empty() || ring_members.front().empty()) {
        return false;
    }

    const auto& reference_ring = ring_members.front();
    std::vector<smile2::BDLOPCommitment> shared_coin_ring;
    shared_coin_ring.reserve(reference_ring.size());
    for (const auto& member : reference_ring) {
        if (!member.IsValid()) return false;
        shared_coin_ring.push_back(member.public_coin);
    }
    for (size_t spend_index = 1; spend_index < ring_members.size(); ++spend_index) {
        if (ring_members[spend_index].size() != reference_ring.size()) {
            return false;
        }
        for (size_t i = 0; i < reference_ring.size(); ++i) {
            const auto& lhs = ring_members[spend_index][i];
            const auto& rhs = reference_ring[i];
            if (lhs.note_commitment != rhs.note_commitment ||
                lhs.account_leaf_commitment != rhs.account_leaf_commitment ||
                lhs.public_key.pk != rhs.public_key.pk ||
                lhs.public_key.A != rhs.public_key.A ||
                lhs.public_coin.t0 != rhs.public_coin.t0 ||
                lhs.public_coin.t_msg != rhs.public_coin.t_msg) {
                return false;
            }
        }
    }
    for (size_t i = 0; i < payload.spends.size(); ++i) {
        const uint256 expected_input_binding =
            smile2::ComputeSmileDirectInputBindingHash(
                Span<const smile2::wallet::SmileRingMember>{reference_ring.data(), reference_ring.size()},
                payload.spends[i].merkle_anchor,
                static_cast<uint32_t>(i),
                payload.spends[i].nullifier);
        if (!payload.spends[i].value_commitment.IsNull() &&
            payload.spends[i].value_commitment != expected_input_binding) {
            return false;
        }
    }

    smile2::CTPublicData pub;
    pub.anon_set = smile2::wallet::BuildAnonymitySet(
        Span<const smile2::wallet::SmileRingMember>{reference_ring.data(), reference_ring.size()});
    pub.coin_rings.assign(payload.spends.size(), shared_coin_ring);
    pub.account_rings.reserve(payload.spends.size());
    for (const auto& spend : payload.spends) {
        std::vector<smile2::CTPublicAccount> account_ring;
        account_ring.reserve(reference_ring.size());
        for (const auto& member : reference_ring) {
            account_ring.push_back(smile2::CTPublicAccount{
                member.note_commitment,
                member.public_key,
                member.public_coin,
                spend.account_leaf_commitment,
            });
        }
        pub.account_rings.push_back(std::move(account_ring));
    }

    return !smile2::VerifySmile2CTFromBytes(context.witness.smile_proof_bytes,
                                            payload.spends.size(),
                                            payload.outputs.size(),
                                            *output_coins,
                                            pub,
                                            payload.value_balance,
                                            reject_rice_codec,
                                            bind_anonset_context)
                .has_value();
}

bool VerifySettlementContext(const SettlementContext& context,
                             const SettlementWitness& witness,
                             std::string& reject_reason)
{
    if (!context.IsValid()) {
        reject_reason = "bad-v2-settlement-context";
        return false;
    }
    if (!witness.IsValid()) {
        reject_reason = "bad-v2-settlement-witness";
        return false;
    }

    const uint256 statement_hash = ComputeBridgeBatchStatementHash(witness.statement);
    if (statement_hash.IsNull()) {
        reject_reason = "bad-v2-settlement-statement";
        return false;
    }

    if (context.imported_claim.has_value()) {
        if (!witness.signed_receipts.empty() ||
            !witness.signed_receipt_proofs.empty() ||
            !witness.proof_receipts.empty() ||
            witness.descriptor_proof.has_value()) {
            reject_reason = "bad-v2-settlement-claim-witness";
            return false;
        }
        if (context.imported_claim->statement_hash != statement_hash ||
            !DoesBridgeProofClaimMatchStatement(*context.imported_claim, witness.statement)) {
            reject_reason = "bad-v2-settlement-claim";
            return false;
        }
        if (!std::all_of(witness.imported_adapters.begin(),
                         witness.imported_adapters.end(),
                         [&](const BridgeProofAdapter& adapter) {
                             return AdapterMatchesClaim(witness.statement, adapter, *context.imported_claim);
                         })) {
            reject_reason = "bad-v2-settlement-claim-adapter";
            return false;
        }
        return true;
    }

    if (!witness.statement.proof_policy.IsValid()) {
        reject_reason = "bad-v2-settlement-proof-policy";
        return false;
    }
    if (!context.imported_receipt.has_value() || !context.descriptor.has_value()) {
        reject_reason = "bad-v2-settlement-receipt-context";
        return false;
    }
    if (context.imported_receipt->statement_hash != statement_hash ||
        !DescriptorMatchesReceipt(*context.descriptor, *context.imported_receipt)) {
        reject_reason = "bad-v2-settlement-receipt";
        return false;
    }
    if (!std::all_of(witness.imported_adapters.begin(),
                     witness.imported_adapters.end(),
                     [&](const BridgeProofAdapter& adapter) {
                         return AdapterMatchesReceipt(witness.statement, adapter, *context.imported_receipt);
                     })) {
        reject_reason = "bad-v2-settlement-receipt-adapter";
        return false;
    }
    if (!witness.descriptor_proof.has_value() ||
        !VerifyBridgeProofPolicyProof(witness.statement.proof_policy,
                                      *context.descriptor,
                                      *witness.descriptor_proof)) {
        reject_reason = "bad-v2-settlement-proof-descriptor";
        return false;
    }
    if (!VerifyProofReceiptSet(witness.statement,
                               *context.descriptor,
                               witness.proof_receipts,
                               *context.imported_receipt,
                               reject_reason)) {
        return false;
    }

    if (context.verification_bundle.has_value()) {
        if (!witness.statement.verifier_set.IsValid()) {
            reject_reason = "bad-v2-settlement-verifier-set";
            return false;
        }
        if (witness.signed_receipts.size() <
            static_cast<size_t>(witness.statement.verifier_set.required_signers)) {
            reject_reason = "bad-v2-settlement-signed-threshold";
            return false;
        }
        if (!HasSignedReceiptMembershipProofs(witness.statement,
                                              witness.signed_receipts,
                                              witness.signed_receipt_proofs)) {
            reject_reason = "bad-v2-settlement-signed-membership";
            return false;
        }

        const auto anchor = BuildBridgeExternalAnchorFromHybridWitness(witness.statement,
                                                                       witness.signed_receipts,
                                                                       witness.proof_receipts);
        if (!anchor.has_value()) {
            reject_reason = "bad-v2-settlement-hybrid-anchor";
            return false;
        }

        const uint256 signed_root = ComputeBridgeBatchReceiptRoot(witness.signed_receipts);
        const uint256 proof_root = ComputeBridgeProofReceiptRoot(witness.proof_receipts);
        if (signed_root.IsNull() ||
            proof_root.IsNull() ||
            signed_root != context.verification_bundle->signed_receipt_root ||
            proof_root != context.verification_bundle->proof_receipt_root ||
            anchor->verification_root != ComputeBridgeVerificationBundleHash(*context.verification_bundle)) {
            reject_reason = "bad-v2-settlement-verification-bundle";
            return false;
        }
        return true;
    }

    if (witness.statement.verifier_set.IsValid() ||
        !witness.signed_receipts.empty() ||
        !witness.signed_receipt_proofs.empty()) {
        reject_reason = "bad-v2-settlement-missing-bundle";
        return false;
    }

    const auto anchor = BuildBridgeExternalAnchorFromProofReceipts(witness.statement, witness.proof_receipts);
    if (!anchor.has_value()) {
        reject_reason = "bad-v2-settlement-proof-anchor";
        return false;
    }
    return true;
}

PayloadLocation ToPayloadLocation(BridgeAggregatePayloadLocation location)
{
    switch (location) {
    case BridgeAggregatePayloadLocation::INLINE_NON_WITNESS:
        return PayloadLocation::INLINE_NON_WITNESS;
    case BridgeAggregatePayloadLocation::INLINE_WITNESS:
        return PayloadLocation::INLINE_WITNESS;
    case BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY:
        return PayloadLocation::L1_DATA_AVAILABILITY;
    case BridgeAggregatePayloadLocation::OFFCHAIN:
        return PayloadLocation::OFFCHAIN;
    }
    return PayloadLocation::INLINE_WITNESS;
}

BridgeAggregatePayloadLocation ToBridgePayloadLocation(PayloadLocation location)
{
    switch (location) {
    case PayloadLocation::INLINE_NON_WITNESS:
        return BridgeAggregatePayloadLocation::INLINE_NON_WITNESS;
    case PayloadLocation::INLINE_WITNESS:
        return BridgeAggregatePayloadLocation::INLINE_WITNESS;
    case PayloadLocation::L1_DATA_AVAILABILITY:
        return BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY;
    case PayloadLocation::OFFCHAIN:
        return BridgeAggregatePayloadLocation::OFFCHAIN;
    }
    return BridgeAggregatePayloadLocation::INLINE_WITNESS;
}

SettlementContext DescribeImportedSettlementReceipt(const BridgeProofReceipt& receipt,
                                                    PayloadLocation payload_location,
                                                    const std::vector<uint8_t>& proof_payload,
                                                    std::optional<BridgeProofDescriptor> descriptor,
                                                    std::optional<BridgeVerificationBundle> verification_bundle)
{
    SettlementContext context;
    context.material.statement.domain = VerificationDomain::BATCH_SETTLEMENT;
    context.material.statement.envelope = MakeEnvelope(ProofKind::IMPORTED_RECEIPT,
                                                       ProofComponentKind::NONE,
                                                       ProofComponentKind::NONE,
                                                       ProofComponentKind::NONE,
                                                       SettlementBindingKind::BRIDGE_RECEIPT,
                                                       receipt.statement_hash);
    context.material.payload_location = payload_location;
    context.material.proof_payload = proof_payload;
    context.material.proof_shards.push_back(
        BuildReceiptProofShard(receipt, static_cast<uint32_t>(proof_payload.size())));
    context.imported_receipt = receipt;
    if (!descriptor.has_value()) {
        descriptor = BridgeProofDescriptor{receipt.proof_system_id, receipt.verifier_key_hash};
    }
    context.descriptor = std::move(descriptor);
    context.verification_bundle = std::move(verification_bundle);
    return context;
}

SettlementContext DescribeImportedSettlementReceipt(const BridgeProofReceipt& receipt,
                                                    PayloadLocation payload_location,
                                                    const std::vector<uint8_t>& proof_payload,
                                                    const Consensus::Params& consensus,
                                                    int32_t validation_height,
                                                    std::optional<BridgeProofDescriptor> descriptor,
                                                    std::optional<BridgeVerificationBundle> verification_bundle)
{
    auto context = DescribeImportedSettlementReceipt(receipt,
                                                     payload_location,
                                                     proof_payload,
                                                     std::move(descriptor),
                                                     std::move(verification_bundle));
    context.material.statement.envelope.proof_kind =
        GetWireProofKindForValidationHeight(TransactionFamily::V2_EGRESS_BATCH,
                                            context.material.statement.envelope.proof_kind,
                                            &consensus,
                                            validation_height);
    context.material.statement.envelope.membership_proof_kind =
        GetWireProofComponentKindForValidationHeight(context.material.statement.envelope.membership_proof_kind,
                                                     &consensus,
                                                     validation_height);
    context.material.statement.envelope.amount_proof_kind =
        GetWireProofComponentKindForValidationHeight(context.material.statement.envelope.amount_proof_kind,
                                                     &consensus,
                                                     validation_height);
    context.material.statement.envelope.balance_proof_kind =
        GetWireProofComponentKindForValidationHeight(context.material.statement.envelope.balance_proof_kind,
                                                     &consensus,
                                                     validation_height);
    context.material.statement.envelope.settlement_binding_kind =
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_EGRESS_BATCH,
                                                        context.material.statement.envelope.settlement_binding_kind,
                                                        &consensus,
                                                        validation_height);
    return context;
}

SettlementContext DescribeImportedSettlementClaim(const BridgeProofClaim& claim,
                                                  PayloadLocation payload_location,
                                                  const std::vector<uint8_t>& proof_payload)
{
    SettlementContext context;
    context.material.statement.domain = VerificationDomain::BATCH_SETTLEMENT;
    context.material.statement.envelope = MakeEnvelope(ProofKind::IMPORTED_CLAIM,
                                                       ProofComponentKind::NONE,
                                                       ProofComponentKind::NONE,
                                                       ProofComponentKind::NONE,
                                                       SettlementBindingKind::BRIDGE_CLAIM,
                                                       claim.statement_hash);
    context.material.payload_location = payload_location;
    context.material.proof_payload = proof_payload;
    context.material.proof_shards.push_back(
        BuildClaimProofShard(claim, static_cast<uint32_t>(proof_payload.size())));
    context.imported_claim = claim;
    return context;
}

SettlementContext DescribeImportedSettlementClaim(const BridgeProofClaim& claim,
                                                  PayloadLocation payload_location,
                                                  const std::vector<uint8_t>& proof_payload,
                                                  const Consensus::Params& consensus,
                                                  int32_t validation_height)
{
    auto context = DescribeImportedSettlementClaim(claim, payload_location, proof_payload);
    context.material.statement.envelope.proof_kind =
        GetWireProofKindForValidationHeight(TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                            context.material.statement.envelope.proof_kind,
                                            &consensus,
                                            validation_height);
    context.material.statement.envelope.membership_proof_kind =
        GetWireProofComponentKindForValidationHeight(context.material.statement.envelope.membership_proof_kind,
                                                     &consensus,
                                                     validation_height);
    context.material.statement.envelope.amount_proof_kind =
        GetWireProofComponentKindForValidationHeight(context.material.statement.envelope.amount_proof_kind,
                                                     &consensus,
                                                     validation_height);
    context.material.statement.envelope.balance_proof_kind =
        GetWireProofComponentKindForValidationHeight(context.material.statement.envelope.balance_proof_kind,
                                                     &consensus,
                                                     validation_height);
    context.material.statement.envelope.settlement_binding_kind =
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_SETTLEMENT_ANCHOR,
                                                        context.material.statement.envelope.settlement_binding_kind,
                                                        &consensus,
                                                        validation_height);
    return context;
}

} // namespace shielded::v2::proof
