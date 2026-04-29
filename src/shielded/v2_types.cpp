// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_types.h>

#include <consensus/amount.h>
#include <hash.h>

#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace shielded::v2 {
namespace {

constexpr std::string_view TAG_NOTE_COMMIT{"BTX_ShieldedV2_Note_Commit_V1"};
constexpr std::string_view TAG_NULLIFIER{"BTX_ShieldedV2_Note_Nullifier_V1"};
constexpr std::string_view TAG_EMPTY_LEAF{"BTX_ShieldedV2_Empty_Leaf_V1"};
constexpr std::string_view TAG_TREE_NODE{"BTX_ShieldedV2_Tree_Node_V1"};
constexpr std::string_view TAG_BATCH_LEAF{"BTX_ShieldedV2_Batch_Leaf_V1"};
constexpr std::string_view TAG_BATCH_NODE{"BTX_ShieldedV2_Batch_Node_V1"};
constexpr std::string_view TAG_PROOF_SHARD{"BTX_ShieldedV2_Proof_Shard_V1"};
constexpr std::string_view TAG_PROOF_SHARD_NODE{"BTX_ShieldedV2_Proof_Shard_Node_V1"};
constexpr std::string_view TAG_OUTPUT_CHUNK{"BTX_ShieldedV2_Output_Chunk_V1"};
constexpr std::string_view TAG_OUTPUT_CHUNK_NODE{"BTX_ShieldedV2_Output_Chunk_Node_V1"};
constexpr std::string_view TAG_NETTING_MANIFEST{"BTX_ShieldedV2_Netting_Manifest_V1"};
constexpr std::string_view TAG_TX_HEADER{"BTX_ShieldedV2_Transaction_Header_V1"};
constexpr std::string_view TAG_LEGACY_EPHEMERAL_KEY{"BTX_ShieldedV2_Legacy_Ephemeral_V2"};

[[nodiscard]] uint256 HashTaggedString(std::string_view tag)
{
    HashWriter hw;
    hw << std::string{tag};
    return hw.GetSHA256();
}

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

template <typename T>
[[nodiscard]] uint256 ComputeOrderedRoot(Span<const T> objects,
                                         std::string_view leaf_tag,
                                         std::string_view node_tag,
                                         uint256 (*leaf_hasher)(const T&))
{
    if (objects.empty()) {
        return uint256::ZERO;
    }

    std::vector<uint256> level;
    level.reserve(objects.size());
    for (const T& obj : objects) {
        level.push_back(leaf_hasher(obj));
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

    if (level.front().IsNull()) {
        return HashTaggedString(leaf_tag);
    }
    return level.front();
}

} // namespace

uint256 ComputeLegacyPayloadEphemeralKey(Span<const uint8_t> ciphertext)
{
    if (ciphertext.empty()) {
        return uint256::ZERO;
    }

    HashWriter hw;
    hw << std::string{TAG_LEGACY_EPHEMERAL_KEY};
    hw.write(AsBytes(ciphertext));
    return hw.GetSHA256();
}

bool IsValidTransactionFamily(TransactionFamily family)
{
    switch (family) {
    case TransactionFamily::V2_SEND:
    case TransactionFamily::V2_INGRESS_BATCH:
    case TransactionFamily::V2_EGRESS_BATCH:
    case TransactionFamily::V2_REBALANCE:
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case TransactionFamily::V2_GENERIC:
    case TransactionFamily::V2_LIFECYCLE:
    case TransactionFamily::V2_SPEND_PATH_RECOVERY:
        return true;
    }
    return false;
}

bool IsValidNoteClass(NoteClass note_class)
{
    switch (note_class) {
    case NoteClass::USER:
    case NoteClass::RESERVE:
    case NoteClass::OPERATOR:
    case NoteClass::SETTLEMENT:
        return true;
    }
    return false;
}

bool IsValidScanDomain(ScanDomain domain)
{
    switch (domain) {
    case ScanDomain::OPAQUE:
    case ScanDomain::USER:
    case ScanDomain::RESERVE:
    case ScanDomain::OPERATOR:
    case ScanDomain::BATCH:
        return true;
    }
    return false;
}

bool IsValidProofKind(ProofKind kind)
{
    switch (kind) {
    case ProofKind::NONE:
    case ProofKind::DIRECT_MATRICT:
    case ProofKind::BATCH_MATRICT:
    case ProofKind::IMPORTED_RECEIPT:
    case ProofKind::IMPORTED_CLAIM:
    case ProofKind::DIRECT_SMILE:
    case ProofKind::BATCH_SMILE:
    case ProofKind::GENERIC_SMILE:
    case ProofKind::GENERIC_BRIDGE:
    case ProofKind::GENERIC_OPAQUE:
        return true;
    }
    return false;
}

bool IsValidProofComponentKind(ProofComponentKind kind)
{
    switch (kind) {
    case ProofComponentKind::NONE:
    case ProofComponentKind::MATRICT:
    case ProofComponentKind::RANGE:
    case ProofComponentKind::BALANCE:
    case ProofComponentKind::RECEIPT:
    case ProofComponentKind::SMILE_MEMBERSHIP:
    case ProofComponentKind::SMILE_BALANCE:
    case ProofComponentKind::GENERIC_OPAQUE:
        return true;
    }
    return false;
}

bool IsValidSettlementBindingKind(SettlementBindingKind kind)
{
    switch (kind) {
    case SettlementBindingKind::NONE:
    case SettlementBindingKind::NATIVE_BATCH:
    case SettlementBindingKind::BRIDGE_RECEIPT:
    case SettlementBindingKind::BRIDGE_CLAIM:
    case SettlementBindingKind::NETTING_MANIFEST:
    case SettlementBindingKind::GENERIC_SHIELDED:
    case SettlementBindingKind::GENERIC_BRIDGE:
    case SettlementBindingKind::GENERIC_POSTFORK:
        return true;
    }
    return false;
}

const char* GetTransactionFamilyName(TransactionFamily family)
{
    switch (family) {
    case TransactionFamily::V2_SEND:
        return "v2_send";
    case TransactionFamily::V2_INGRESS_BATCH:
        return "v2_ingress_batch";
    case TransactionFamily::V2_EGRESS_BATCH:
        return "v2_egress_batch";
    case TransactionFamily::V2_REBALANCE:
        return "v2_rebalance";
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
        return "v2_settlement_anchor";
    case TransactionFamily::V2_GENERIC:
        return "shielded_v2";
    case TransactionFamily::V2_LIFECYCLE:
        return "v2_lifecycle";
    case TransactionFamily::V2_SPEND_PATH_RECOVERY:
        return "v2_spend_path_recovery";
    }
    return "unknown";
}

const char* GetNoteClassName(NoteClass note_class)
{
    switch (note_class) {
    case NoteClass::USER:
        return "user";
    case NoteClass::RESERVE:
        return "reserve";
    case NoteClass::OPERATOR:
        return "operator";
    case NoteClass::SETTLEMENT:
        return "settlement";
    }
    return "unknown";
}

const char* GetScanDomainName(ScanDomain domain)
{
    switch (domain) {
    case ScanDomain::OPAQUE:
        return "opaque";
    case ScanDomain::USER:
        return "user";
    case ScanDomain::RESERVE:
        return "reserve";
    case ScanDomain::OPERATOR:
        return "operator";
    case ScanDomain::BATCH:
        return "batch";
    }
    return "unknown";
}

const char* GetProofKindName(ProofKind kind)
{
    switch (kind) {
    case ProofKind::NONE:
        return "none";
    case ProofKind::DIRECT_MATRICT:
        return "direct_matrict";
    case ProofKind::BATCH_MATRICT:
        return "batch_matrict";
    case ProofKind::IMPORTED_RECEIPT:
        return "imported_receipt";
    case ProofKind::IMPORTED_CLAIM:
        return "imported_claim";
    case ProofKind::DIRECT_SMILE:
        return "direct_smile";
    case ProofKind::BATCH_SMILE:
        return "batch_smile";
    case ProofKind::GENERIC_SMILE:
        return "generic_smile";
    case ProofKind::GENERIC_BRIDGE:
        return "generic_bridge";
    case ProofKind::GENERIC_OPAQUE:
        return "generic_opaque";
    }
    return "unknown";
}

const char* GetProofComponentKindName(ProofComponentKind kind)
{
    switch (kind) {
    case ProofComponentKind::NONE:
        return "none";
    case ProofComponentKind::MATRICT:
        return "matrict";
    case ProofComponentKind::RANGE:
        return "range";
    case ProofComponentKind::BALANCE:
        return "balance";
    case ProofComponentKind::RECEIPT:
        return "receipt";
    case ProofComponentKind::SMILE_MEMBERSHIP:
        return "smile_membership";
    case ProofComponentKind::SMILE_BALANCE:
        return "smile_balance";
    case ProofComponentKind::GENERIC_OPAQUE:
        return "generic_opaque";
    }
    return "unknown";
}

const char* GetSettlementBindingKindName(SettlementBindingKind kind)
{
    switch (kind) {
    case SettlementBindingKind::NONE:
        return "none";
    case SettlementBindingKind::NATIVE_BATCH:
        return "native_batch";
    case SettlementBindingKind::BRIDGE_RECEIPT:
        return "bridge_receipt";
    case SettlementBindingKind::BRIDGE_CLAIM:
        return "bridge_claim";
    case SettlementBindingKind::NETTING_MANIFEST:
        return "netting_manifest";
    case SettlementBindingKind::GENERIC_SHIELDED:
        return "generic_shielded";
    case SettlementBindingKind::GENERIC_BRIDGE:
        return "generic_bridge";
    case SettlementBindingKind::GENERIC_POSTFORK:
        return "generic_postfork";
    }
    return "unknown";
}

bool EncryptedNotePayload::IsValid() const
{
    return version == WIRE_VERSION &&
           scan_hint_version == SCAN_HINT_VERSION &&
           IsValidScanDomain(scan_domain) &&
           !ciphertext.empty() &&
           ciphertext.size() <= MAX_NOTE_CIPHERTEXT_BYTES &&
           !ComputeLegacyPayloadEphemeralKey(ciphertext).IsNull();
}

bool Note::IsValid() const
{
    return version == WIRE_VERSION &&
           IsValidNoteClass(note_class) &&
           MoneyRange(value) &&
           value > 0 &&
           !owner_commitment.IsNull() &&
           !rho.IsNull() &&
           !rseed.IsNull() &&
           memo.size() <= MAX_NOTE_MEMO_BYTES;
}

bool ProofEnvelope::IsValid() const
{
    if (version != WIRE_VERSION ||
        !IsValidProofKind(proof_kind) ||
        !IsValidProofComponentKind(membership_proof_kind) ||
        !IsValidProofComponentKind(amount_proof_kind) ||
        !IsValidProofComponentKind(balance_proof_kind) ||
        !IsValidSettlementBindingKind(settlement_binding_kind)) {
        return false;
    }

    if (proof_kind == ProofKind::NONE) {
        return membership_proof_kind == ProofComponentKind::NONE &&
               amount_proof_kind == ProofComponentKind::NONE &&
               balance_proof_kind == ProofComponentKind::NONE &&
               statement_digest.IsNull();
    }

    return !statement_digest.IsNull();
}

bool BatchLeaf::IsValid() const
{
    const bool batch_family = family_id == TransactionFamily::V2_INGRESS_BATCH ||
                              family_id == TransactionFamily::V2_EGRESS_BATCH ||
                              family_id == TransactionFamily::V2_GENERIC;
    return version == WIRE_VERSION &&
           batch_family &&
           !l2_id.IsNull() &&
           !destination_commitment.IsNull() &&
           !amount_commitment.IsNull() &&
           !fee_commitment.IsNull() &&
           !nonce.IsNull() &&
           !settlement_domain.IsNull();
}

bool ProofShardDescriptor::IsValid() const
{
    if (version != WIRE_VERSION ||
        leaf_count == 0 ||
        settlement_domain.IsNull() ||
        leaf_subroot.IsNull() ||
        nullifier_commitment.IsNull() ||
        value_commitment.IsNull() ||
        statement_digest.IsNull() ||
        proof_metadata.empty() ||
        proof_metadata.size() > MAX_PROOF_METADATA_BYTES ||
        proof_payload_size == 0) {
        return false;
    }

    return proof_payload_offset <= std::numeric_limits<uint32_t>::max() - proof_payload_size;
}

bool OutputChunkDescriptor::IsValid() const
{
    return version == WIRE_VERSION &&
           IsValidScanDomain(scan_domain) &&
           output_count > 0 &&
           ciphertext_bytes > 0 &&
           !scan_hint_commitment.IsNull() &&
           !ciphertext_commitment.IsNull();
}

bool NettingManifestEntry::IsValid() const
{
    return !l2_id.IsNull() &&
           net_reserve_delta != 0 &&
           IsAmountDeltaInRange(net_reserve_delta);
}

bool NettingManifest::IsValid() const
{
    if (version != WIRE_VERSION ||
        settlement_window == 0 ||
        domains.empty() ||
        domains.size() > MAX_NETTING_DOMAINS ||
        aggregate_net_delta != 0 ||
        !IsAmountDeltaInRange(aggregate_net_delta) ||
        gross_flow_commitment.IsNull() ||
        !IsValidSettlementBindingKind(binding_kind) ||
        binding_kind == SettlementBindingKind::NONE ||
        authorization_digest.IsNull()) {
        return false;
    }

    CAmount total_delta{0};
    uint256 previous_l2{};
    bool first{true};
    for (const NettingManifestEntry& entry : domains) {
        if (!entry.IsValid()) {
            return false;
        }
        if (!first && !(previous_l2 < entry.l2_id)) {
            return false;
        }
        first = false;
        previous_l2 = entry.l2_id;
        total_delta += entry.net_reserve_delta;
    }

    return total_delta == aggregate_net_delta;
}

bool TransactionHeader::IsValid() const
{
    if (version != WIRE_VERSION ||
        !IsValidTransactionFamily(family_id) ||
        !proof_envelope.IsValid() ||
        payload_digest.IsNull()) {
        return false;
    }

    if ((proof_shard_count == 0) != proof_shard_root.IsNull()) {
        return false;
    }
    if ((output_chunk_count == 0) != output_chunk_root.IsNull()) {
        return false;
    }
    if (netting_manifest_version != 0 && netting_manifest_version != WIRE_VERSION) {
        return false;
    }
    if (netting_manifest_version != 0 &&
        family_id != TransactionFamily::V2_REBALANCE &&
        family_id != TransactionFamily::V2_GENERIC) {
        return false;
    }

    return true;
}

bool IsAmountDeltaInRange(CAmount amount)
{
    return amount >= -MAX_MONEY && amount <= MAX_MONEY;
}

uint256 ComputeNoteCommitment(const Note& note)
{
    HashWriter hw;
    hw << std::string{TAG_NOTE_COMMIT}
       << note.version
       << static_cast<uint8_t>(note.note_class)
       << note.value
       << note.owner_commitment
       << note.rho
       << note.rseed
       << note.source_binding;
    return hw.GetSHA256();
}

uint256 ComputeNullifier(const Note& note, Span<const uint8_t> spending_key)
{
    const uint256 commitment = ComputeNoteCommitment(note);

    HashWriter hw;
    hw << std::string{TAG_NULLIFIER}
       << note.version
       << static_cast<uint8_t>(note.note_class);
    hw.write(AsBytes(spending_key));
    hw << note.rho << commitment;
    return hw.GetSHA256();
}

uint256 ComputeTreeEmptyLeaf()
{
    return HashTaggedString(TAG_EMPTY_LEAF);
}

uint256 ComputeTreeNode(const uint256& left, const uint256& right)
{
    return HashTaggedPair(TAG_TREE_NODE, left, right);
}

uint256 ComputeBatchLeafHash(const BatchLeaf& leaf)
{
    return HashTaggedObject(TAG_BATCH_LEAF, leaf);
}

uint256 ComputeBatchLeafRoot(Span<const BatchLeaf> leaves)
{
    return ComputeOrderedRoot(leaves, TAG_BATCH_LEAF, TAG_BATCH_NODE, ComputeBatchLeafHash);
}

uint256 ComputeProofShardDescriptorHash(const ProofShardDescriptor& descriptor)
{
    return HashTaggedObject(TAG_PROOF_SHARD, descriptor);
}

uint256 ComputeProofShardRoot(Span<const ProofShardDescriptor> descriptors)
{
    return ComputeOrderedRoot(descriptors, TAG_PROOF_SHARD, TAG_PROOF_SHARD_NODE, ComputeProofShardDescriptorHash);
}

uint256 ComputeOutputChunkDescriptorHash(const OutputChunkDescriptor& descriptor)
{
    return HashTaggedObject(TAG_OUTPUT_CHUNK, descriptor);
}

uint256 ComputeOutputChunkRoot(Span<const OutputChunkDescriptor> descriptors)
{
    return ComputeOrderedRoot(descriptors, TAG_OUTPUT_CHUNK, TAG_OUTPUT_CHUNK_NODE, ComputeOutputChunkDescriptorHash);
}

uint256 ComputeNettingManifestId(const NettingManifest& manifest)
{
    return HashTaggedObject(TAG_NETTING_MANIFEST, manifest);
}

uint256 ComputeTransactionHeaderId(const TransactionHeader& header)
{
    return HashTaggedObject(TAG_TX_HEADER, header);
}

} // namespace shielded::v2
