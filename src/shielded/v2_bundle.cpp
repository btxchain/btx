// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_bundle.h>
#include <shielded/v2_proof.h>

#include <consensus/params.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <streams.h>

#include <algorithm>
#include <array>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace shielded::v2 {
namespace {

constexpr std::string_view TAG_SPEND_DESCRIPTION{"BTX_ShieldedV2_Spend_Description_V1"};
constexpr std::string_view TAG_SPEND_ROOT_LEAF{"BTX_ShieldedV2_Spend_Root_Leaf_V1"};
constexpr std::string_view TAG_SPEND_ROOT_NODE{"BTX_ShieldedV2_Spend_Root_Node_V1"};
constexpr std::string_view TAG_OUTPUT_DESCRIPTION{"BTX_ShieldedV2_Output_Description_V1"};
constexpr std::string_view TAG_OUTPUT_ROOT_LEAF{"BTX_ShieldedV2_Output_Root_Leaf_V1"};
constexpr std::string_view TAG_OUTPUT_ROOT_NODE{"BTX_ShieldedV2_Output_Root_Node_V1"};
constexpr std::string_view TAG_RESERVE_DELTA{"BTX_ShieldedV2_Reserve_Delta_V1"};
constexpr std::string_view TAG_RESERVE_DELTA_LEAF{"BTX_ShieldedV2_Reserve_Delta_Leaf_V1"};
constexpr std::string_view TAG_RESERVE_DELTA_NODE{"BTX_ShieldedV2_Reserve_Delta_Node_V1"};
constexpr std::string_view TAG_SEND_PAYLOAD{"BTX_ShieldedV2_Send_Payload_V1"};
constexpr std::string_view TAG_INGRESS_PAYLOAD{"BTX_ShieldedV2_Ingress_Payload_V1"};
constexpr std::string_view TAG_EGRESS_PAYLOAD{"BTX_ShieldedV2_Egress_Payload_V1"};
constexpr std::string_view TAG_REBALANCE_PAYLOAD{"BTX_ShieldedV2_Rebalance_Payload_V1"};
constexpr std::string_view TAG_SETTLEMENT_ANCHOR_PAYLOAD{"BTX_ShieldedV2_Settlement_Anchor_Payload_V1"};
constexpr std::string_view TAG_TRANSACTION_BUNDLE{"BTX_ShieldedV2_Transaction_Bundle_V1"};
constexpr std::string_view TAG_OUTPUT_CHUNK_SCAN_HINT_LEAF{"BTX_ShieldedV2_Output_Chunk_Scan_Hint_Leaf_V1"};
constexpr std::string_view TAG_OUTPUT_CHUNK_SCAN_HINT_NODE{"BTX_ShieldedV2_Output_Chunk_Scan_Hint_Node_V1"};
constexpr std::string_view TAG_OUTPUT_CHUNK_CIPHERTEXT_LEAF{"BTX_ShieldedV2_Output_Chunk_Ciphertext_Leaf_V1"};
constexpr std::string_view TAG_OUTPUT_CHUNK_CIPHERTEXT_NODE{"BTX_ShieldedV2_Output_Chunk_Ciphertext_Node_V1"};
constexpr std::string_view TAG_REBALANCE_STATEMENT_DIGEST{"BTX_ShieldedV2_Rebalance_Statement_Digest_V1"};
constexpr std::string_view TAG_REBALANCE_SHARD_PAYLOAD{"BTX_ShieldedV2_Rebalance_Shard_Payload_V1"};
constexpr std::string_view TAG_REBALANCE_SHARD_LEAF_SUBROOT{"BTX_ShieldedV2_Rebalance_Shard_Leaf_Subroot_V1"};
constexpr std::string_view TAG_REBALANCE_SHARD_NULLIFIER_COMMIT{"BTX_ShieldedV2_Rebalance_Shard_Nullifier_Commit_V1"};
constexpr std::string_view TAG_REBALANCE_SHARD_VALUE_COMMIT{"BTX_ShieldedV2_Rebalance_Shard_Value_Commit_V1"};
constexpr std::string_view TAG_REBALANCE_SHARD_METADATA{"BTX_ShieldedV2_Rebalance_Shard_Metadata_V1"};
constexpr std::string_view TAG_EGRESS_OUTPUT_VALUE_COMMIT{"BTX_ShieldedV2_Egress_Output_Value_V2"};
constexpr std::string_view TAG_REBALANCE_OUTPUT_VALUE_COMMIT{"BTX_ShieldedV2_Rebalance_Output_Value_V2"};
constexpr std::string_view TAG_ADDRESS_LIFECYCLE_CONTROL_SIG{"BTX_ShieldedV2_Address_Lifecycle_Sig_V1"};
constexpr std::string_view TAG_ADDRESS_LIFECYCLE_RECORD_SIG{"BTX_ShieldedV2_Address_Lifecycle_Record_Sig_V1"};
constexpr std::string_view TAG_LIFECYCLE_TRANSPARENT_BINDING{"BTX_ShieldedV2_Lifecycle_Transparent_Binding_V1"};
constexpr std::string_view TAG_LIFECYCLE_PAYLOAD{"BTX_ShieldedV2_Lifecycle_Payload_V1"};
constexpr std::array<uint8_t, 4> GENERIC_OPAQUE_PAYLOAD_WIRE_MAGIC{{'G', 'O', 'P', '1'}};

template <typename T>
[[nodiscard]] bool ObjectsEqualBySerialization(const T& lhs, const T& rhs);
[[nodiscard]] ReserveDelta MakeOpaquePaddingReserveDelta(uint32_t padding_index,
                                                         size_t padding_count);
[[nodiscard]] bool OpaqueReserveDeltasAreValid(Span<const ReserveDelta> deltas);
[[nodiscard]] bool StripCanonicalOpaquePayloadPadding(GenericOpaquePayloadEnvelope& envelope);

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

[[nodiscard]] uint256 HashBytes(Span<const uint8_t> bytes)
{
    HashWriter hw;
    hw.write(AsBytes(bytes));
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

template <typename T>
[[nodiscard]] bool AllValid(Span<const T> objects)
{
    return std::all_of(objects.begin(), objects.end(), [](const T& obj) { return obj.IsValid(); });
}

[[nodiscard]] bool IsNonNullAndUnique(Span<const uint256> values)
{
    if (std::any_of(values.begin(), values.end(), [](const uint256& value) { return value.IsNull(); })) {
        return false;
    }
    std::vector<uint256> sorted{values.begin(), values.end()};
    std::sort(sorted.begin(), sorted.end());
    return std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end();
}

[[nodiscard]] bool ContainsDigest(Span<const uint256> digests, const uint256& digest)
{
    return std::find(digests.begin(), digests.end(), digest) != digests.end();
}

template <typename T, typename Accessor>
[[nodiscard]] bool IsStrictlySortedUnique(Span<const T> values, Accessor accessor)
{
    if (values.empty()) return true;
    for (size_t i = 1; i < values.size(); ++i) {
        if (!(accessor(values[i - 1]) < accessor(values[i]))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool ValueConservationHolds(Span<const ReserveDelta> deltas)
{
    CAmount total{0};
    for (const ReserveDelta& delta : deltas) {
        if (!IsAmountDeltaInRange(delta.reserve_delta)) return false;
        total += delta.reserve_delta;
        if (!IsAmountDeltaInRange(total)) return false;
    }
    return total == 0;
}

[[nodiscard]] uint256 ComputeDeterministicRebalanceStatementDigest(const uint256& manifest_id,
                                                                   const uint256& reserve_delta_root,
                                                                   const uint256& reserve_output_root)
{
    HashWriter hw;
    hw << std::string{TAG_REBALANCE_STATEMENT_DIGEST}
       << manifest_id
       << reserve_delta_root
       << reserve_output_root;
    return hw.GetSHA256();
}

[[nodiscard]] std::vector<uint8_t> SerializeDeterministicRebalanceShardPayload(
    const ReserveDelta& delta,
    const uint256& manifest_id,
    const uint256& statement_digest,
    const uint256& settlement_binding_digest,
    const uint256& reserve_output_root,
    uint32_t shard_index)
{
    DataStream stream;
    stream << std::string{TAG_REBALANCE_SHARD_PAYLOAD}
           << manifest_id
           << statement_digest
           << settlement_binding_digest
           << reserve_output_root
           << shard_index
           << delta;
    const auto* begin = reinterpret_cast<const uint8_t*>(stream.data());
    return {begin, begin + stream.size()};
}

[[nodiscard]] uint256 ComputeDeterministicRebalanceShardLeafSubroot(const ReserveDelta& delta,
                                                                    const uint256& manifest_id,
                                                                    const uint256& statement_digest)
{
    HashWriter hw;
    hw << std::string{TAG_REBALANCE_SHARD_LEAF_SUBROOT}
       << manifest_id
       << statement_digest
       << delta;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeDeterministicRebalanceShardNullifierCommitment(const ReserveDelta& delta,
                                                                            const uint256& manifest_id)
{
    HashWriter hw;
    hw << std::string{TAG_REBALANCE_SHARD_NULLIFIER_COMMIT}
       << manifest_id
       << delta.l2_id;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeDeterministicRebalanceShardPayloadDigest(Span<const uint8_t> shard_payload)
{
    HashWriter hw;
    hw << std::string{TAG_REBALANCE_SHARD_PAYLOAD}
       << shard_payload;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeDeterministicRebalanceShardValueCommitment(const ReserveDelta& delta,
                                                                        const uint256& reserve_output_root,
                                                                        const uint256& payload_digest)
{
    HashWriter hw;
    hw << std::string{TAG_REBALANCE_SHARD_VALUE_COMMIT}
       << reserve_output_root
       << payload_digest
       << delta.l2_id
       << delta.reserve_delta;
    return hw.GetSHA256();
}

[[nodiscard]] std::vector<uint8_t> ComputeDeterministicRebalanceShardMetadata(const ReserveDelta& delta,
                                                                              const uint256& manifest_id,
                                                                              const uint256& payload_digest)
{
    HashWriter hw;
    hw << std::string{TAG_REBALANCE_SHARD_METADATA}
       << manifest_id
       << payload_digest
       << delta.l2_id
       << delta.reserve_delta;
    const uint256 digest = hw.GetSHA256();
    return {digest.begin(), digest.end()};
}

template <typename T>
[[nodiscard]] Span<const T> MakeSpan(const std::vector<T>& values)
{
    return {values.data(), values.size()};
}

[[nodiscard]] bool ProofShardsMatchStatementDigest(Span<const ProofShardDescriptor> proof_shards,
                                                   const uint256& statement_digest)
{
    return std::all_of(proof_shards.begin(), proof_shards.end(), [&](const ProofShardDescriptor& descriptor) {
        return descriptor.statement_digest == statement_digest;
    });
}

[[nodiscard]] bool ProofEnvelopeMatchesFamily(TransactionFamily family, const ProofEnvelope& envelope)
{
    proof::ProofStatement statement;
    statement.domain = (family == TransactionFamily::V2_SEND ||
                        family == TransactionFamily::V2_LIFECYCLE)
        ? proof::VerificationDomain::DIRECT_SPEND
        : proof::VerificationDomain::BATCH_SETTLEMENT;
    statement.envelope = envelope;
    if (!statement.IsValid()) {
        return false;
    }

    switch (family) {
    case TransactionFamily::V2_SEND:
        return (envelope.proof_kind == ProofKind::NONE ||
                envelope.proof_kind == ProofKind::DIRECT_MATRICT ||
                envelope.proof_kind == ProofKind::DIRECT_SMILE ||
                envelope.proof_kind == ProofKind::GENERIC_SMILE ||
                envelope.proof_kind == ProofKind::GENERIC_OPAQUE) &&
               (envelope.settlement_binding_kind == SettlementBindingKind::NONE ||
                IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind));
    case TransactionFamily::V2_LIFECYCLE:
        return envelope.proof_kind == ProofKind::NONE &&
               (envelope.settlement_binding_kind == SettlementBindingKind::NONE ||
                IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind));
    case TransactionFamily::V2_INGRESS_BATCH:
        return (envelope.proof_kind == ProofKind::BATCH_MATRICT ||
                envelope.proof_kind == ProofKind::BATCH_SMILE ||
                envelope.proof_kind == ProofKind::GENERIC_SMILE ||
                envelope.proof_kind == ProofKind::GENERIC_OPAQUE) &&
               (envelope.settlement_binding_kind == SettlementBindingKind::NATIVE_BATCH ||
                IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind));
    case TransactionFamily::V2_EGRESS_BATCH:
        return (envelope.proof_kind == ProofKind::IMPORTED_RECEIPT ||
                envelope.proof_kind == ProofKind::GENERIC_BRIDGE ||
                envelope.proof_kind == ProofKind::GENERIC_OPAQUE) &&
               (envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_RECEIPT ||
                IsGenericBridgeSettlementBindingKind(envelope.settlement_binding_kind));
    case TransactionFamily::V2_REBALANCE:
        return (envelope.proof_kind == ProofKind::BATCH_MATRICT ||
                envelope.proof_kind == ProofKind::BATCH_SMILE ||
                envelope.proof_kind == ProofKind::GENERIC_SMILE ||
                envelope.proof_kind == ProofKind::GENERIC_OPAQUE) &&
               (envelope.settlement_binding_kind == SettlementBindingKind::NETTING_MANIFEST ||
                IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind));
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
        return (envelope.proof_kind == ProofKind::IMPORTED_RECEIPT ||
                envelope.proof_kind == ProofKind::IMPORTED_CLAIM ||
                envelope.proof_kind == ProofKind::GENERIC_BRIDGE ||
                envelope.proof_kind == ProofKind::GENERIC_OPAQUE) &&
               (envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_RECEIPT ||
                envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_CLAIM ||
                IsGenericBridgeSettlementBindingKind(envelope.settlement_binding_kind));
    case TransactionFamily::V2_GENERIC:
        return false;
    }
    return false;
}

[[nodiscard]] std::optional<uint32_t> ComputeCiphertextByteCount(Span<const OutputDescription> outputs)
{
    uint64_t total_bytes{0};
    for (const OutputDescription& output : outputs) {
        total_bytes += output.encrypted_note.ciphertext.size();
        if (total_bytes > std::numeric_limits<uint32_t>::max()) {
            return std::nullopt;
        }
    }
    return static_cast<uint32_t>(total_bytes);
}

[[nodiscard]] uint256 ComputeOutputChunkScanHintLeaf(const OutputDescription& output)
{
    HashWriter hw;
    hw << std::string{TAG_OUTPUT_CHUNK_SCAN_HINT_LEAF}
       << static_cast<uint8_t>(ScanDomain::OPAQUE)
       << output.encrypted_note.scan_hint;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeOutputChunkCiphertextLeaf(const OutputDescription& output)
{
    const uint256 derived_ephemeral_key =
        ComputeLegacyPayloadEphemeralKey(Span<const uint8_t>{output.encrypted_note.ciphertext.data(),
                                                             output.encrypted_note.ciphertext.size()});
    HashWriter hw;
    hw << std::string{TAG_OUTPUT_CHUNK_CIPHERTEXT_LEAF}
       << derived_ephemeral_key
       << output.encrypted_note.ciphertext;
    return hw.GetSHA256();
}

[[nodiscard]] bool OutputChunksMatchOutputs(Span<const OutputChunkDescriptor> output_chunks,
                                            Span<const OutputDescription> outputs)
{
    for (const OutputChunkDescriptor& descriptor : output_chunks) {
        if (descriptor.first_output_index > outputs.size()) {
            return false;
        }
        if (descriptor.output_count > outputs.size() - descriptor.first_output_index) {
            return false;
        }

        const auto* begin = outputs.data() + descriptor.first_output_index;
        if (!OutputChunkMatchesOutputs(descriptor, {begin, descriptor.output_count})) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool OutputBindsCanonicalSmileAccount(const OutputDescription& output)
{
    return output.smile_account.has_value() &&
           output.smile_account->IsValid() &&
           smile2::ComputeCompactPublicAccountHash(*output.smile_account) == output.note_commitment;
}

[[nodiscard]] bool OutputHasCompactSmileKeyData(const OutputDescription& output)
{
    return output.smile_public_key.has_value() &&
           output.smile_public_key->IsValid();
}

[[nodiscard]] bool OutputsBindCanonicalSmileAccounts(Span<const OutputDescription> outputs)
{
    return std::all_of(outputs.begin(), outputs.end(), [](const OutputDescription& output) {
        return OutputBindsCanonicalSmileAccount(output);
    });
}

void RehydrateDirectSendSmileAccounts(TransactionBundle& bundle)
{
    if (!BundleHasSemanticFamily(bundle, TransactionFamily::V2_SEND) ||
        !std::holds_alternative<SendPayload>(bundle.payload)) {
        return;
    }

    auto& payload = std::get<SendPayload>(bundle.payload);
    if (!IsCompactSendOutputEncoding(payload.output_encoding)) {
        return;
    }

    std::string reject_reason;
    auto witness = proof::ParseV2SendWitness(bundle, reject_reason);
    if (!witness.has_value() || !witness->use_smile ||
        witness->smile_output_coins.size() != payload.outputs.size()) {
        throw std::ios_base::failure("TransactionBundle::Unserialize invalid smile witness");
    }

    for (size_t output_index = 0; output_index < payload.outputs.size(); ++output_index) {
        auto& output = payload.outputs[output_index];
        if (!OutputHasCompactSmileKeyData(output)) {
            throw std::ios_base::failure("TransactionBundle::Unserialize missing smile public key");
        }
        auto reconstructed = smile2::BuildCompactPublicAccountFromPublicParts(
            *output.smile_public_key,
            witness->smile_output_coins[output_index]);
        if (!reconstructed.has_value() ||
            smile2::ComputeCompactPublicAccountHash(*reconstructed) != output.note_commitment ||
            smile2::ComputeSmileOutputCoinHash(witness->smile_output_coins[output_index]) !=
                output.value_commitment) {
            throw std::ios_base::failure("TransactionBundle::Unserialize mismatched smile output account");
        }
        output.smile_account = std::move(*reconstructed);
    }
}

} // namespace

bool SpendDescription::IsValid() const
{
    return version == WIRE_VERSION &&
           !nullifier.IsNull() &&
           !merkle_anchor.IsNull() &&
           !account_leaf_commitment.IsNull() &&
           account_registry_proof.IsValid() &&
           account_registry_proof.account_leaf_commitment == account_leaf_commitment &&
           !value_commitment.IsNull();
}

bool ConsumedAccountLeafSpend::IsValid() const
{
    return version == WIRE_VERSION &&
           !nullifier.IsNull() &&
           !account_leaf_commitment.IsNull() &&
           account_registry_proof.IsValid() &&
           account_registry_proof.account_leaf_commitment == account_leaf_commitment;
}

uint256 ComputeV2EgressOutputValueCommitment(const uint256& output_binding_digest,
                                             uint32_t output_index,
                                             const uint256& note_commitment)
{
    if (output_binding_digest.IsNull() || note_commitment.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{TAG_EGRESS_OUTPUT_VALUE_COMMIT}
       << output_binding_digest
       << output_index
       << note_commitment;
    return hw.GetSHA256();
}

uint256 ComputeV2RebalanceOutputValueCommitment(uint32_t output_index,
                                                const uint256& note_commitment)
{
    if (note_commitment.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{TAG_REBALANCE_OUTPUT_VALUE_COMMIT}
       << output_index
       << note_commitment;
    return hw.GetSHA256();
}

bool LifecycleAddress::IsValid() const
{
    if ((version != 0x00 && version != 0x01) ||
        algo_byte != 0x00 ||
        pk_hash.IsNull() ||
        kem_pk_hash.IsNull()) {
        return false;
    }
    if (version == 0x00) {
        return !has_kem_public_key;
    }
    if (!has_kem_public_key) {
        return false;
    }
    return HashBytes(Span<const uint8_t>{kem_public_key.data(), kem_public_key.size()}) == kem_pk_hash;
}

[[nodiscard]] bool HasValidAddressLifecycleControlStructure(const AddressLifecycleControl& control,
                                                            bool require_signature)
{
    if (control.version != WIRE_VERSION ||
        !IsValidAddressLifecycleControlKind(control.kind) ||
        !control.subject.IsValid() ||
        control.subject_spending_pubkey.size() != MLDSA44_PUBKEY_SIZE ||
        HashBytes(Span<const uint8_t>{control.subject_spending_pubkey.data(),
                                      control.subject_spending_pubkey.size()}) != control.subject.pk_hash) {
        return false;
    }
    if (require_signature) {
        if (control.signature.size() != MLDSA44_SIGNATURE_SIZE) {
            return false;
        }
    } else if (!control.signature.empty() && control.signature.size() != MLDSA44_SIGNATURE_SIZE) {
        return false;
    }
    if (control.kind == AddressLifecycleControlKind::ROTATE) {
        return control.has_successor &&
               control.successor.IsValid() &&
               control.successor.version == 0x01 &&
               control.successor.has_kem_public_key &&
               control.successor.pk_hash != control.subject.pk_hash &&
               control.successor.kem_pk_hash != control.subject.kem_pk_hash;
    }
    return !control.has_successor;
}

bool AddressLifecycleControl::IsValid() const
{
    return HasValidAddressLifecycleControlStructure(*this, /*require_signature=*/true);
}

uint256 ComputeAddressLifecycleControlSigHash(const AddressLifecycleControl& control,
                                              const uint256& note_commitment)
{
    if (!HasValidAddressLifecycleControlStructure(control, /*require_signature=*/false) ||
        note_commitment.IsNull()) {
        return uint256{};
    }

    HashWriter hw;
    hw << std::string{TAG_ADDRESS_LIFECYCLE_CONTROL_SIG}
       << static_cast<uint8_t>(control.kind)
       << control.output_index
       << control.subject
       << control.has_successor;
    if (control.has_successor) {
        hw << control.successor;
    }
    hw << note_commitment;
    return hw.GetSHA256();
}

bool VerifyAddressLifecycleControl(const AddressLifecycleControl& control,
                                   const uint256& note_commitment)
{
    if (!control.IsValid()) {
        return false;
    }
    const uint256 sighash = ComputeAddressLifecycleControlSigHash(control, note_commitment);
    if (sighash.IsNull()) {
        return false;
    }
    return CPQPubKey{PQAlgorithm::ML_DSA_44,
                     Span<const uint8_t>{control.subject_spending_pubkey.data(),
                                         control.subject_spending_pubkey.size()}}
        .Verify(sighash,
                Span<const uint8_t>{control.signature.data(), control.signature.size()});
}

uint256 ComputeV2LifecycleTransparentBindingDigest(const CTransaction& tx)
{
    if (tx.vin.empty()) {
        return uint256{};
    }

    HashWriter hw;
    hw << std::string{TAG_LIFECYCLE_TRANSPARENT_BINDING}
       << tx.version
       << tx.nLockTime
       << static_cast<uint64_t>(tx.vin.size());
    for (const auto& txin : tx.vin) {
        hw << txin.prevout << txin.nSequence;
    }
    hw << static_cast<uint64_t>(tx.vout.size());
    for (const auto& txout : tx.vout) {
        hw << txout.nValue << txout.scriptPubKey;
    }
    return hw.GetSHA256();
}

uint256 ComputeAddressLifecycleRecordSigHash(const AddressLifecycleControl& control,
                                             const uint256& transparent_binding_digest)
{
    if (!HasValidAddressLifecycleControlStructure(control, /*require_signature=*/false) ||
        transparent_binding_digest.IsNull()) {
        return uint256{};
    }

    HashWriter hw;
    hw << std::string{TAG_ADDRESS_LIFECYCLE_RECORD_SIG}
       << static_cast<uint8_t>(control.kind)
       << control.output_index
       << control.subject
       << control.has_successor;
    if (control.has_successor) {
        hw << control.successor;
    }
    hw << transparent_binding_digest;
    return hw.GetSHA256();
}

bool VerifyAddressLifecycleRecord(const AddressLifecycleControl& control,
                                  const uint256& transparent_binding_digest)
{
    if (!control.IsValid()) {
        return false;
    }
    const uint256 sighash =
        ComputeAddressLifecycleRecordSigHash(control, transparent_binding_digest);
    if (sighash.IsNull()) {
        return false;
    }
    return CPQPubKey{PQAlgorithm::ML_DSA_44,
                     Span<const uint8_t>{control.subject_spending_pubkey.data(),
                                         control.subject_spending_pubkey.size()}}
        .Verify(sighash,
                Span<const uint8_t>{control.signature.data(), control.signature.size()});
}

bool OutputDescription::IsValid() const
{
    return version == WIRE_VERSION &&
           IsValidNoteClass(note_class) &&
           !note_commitment.IsNull() &&
           !value_commitment.IsNull() &&
           ((smile_account.has_value() &&
             smile_account->IsValid() &&
             (!smile_public_key.has_value() ||
              smile_public_key->public_key == smile_account->public_key) &&
             smile2::ComputeCompactPublicAccountHash(*smile_account) == note_commitment) ||
            OutputHasCompactSmileKeyData(*this)) &&
           encrypted_note.IsValid();
}

bool ReserveDelta::IsValid() const
{
    return version == WIRE_VERSION &&
           !l2_id.IsNull() &&
           reserve_delta != 0 &&
           IsAmountDeltaInRange(reserve_delta);
}

bool ReserveDeltaSetIsCanonical(Span<const ReserveDelta> deltas)
{
    return std::all_of(deltas.begin(), deltas.end(), [](const ReserveDelta& delta) {
               return delta.IsValid();
           }) &&
           IsStrictlySortedUnique(deltas, [](const ReserveDelta& delta) -> const uint256& { return delta.l2_id; }) &&
           ValueConservationHolds(deltas);
}

bool SendPayload::IsValid() const
{
    const Span<const OutputDescription> output_span = MakeSpan(outputs);
    const bool has_spends = !spends.empty();
    const bool has_lifecycle_controls = !lifecycle_controls.empty();
    const bool elides_value_balance =
        SendOutputEncodingElidesValueBalance(output_encoding) && !has_lifecycle_controls;
    const bool spends_are_valid =
        std::all_of(spends.begin(), spends.end(), [&](const SpendDescription& spend) {
            if (spend.version != WIRE_VERSION ||
                spend.nullifier.IsNull() ||
                spend.merkle_anchor.IsNull() ||
                spend.account_leaf_commitment.IsNull() ||
                !spend.account_registry_proof.IsValid() ||
                spend.account_registry_proof.account_leaf_commitment != spend.account_leaf_commitment) {
                return false;
            }
            if (IsCompactSendOutputEncoding(output_encoding)) {
                return true;
            }
            return !spend.value_commitment.IsNull();
        });
    if (version != WIRE_VERSION ||
        spends.size() > MAX_DIRECT_SPENDS ||
        outputs.empty() || outputs.size() > MAX_DIRECT_OUTPUTS ||
        lifecycle_controls.size() > MAX_ADDRESS_LIFECYCLE_CONTROLS ||
        !IsValidSendOutputEncoding(output_encoding) ||
        !AllValid(output_span) ||
        !MoneyRangeSigned(value_balance) ||
        !MoneyRange(fee) || fee < 0) {
        return false;
    }

    if (has_spends) {
        if (spend_anchor.IsNull() ||
            account_registry_anchor.IsNull() ||
            !spends_are_valid ||
            value_balance < fee) {
            return false;
        }
    } else if (!spend_anchor.IsNull() ||
               !account_registry_anchor.IsNull() ||
               value_balance >= 0) {
        return false;
    }

    if (has_spends) {
        std::vector<uint256> nullifiers;
        nullifiers.reserve(spends.size());
        for (const SpendDescription& spend : spends) {
            nullifiers.push_back(spend.nullifier);
        }
        if (!IsNonNullAndUnique(MakeSpan(nullifiers))) {
            return false;
        }
    }

    if (elides_value_balance &&
        (!has_spends || value_balance != fee)) {
        return false;
    }

    if (has_lifecycle_controls &&
        output_encoding != SendOutputEncoding::LEGACY) {
        return false;
    }

    if (IsCompactSendOutputEncoding(output_encoding)) {
        if (!IsValidNoteClass(output_note_class) ||
            output_scan_domain != ScanDomain::OPAQUE ||
            !std::all_of(outputs.begin(), outputs.end(), [&](const OutputDescription& output) {
                return output.note_class == output_note_class &&
                       output.encrypted_note.scan_domain == output_scan_domain &&
                       (OutputHasCompactSmileKeyData(output) ||
                        OutputBindsCanonicalSmileAccount(output));
            })) {
            return false;
        }
    }

    if (has_lifecycle_controls) {
        if (has_spends ||
            outputs.size() != 1 ||
            output_note_class != NoteClass::OPERATOR) {
            return false;
        }
        std::vector<uint32_t> control_indexes;
        control_indexes.reserve(lifecycle_controls.size());
        for (const auto& control : lifecycle_controls) {
            if (!control.IsValid() ||
                control.output_index >= outputs.size() ||
                outputs[control.output_index].note_class != NoteClass::OPERATOR ||
                !VerifyAddressLifecycleControl(control, outputs[control.output_index].note_commitment)) {
                return false;
            }
            control_indexes.push_back(control.output_index);
        }
        std::sort(control_indexes.begin(), control_indexes.end());
        if (std::adjacent_find(control_indexes.begin(), control_indexes.end()) != control_indexes.end()) {
            return false;
        }
    }

    std::vector<uint256> note_commitments;
    note_commitments.reserve(outputs.size());
    for (const OutputDescription& output : outputs) {
        note_commitments.push_back(output.note_commitment);
    }
    return IsNonNullAndUnique(MakeSpan(note_commitments));
}

bool LifecyclePayload::IsValid() const
{
    if (version != WIRE_VERSION ||
        transparent_binding_digest.IsNull() ||
        lifecycle_controls.size() != 1) {
        return false;
    }

    return std::all_of(lifecycle_controls.begin(),
                       lifecycle_controls.end(),
                       [&](const AddressLifecycleControl& control) {
                           return control.output_index == 0 &&
                                  VerifyAddressLifecycleRecord(control,
                                                               transparent_binding_digest);
                       });
}

bool IngressBatchPayload::IsValid() const
{
    const Span<const BatchLeaf> leaf_span = MakeSpan(ingress_leaves);
    const Span<const OutputDescription> output_span = MakeSpan(reserve_outputs);
    if (version != WIRE_VERSION ||
        spend_anchor.IsNull() ||
        account_registry_anchor.IsNull() ||
        consumed_spends.empty() || consumed_spends.size() > MAX_BATCH_NULLIFIERS ||
        ingress_leaves.empty() || ingress_leaves.size() > MAX_BATCH_LEAVES ||
        reserve_outputs.empty() || reserve_outputs.size() > MAX_BATCH_RESERVE_OUTPUTS ||
        !IsValidReserveOutputEncoding(reserve_output_encoding) ||
        !AllValid(leaf_span) ||
        !AllValid(output_span) ||
        !std::all_of(consumed_spends.begin(), consumed_spends.end(), [](const ConsumedAccountLeafSpend& spend) {
            return spend.IsValid();
        }) ||
        ingress_root.IsNull() ||
        l2_credit_root.IsNull() ||
        aggregate_reserve_commitment.IsNull() ||
        aggregate_fee_commitment.IsNull() ||
        fee < 0 ||
        !MoneyRange(fee) ||
        settlement_binding_digest.IsNull()) {
        return false;
    }
    if (!std::all_of(reserve_outputs.begin(), reserve_outputs.end(), [](const OutputDescription& output) {
            return output.note_class == NoteClass::RESERVE &&
                   output.encrypted_note.scan_domain == ScanDomain::OPAQUE;
        })) {
        return false;
    }
    if (reserve_output_encoding == ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED) {
        for (size_t output_index = 0; output_index < reserve_outputs.size(); ++output_index) {
            const OutputDescription& output = reserve_outputs[output_index];
            if (output.value_commitment != ComputeV2IngressPlaceholderReserveValueCommitment(
                                               settlement_binding_digest,
                                               static_cast<uint32_t>(output_index),
                                               output.note_commitment)) {
                return false;
            }
        }
    }
    std::vector<uint256> consumed_nullifiers;
    consumed_nullifiers.reserve(consumed_spends.size());
    for (const auto& spend : consumed_spends) {
        consumed_nullifiers.push_back(spend.nullifier);
    }
    if (!IsNonNullAndUnique(MakeSpan(consumed_nullifiers))) {
        return false;
    }
    if (ComputeBatchLeafRoot(leaf_span) != ingress_root ||
        ComputeV2IngressL2CreditRoot(leaf_span) != l2_credit_root ||
        ComputeV2IngressAggregateFeeCommitment(leaf_span) != aggregate_fee_commitment ||
        ComputeV2IngressAggregateReserveCommitment(output_span) != aggregate_reserve_commitment) {
        return false;
    }
    for (size_t i = 0; i < ingress_leaves.size(); ++i) {
        if (ingress_leaves[i].position != i) {
            return false;
        }
    }
    return true;
}

bool EgressBatchPayload::IsValid() const
{
    const Span<const OutputDescription> output_span = MakeSpan(outputs);
    return version == WIRE_VERSION &&
           !settlement_anchor.IsNull() &&
           !egress_root.IsNull() &&
           !output_binding_digest.IsNull() &&
           !outputs.empty() &&
           outputs.size() <= MAX_EGRESS_OUTPUTS &&
           AllValid(output_span) &&
           std::all_of(outputs.begin(), outputs.end(), [&](const OutputDescription& output) {
               const uint32_t output_index = static_cast<uint32_t>(&output - outputs.data());
               return output.note_class == NoteClass::USER &&
                      output.encrypted_note.scan_domain == ScanDomain::OPAQUE &&
                      output.value_commitment == ComputeV2EgressOutputValueCommitment(output_binding_digest,
                                                                                      output_index,
                                                                                      output.note_commitment);
           }) &&
           ComputeOutputDescriptionRoot(output_span) == egress_root &&
           !settlement_binding_digest.IsNull();
}

bool RebalancePayload::IsValid() const
{
    const Span<const ReserveDelta> delta_span = MakeSpan(reserve_deltas);
    const Span<const OutputDescription> output_span = MakeSpan(reserve_outputs);
    const uint256 manifest_id = has_netting_manifest ? ComputeNettingManifestId(netting_manifest) : uint256{};
    if (version != WIRE_VERSION ||
        reserve_deltas.size() < 2 || reserve_deltas.size() > MAX_REBALANCE_DOMAINS ||
        reserve_outputs.size() > MAX_BATCH_RESERVE_OUTPUTS ||
        !ReserveDeltaSetIsCanonical(delta_span) ||
        !AllValid(output_span) ||
        settlement_binding_digest.IsNull() ||
        batch_statement_digest.IsNull()) {
        return false;
    }
    if (!std::all_of(reserve_outputs.begin(), reserve_outputs.end(), [&](const OutputDescription& output) {
            const uint32_t output_index = static_cast<uint32_t>(&output - reserve_outputs.data());
            return output.note_class == NoteClass::RESERVE &&
                   output.encrypted_note.scan_domain == ScanDomain::OPAQUE &&
                   output.value_commitment == ComputeV2RebalanceOutputValueCommitment(output_index,
                                                                                      output.note_commitment);
        })) {
        return false;
    }
    if (!has_netting_manifest) {
        return true;
    }
    if (!netting_manifest.IsValid() ||
        manifest_id.IsNull() ||
        netting_manifest.binding_kind != SettlementBindingKind::NETTING_MANIFEST ||
        netting_manifest.domains.size() != reserve_deltas.size() ||
        settlement_binding_digest != manifest_id ||
        batch_statement_digest != ComputeV2RebalanceStatementDigest(settlement_binding_digest,
                                                                    delta_span,
                                                                    output_span)) {
        return false;
    }
    for (size_t i = 0; i < reserve_deltas.size(); ++i) {
        if (netting_manifest.domains[i].l2_id != reserve_deltas[i].l2_id ||
            netting_manifest.domains[i].net_reserve_delta != reserve_deltas[i].reserve_delta) {
            return false;
        }
    }
    return true;
}

uint256 ComputeV2RebalanceStatementDigest(const uint256& settlement_binding_digest,
                                          Span<const ReserveDelta> reserve_deltas,
                                          Span<const OutputDescription> reserve_outputs)
{
    const uint256 reserve_delta_root = ComputeReserveDeltaRoot(reserve_deltas);
    const uint256 reserve_output_root = reserve_outputs.empty()
        ? uint256::ZERO
        : ComputeOutputDescriptionRoot(reserve_outputs);
    if (settlement_binding_digest.IsNull() ||
        (reserve_deltas.empty() && reserve_output_root.IsNull())) {
        return uint256{};
    }
    return ComputeDeterministicRebalanceStatementDigest(settlement_binding_digest,
                                                        reserve_delta_root,
                                                        reserve_output_root);
}

bool SettlementAnchorPayload::IsValid() const
{
    const Span<const ReserveDelta> delta_span = MakeSpan(reserve_deltas);
    const auto ids_valid = [](Span<const uint256> ids) {
        if (ids.size() > MAX_SETTLEMENT_REFS) return false;
        return IsNonNullAndUnique(ids);
    };
    if (version != WIRE_VERSION ||
        !ids_valid(MakeSpan(imported_claim_ids)) ||
        !ids_valid(MakeSpan(imported_adapter_ids)) ||
        !ids_valid(MakeSpan(proof_receipt_ids)) ||
        !ids_valid(MakeSpan(batch_statement_digests)) ||
        reserve_deltas.size() > MAX_REBALANCE_DOMAINS ||
        !ReserveDeltaSetIsCanonical(delta_span) ||
        (reserve_deltas.empty() && !anchored_netting_manifest_id.IsNull())) {
        return false;
    }
    return !(imported_claim_ids.empty() &&
             imported_adapter_ids.empty() &&
             proof_receipt_ids.empty() &&
             batch_statement_digests.empty() &&
             reserve_deltas.empty() &&
             anchored_netting_manifest_id.IsNull());
}

bool GenericOpaqueSpendRecord::IsValid() const
{
    return version == WIRE_VERSION &&
           !nullifier.IsNull() &&
           !account_leaf_commitment.IsNull() &&
           account_registry_proof.IsValid() &&
           account_registry_proof.account_leaf_commitment == account_leaf_commitment;
}

bool GenericOpaqueOutputRecord::IsValid() const
{
    return version == WIRE_VERSION &&
           IsValidNoteClass(note_class) &&
           IsValidScanDomain(scan_domain) &&
           !note_commitment.IsNull() &&
           !value_commitment.IsNull() &&
           encrypted_note.IsValid() &&
           ((has_smile_account &&
             smile_account.IsValid() &&
             (!has_smile_public_key ||
              smile_public_key.public_key == smile_account.public_key) &&
             smile2::ComputeCompactPublicAccountHash(smile_account) == note_commitment) ||
            (has_smile_public_key && smile_public_key.IsValid()));
}

bool GenericOpaquePayloadEnvelope::IsValid() const
{
    const auto ids_valid = [](Span<const uint256> ids) {
        if (ids.size() > MAX_SETTLEMENT_REFS) return false;
        return IsNonNullAndUnique(ids);
    };
    return version == WIRE_VERSION &&
           IsValidSendOutputEncoding(output_encoding) &&
           IsValidNoteClass(output_note_class) &&
           IsValidScanDomain(output_scan_domain) &&
           IsValidReserveOutputEncoding(reserve_output_encoding) &&
           spends.size() <= MAX_GENERIC_SPENDS &&
           outputs.size() <= MAX_GENERIC_OUTPUTS &&
           lifecycle_controls.size() <= MAX_ADDRESS_LIFECYCLE_CONTROLS &&
           ingress_leaves.size() <= MAX_BATCH_LEAVES &&
           reserve_deltas.size() <= MAX_REBALANCE_DOMAINS &&
           AllValid(MakeSpan(spends)) &&
           AllValid(MakeSpan(outputs)) &&
           AllValid(MakeSpan(ingress_leaves)) &&
           std::all_of(lifecycle_controls.begin(), lifecycle_controls.end(), [](const auto& control) {
               return control.IsValid();
           }) &&
           OpaqueReserveDeltasAreValid(MakeSpan(reserve_deltas)) &&
           (!has_netting_manifest || netting_manifest.IsValid()) &&
           MoneyRangeSigned(value_balance) &&
           MoneyRange(fee) &&
           fee >= 0 &&
           ids_valid(MakeSpan(imported_claim_ids)) &&
           ids_valid(MakeSpan(imported_adapter_ids)) &&
           ids_valid(MakeSpan(proof_receipt_ids)) &&
           ids_valid(MakeSpan(batch_statement_digests));
}

TransactionFamily GetPayloadFamily(const FamilyPayload& payload)
{
    if (std::holds_alternative<SendPayload>(payload)) return TransactionFamily::V2_SEND;
    if (std::holds_alternative<LifecyclePayload>(payload)) return TransactionFamily::V2_LIFECYCLE;
    if (std::holds_alternative<IngressBatchPayload>(payload)) return TransactionFamily::V2_INGRESS_BATCH;
    if (std::holds_alternative<EgressBatchPayload>(payload)) return TransactionFamily::V2_EGRESS_BATCH;
    if (std::holds_alternative<RebalancePayload>(payload)) return TransactionFamily::V2_REBALANCE;
    return TransactionFamily::V2_SETTLEMENT_ANCHOR;
}

bool IsGenericTransactionFamily(TransactionFamily family)
{
    return family == TransactionFamily::V2_GENERIC;
}

bool IsGenericPostforkSettlementBindingKind(SettlementBindingKind kind)
{
    return kind == SettlementBindingKind::GENERIC_POSTFORK;
}

bool IsGenericShieldedSettlementBindingKind(SettlementBindingKind kind)
{
    return kind == SettlementBindingKind::GENERIC_SHIELDED ||
           kind == SettlementBindingKind::GENERIC_POSTFORK;
}

bool IsGenericBridgeSettlementBindingKind(SettlementBindingKind kind)
{
    return kind == SettlementBindingKind::GENERIC_BRIDGE ||
           kind == SettlementBindingKind::GENERIC_POSTFORK;
}

bool WireFamilyMatchesPayload(TransactionFamily wire_family, const FamilyPayload& payload)
{
    const TransactionFamily semantic_family = GetPayloadFamily(payload);
    return wire_family == semantic_family || IsGenericTransactionFamily(wire_family);
}

TransactionFamily GetBundleSemanticFamily(const TransactionBundle& bundle)
{
    return GetPayloadFamily(bundle.payload);
}

bool BundleHasSemanticFamily(const TransactionBundle& bundle, TransactionFamily family)
{
    return GetBundleSemanticFamily(bundle) == family &&
           WireFamilyMatchesPayload(bundle.header.family_id, bundle.payload);
}

bool UseGenericV2WireFamily(const Consensus::Params* consensus, int32_t validation_height)
{
    return consensus != nullptr && consensus->IsShieldedMatRiCTDisabled(validation_height);
}

bool UseGenericV2ProofEnvelope(const Consensus::Params* consensus, int32_t validation_height)
{
    return UseGenericV2WireFamily(consensus, validation_height);
}

bool UseGenericV2SettlementBinding(const Consensus::Params* consensus, int32_t validation_height)
{
    return UseGenericV2WireFamily(consensus, validation_height);
}

bool IsGenericOpaqueProofComponentKind(ProofComponentKind kind)
{
    return kind == ProofComponentKind::GENERIC_OPAQUE;
}

bool IsGenericOpaqueProofKind(ProofKind kind)
{
    return kind == ProofKind::GENERIC_OPAQUE;
}

bool IsGenericSmileProofKind(ProofKind kind)
{
    return kind == ProofKind::GENERIC_SMILE;
}

bool IsGenericBridgeProofKind(ProofKind kind)
{
    return kind == ProofKind::GENERIC_BRIDGE;
}

TransactionFamily GetWireTransactionFamilyForValidationHeight(TransactionFamily semantic_family,
                                                              const Consensus::Params* consensus,
                                                              int32_t validation_height)
{
    return UseGenericV2WireFamily(consensus, validation_height)
        ? TransactionFamily::V2_GENERIC
        : semantic_family;
}

ProofComponentKind GetWireProofComponentKindForValidationHeight(
    ProofComponentKind semantic_component_kind,
    const Consensus::Params* consensus,
    int32_t validation_height)
{
    if (!UseGenericV2ProofEnvelope(consensus, validation_height) ||
        semantic_component_kind == ProofComponentKind::NONE) {
        return semantic_component_kind;
    }
    return ProofComponentKind::GENERIC_OPAQUE;
}

ProofKind GetWireProofKindForValidationHeight(TransactionFamily semantic_family,
                                              ProofKind semantic_proof_kind,
                                              const Consensus::Params* consensus,
                                              int32_t validation_height)
{
    if (!UseGenericV2ProofEnvelope(consensus, validation_height)) {
        return semantic_proof_kind;
    }

    switch (semantic_proof_kind) {
    case ProofKind::NONE:
    case ProofKind::DIRECT_MATRICT:
    case ProofKind::BATCH_MATRICT:
        return semantic_proof_kind;
    case ProofKind::IMPORTED_RECEIPT:
    case ProofKind::IMPORTED_CLAIM:
    case ProofKind::DIRECT_SMILE:
    case ProofKind::BATCH_SMILE:
    case ProofKind::GENERIC_SMILE:
    case ProofKind::GENERIC_BRIDGE:
    case ProofKind::GENERIC_OPAQUE:
        return semantic_family == TransactionFamily::V2_GENERIC
            ? semantic_proof_kind
            : ProofKind::GENERIC_OPAQUE;
    }
    return semantic_proof_kind;
}

SettlementBindingKind GetWireSettlementBindingKindForValidationHeight(
    TransactionFamily semantic_family,
    SettlementBindingKind semantic_binding_kind,
    const Consensus::Params* consensus,
    int32_t validation_height)
{
    if (!UseGenericV2SettlementBinding(consensus, validation_height)) {
        return semantic_binding_kind;
    }

    switch (semantic_family) {
    case TransactionFamily::V2_SEND:
    case TransactionFamily::V2_LIFECYCLE:
    case TransactionFamily::V2_INGRESS_BATCH:
    case TransactionFamily::V2_EGRESS_BATCH:
    case TransactionFamily::V2_REBALANCE:
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
        return SettlementBindingKind::GENERIC_POSTFORK;
    case TransactionFamily::V2_GENERIC:
        return semantic_binding_kind;
    }
    return semantic_binding_kind;
}

namespace {

[[nodiscard]] size_t CanonicalOpaquePayloadSize(size_t raw_size)
{
    if (raw_size == 0) {
        return 0;
    }
    const size_t quantum = static_cast<size_t>(OPAQUE_FAMILY_PAYLOAD_PAD_QUANTUM);
    return ((raw_size + quantum - 1) / quantum) * quantum;
}

[[nodiscard]] std::vector<uint8_t> PadOpaqueBytes(std::vector<uint8_t> bytes)
{
    const size_t canonical_size = CanonicalOpaquePayloadSize(bytes.size());
    if (canonical_size > bytes.size()) {
        bytes.resize(canonical_size, 0);
    }
    return bytes;
}

[[nodiscard]] bool RemainingBytesAreZero(const DataStream& ds)
{
    return std::all_of(ds.begin(), ds.end(), [](const std::byte value) { return value == std::byte{0}; });
}

[[nodiscard]] bool TrailingBytesAreZero(Span<const uint8_t> bytes, size_t used_size)
{
    if (used_size > bytes.size()) {
        return false;
    }
    return std::all_of(bytes.begin() + static_cast<ptrdiff_t>(used_size),
                       bytes.end(),
                       [](uint8_t value) { return value == 0; });
}

[[nodiscard]] size_t CanonicalOpaqueVectorCount(size_t logical_count, size_t max_count)
{
    if (max_count == 0) {
        return 0;
    }
    if (logical_count == 0) {
        return 1;
    }
    if (logical_count <= 2) {
        return std::min<size_t>(2, max_count);
    }

    size_t bucket{4};
    while (bucket < logical_count && bucket < 16 && bucket < max_count) {
        bucket <<= 1;
    }
    if (bucket >= logical_count) {
        return std::min(bucket, max_count);
    }

    constexpr size_t kLargeQuantum{16};
    const size_t quantum = std::min(kLargeQuantum, max_count);
    return std::min(((logical_count + quantum - 1) / quantum) * quantum, max_count);
}

template <typename T, typename MakePadding>
void PadOpaqueVectorToCanonicalCount(std::vector<T>& values,
                                     size_t max_count,
                                     MakePadding make_padding)
{
    const size_t logical_count = values.size();
    const size_t padded_count = CanonicalOpaqueVectorCount(logical_count, max_count);
    for (size_t padding_index = logical_count; padding_index < padded_count; ++padding_index) {
        values.push_back(make_padding(static_cast<uint32_t>(padding_index - logical_count),
                                      padded_count - logical_count));
    }
}

template <typename T, typename MatchesPadding>
[[nodiscard]] bool StripOpaqueVectorPadding(std::vector<T>& values,
                                            size_t max_count,
                                            MatchesPadding matches_padding)
{
    if (values.empty() || values.size() > max_count) {
        return false;
    }

    for (size_t logical_count = 0; logical_count <= values.size(); ++logical_count) {
        if (values.size() != CanonicalOpaqueVectorCount(logical_count, max_count)) {
            continue;
        }

        bool matches{true};
        for (size_t padding_index = logical_count; padding_index < values.size(); ++padding_index) {
            if (!matches_padding(values[padding_index],
                                 static_cast<uint32_t>(padding_index - logical_count),
                                 values.size() - logical_count)) {
                matches = false;
                break;
            }
        }
        if (!matches) {
            continue;
        }

        values.resize(logical_count);
        return true;
    }

    return false;
}

[[nodiscard]] bool StripReserveDeltaPadding(std::vector<ReserveDelta>& deltas)
{
    if (deltas.size() > MAX_REBALANCE_DOMAINS) {
        return false;
    }

    for (size_t logical_count = 0; logical_count <= deltas.size(); ++logical_count) {
        if (deltas.size() != CanonicalOpaqueVectorCount(logical_count, MAX_REBALANCE_DOMAINS)) {
            continue;
        }
        if (!ReserveDeltaSetIsCanonical({deltas.data(), logical_count})) {
            continue;
        }

        bool matches{true};
        for (size_t padding_index = logical_count; padding_index < deltas.size(); ++padding_index) {
            if (!ObjectsEqualBySerialization(
                    deltas[padding_index],
                    MakeOpaquePaddingReserveDelta(static_cast<uint32_t>(padding_index - logical_count),
                                                  deltas.size() - logical_count))) {
                matches = false;
                break;
            }
        }
        if (matches) {
            deltas.resize(logical_count);
            return true;
        }
    }

    return false;
}

[[nodiscard]] bool OpaqueReserveDeltasAreValid(Span<const ReserveDelta> deltas)
{
    if (deltas.empty()) {
        return true;
    }
    if (deltas.size() > MAX_REBALANCE_DOMAINS) {
        return false;
    }

    for (size_t logical_count = 0; logical_count <= deltas.size(); ++logical_count) {
        if (deltas.size() != CanonicalOpaqueVectorCount(logical_count, MAX_REBALANCE_DOMAINS)) {
            continue;
        }
        if (!ReserveDeltaSetIsCanonical(deltas.subspan(0, logical_count))) {
            continue;
        }

        bool matches{true};
        for (size_t padding_index = logical_count; padding_index < deltas.size(); ++padding_index) {
            if (!ObjectsEqualBySerialization(
                    deltas[padding_index],
                    MakeOpaquePaddingReserveDelta(static_cast<uint32_t>(padding_index - logical_count),
                                                  deltas.size() - logical_count))) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return true;
        }
    }

    return false;
}
constexpr std::string_view TAG_GENERIC_PROOF_PADDING_DOMAIN{
    "BTX_ShieldedV2_Generic_Proof_Padding_Domain_V1"};
constexpr std::string_view TAG_GENERIC_PROOF_PADDING_LEAF{
    "BTX_ShieldedV2_Generic_Proof_Padding_Leaf_V1"};
constexpr std::string_view TAG_GENERIC_PROOF_PADDING_NULLIFIER{
    "BTX_ShieldedV2_Generic_Proof_Padding_Nullifier_V1"};
constexpr std::string_view TAG_GENERIC_PROOF_PADDING_VALUE{
    "BTX_ShieldedV2_Generic_Proof_Padding_Value_V1"};
constexpr std::string_view TAG_GENERIC_PROOF_PADDING_STATEMENT{
    "BTX_ShieldedV2_Generic_Proof_Padding_Statement_V1"};
constexpr std::string_view TAG_GENERIC_PROOF_PADDING_METADATA{
    "BTX_ShieldedV2_Generic_Proof_Padding_Metadata_V1"};
constexpr std::string_view TAG_GENERIC_OUTPUT_CHUNK_PADDING_SCAN{
    "BTX_ShieldedV2_Generic_Output_Chunk_Padding_Scan_V1"};
constexpr std::string_view TAG_GENERIC_OUTPUT_CHUNK_PADDING_CIPHERTEXT{
    "BTX_ShieldedV2_Generic_Output_Chunk_Padding_Ciphertext_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SPEND_NULLIFIER{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Spend_Nullifier_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SPEND_ACCOUNT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Spend_Account_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SPEND_SIBLING{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Spend_Sibling_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_OUTPUT_NOTE{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Output_Note_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_OUTPUT_VALUE{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Output_Value_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_OUTPUT_HINT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Output_Hint_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_OUTPUT_CIPHERTEXT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Output_Ciphertext_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LIFECYCLE_PUBKEY{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Lifecycle_PubKey_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LIFECYCLE_KEM{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Lifecycle_KEM_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LIFECYCLE_SIG{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Lifecycle_Signature_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LEAF_L2{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Leaf_L2_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LEAF_DEST{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Leaf_Destination_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LEAF_AMOUNT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Leaf_Amount_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LEAF_FEE{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Leaf_Fee_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LEAF_NONCE{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Leaf_Nonce_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_LEAF_DOMAIN{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Leaf_Domain_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_DELTA_ID{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Delta_Id_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_DIGEST{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Digest_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_NETTING_ID{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Netting_Id_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_NETTING_FLOW{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Netting_Flow_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_NETTING_AUTH{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Netting_Auth_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_SPEND_ANCHOR{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Spend_Anchor_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_REGISTRY_ANCHOR{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Registry_Anchor_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_SETTLEMENT_ANCHOR{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Settlement_Anchor_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_INGRESS_ROOT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Ingress_Root_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_L2_ROOT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_L2_Root_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_RESERVE_COMMITMENT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Reserve_Commitment_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_FEE_COMMITMENT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Fee_Commitment_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_OUTPUT_BINDING{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Output_Binding_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_EGRESS_ROOT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Egress_Root_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_SETTLEMENT_BINDING{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Settlement_Binding_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_BATCH_STATEMENT{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Batch_Statement_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_NETTING_MANIFEST{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Netting_Manifest_V1"};
constexpr std::string_view TAG_GENERIC_OPAQUE_PADDING_SCALAR_TRANSPARENT_BINDING{
    "BTX_ShieldedV2_Generic_Opaque_Padding_Scalar_Transparent_Binding_V1"};

[[nodiscard]] uint256 HashTaggedIndex(std::string_view tag, uint32_t index)
{
    HashWriter hw;
    hw << std::string{tag} << index;
    return hw.GetSHA256();
}

template <size_t Size>
[[nodiscard]] std::array<uint8_t, Size> TaggedPaddingBytes(std::string_view tag,
                                                           uint32_t index)
{
    std::array<uint8_t, Size> out{};
    size_t offset{0};
    uint32_t chunk_index{0};
    while (offset < Size) {
        const uint256 digest = HashTaggedIndex(tag, index + chunk_index);
        const size_t copy_size = std::min<size_t>(digest.size(), Size - offset);
        std::copy_n(digest.begin(), copy_size, out.begin() + static_cast<ptrdiff_t>(offset));
        offset += copy_size;
        ++chunk_index;
    }
    return out;
}

[[nodiscard]] std::vector<uint8_t> TaggedPaddingVector(std::string_view tag,
                                                       uint32_t index,
                                                       size_t size)
{
    std::vector<uint8_t> out(size);
    size_t offset{0};
    uint32_t chunk_index{0};
    while (offset < size) {
        const uint256 digest = HashTaggedIndex(tag, index + chunk_index);
        const size_t copy_size = std::min<size_t>(digest.size(), size - offset);
        std::copy_n(digest.begin(), copy_size, out.begin() + static_cast<ptrdiff_t>(offset));
        offset += copy_size;
        ++chunk_index;
    }
    return out;
}

template <typename T>
[[nodiscard]] bool ObjectsEqualBySerialization(const T& lhs, const T& rhs)
{
    DataStream lhs_stream;
    ::Serialize(lhs_stream, lhs);
    DataStream rhs_stream;
    ::Serialize(rhs_stream, rhs);
    return lhs_stream.size() == rhs_stream.size() &&
           std::equal(lhs_stream.begin(), lhs_stream.end(), rhs_stream.begin());
}

[[nodiscard]] uint256 PlaceholderScalarDigest(std::string_view tag)
{
    return HashTaggedIndex(tag, 0);
}

[[nodiscard]] GenericOpaqueSpendRecord MakeOpaquePaddingSpendRecord(uint32_t padding_index)
{
    GenericOpaqueSpendRecord record;
    record.nullifier =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_SPEND_NULLIFIER, padding_index);
    record.account_leaf_commitment =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_SPEND_ACCOUNT, padding_index);
    record.account_registry_proof.account_leaf_commitment = record.account_leaf_commitment;
    record.account_registry_proof.sibling_path = {
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_SPEND_SIBLING, padding_index)};
    record.note_commitment =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_OUTPUT_NOTE, padding_index);
    record.value_commitment =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_OUTPUT_VALUE, padding_index);
    return record;
}

[[nodiscard]] GenericOpaqueOutputRecord MakeOpaquePaddingOutputRecord(uint32_t padding_index)
{
    GenericOpaqueOutputRecord record;
    record.note_class = NoteClass::USER;
    record.scan_domain = ScanDomain::OPAQUE;
    record.note_commitment =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_OUTPUT_NOTE, padding_index);
    record.value_commitment =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_OUTPUT_VALUE, padding_index);
    record.has_smile_public_key = true;
    record.smile_public_key.public_key.assign(smile2::KEY_ROWS, {});
    record.encrypted_note.scan_domain = ScanDomain::OPAQUE;
    record.encrypted_note.scan_hint =
        TaggedPaddingBytes<SCAN_HINT_BYTES>(TAG_GENERIC_OPAQUE_PADDING_OUTPUT_HINT,
                                            padding_index);
    record.encrypted_note.ciphertext =
        TaggedPaddingVector(TAG_GENERIC_OPAQUE_PADDING_OUTPUT_CIPHERTEXT,
                            padding_index,
                            64);
    record.encrypted_note.ephemeral_key =
        ComputeLegacyPayloadEphemeralKey(record.encrypted_note.ciphertext);
    return record;
}

[[nodiscard]] LifecycleAddress MakeOpaquePaddingLifecycleAddress(uint32_t padding_index)
{
    LifecycleAddress address;
    address.version = 0x01;
    address.algo_byte = 0x00;
    address.has_kem_public_key = true;
    address.kem_public_key =
        TaggedPaddingBytes<mlkem::PUBLICKEYBYTES>(TAG_GENERIC_OPAQUE_PADDING_LIFECYCLE_KEM,
                                                  padding_index);
    address.kem_pk_hash = HashBytes(
        Span<const uint8_t>{address.kem_public_key.data(), address.kem_public_key.size()});
    return address;
}

[[nodiscard]] AddressLifecycleControl MakeOpaquePaddingLifecycleControl(uint32_t padding_index)
{
    AddressLifecycleControl control;
    control.kind = AddressLifecycleControlKind::REVOKE;
    control.output_index = 0;
    control.subject = MakeOpaquePaddingLifecycleAddress(padding_index);
    control.subject_spending_pubkey = TaggedPaddingVector(
        TAG_GENERIC_OPAQUE_PADDING_LIFECYCLE_PUBKEY,
        padding_index,
        MLDSA44_PUBKEY_SIZE);
    control.subject.pk_hash = HashBytes(Span<const uint8_t>{control.subject_spending_pubkey.data(),
                                                            control.subject_spending_pubkey.size()});
    control.signature = TaggedPaddingVector(TAG_GENERIC_OPAQUE_PADDING_LIFECYCLE_SIG,
                                            padding_index,
                                            MLDSA44_SIGNATURE_SIZE);
    return control;
}

[[nodiscard]] BatchLeaf MakeOpaquePaddingBatchLeaf(uint32_t padding_index)
{
    BatchLeaf leaf;
    leaf.family_id = TransactionFamily::V2_GENERIC;
    leaf.l2_id = HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_LEAF_L2, padding_index);
    leaf.destination_commitment =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_LEAF_DEST, padding_index);
    leaf.amount_commitment =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_LEAF_AMOUNT, padding_index);
    leaf.fee_commitment =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_LEAF_FEE, padding_index);
    leaf.position = padding_index;
    leaf.nonce = HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_LEAF_NONCE, padding_index);
    leaf.settlement_domain =
        HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_LEAF_DOMAIN, padding_index);
    return leaf;
}

[[nodiscard]] ReserveDelta MakeOpaquePaddingReserveDelta(uint32_t padding_index,
                                                         size_t padding_count)
{
    ReserveDelta delta;
    delta.l2_id = HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_DELTA_ID, padding_index);
    if (padding_count <= 1) {
        delta.reserve_delta = 1;
    } else if (padding_index + 1 < padding_count) {
        delta.reserve_delta = 1;
    } else {
        delta.reserve_delta = -static_cast<CAmount>(padding_count - 1);
    }
    return delta;
}

[[nodiscard]] uint256 MakeOpaquePaddingDigest(uint32_t padding_index)
{
    return HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_DIGEST, padding_index);
}

[[nodiscard]] NettingManifest MakeOpaquePaddingNettingManifest()
{
    NettingManifest manifest;
    manifest.settlement_window = 1;
    manifest.aggregate_net_delta = 0;
    manifest.binding_kind = SettlementBindingKind::NETTING_MANIFEST;
    manifest.gross_flow_commitment = HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_NETTING_FLOW, 0);
    manifest.authorization_digest = HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_NETTING_AUTH, 0);
    uint256 first_l2 = HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_NETTING_ID, 0);
    uint256 second_l2 = HashTaggedIndex(TAG_GENERIC_OPAQUE_PADDING_NETTING_ID, 1);
    if (second_l2 < first_l2) {
        std::swap(first_l2, second_l2);
    }
    manifest.domains = {
        NettingManifestEntry{first_l2, 1},
        NettingManifestEntry{second_l2, -1},
    };
    return manifest;
}

[[nodiscard]] bool ProofShardDescriptorEquals(const ProofShardDescriptor& lhs,
                                              const ProofShardDescriptor& rhs)
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

[[nodiscard]] ProofShardDescriptor MakeGenericProofPaddingDescriptor(uint32_t first_leaf_index,
                                                                    uint32_t proof_payload_offset,
                                                                    uint32_t padding_index)
{
    ProofShardDescriptor descriptor;
    descriptor.settlement_domain = HashTaggedIndex(TAG_GENERIC_PROOF_PADDING_DOMAIN, padding_index);
    descriptor.first_leaf_index = first_leaf_index;
    descriptor.leaf_count = 1;
    descriptor.leaf_subroot = HashTaggedIndex(TAG_GENERIC_PROOF_PADDING_LEAF, padding_index);
    descriptor.nullifier_commitment = HashTaggedIndex(TAG_GENERIC_PROOF_PADDING_NULLIFIER, padding_index);
    descriptor.value_commitment = HashTaggedIndex(TAG_GENERIC_PROOF_PADDING_VALUE, padding_index);
    descriptor.statement_digest = HashTaggedIndex(TAG_GENERIC_PROOF_PADDING_STATEMENT, padding_index);
    const uint256 metadata_digest = HashTaggedIndex(TAG_GENERIC_PROOF_PADDING_METADATA, padding_index);
    descriptor.proof_metadata.assign(metadata_digest.begin(), metadata_digest.end());
    descriptor.proof_payload_offset = proof_payload_offset;
    descriptor.proof_payload_size = 1;
    return descriptor;
}

[[nodiscard]] OutputChunkDescriptor MakeGenericOutputChunkPaddingDescriptor(uint32_t first_output_index,
                                                                           uint32_t padding_index)
{
    OutputChunkDescriptor descriptor;
    descriptor.scan_domain = ScanDomain::OPAQUE;
    descriptor.first_output_index = first_output_index;
    descriptor.output_count = 1;
    descriptor.ciphertext_bytes = 1;
    descriptor.scan_hint_commitment = HashTaggedIndex(TAG_GENERIC_OUTPUT_CHUNK_PADDING_SCAN, padding_index);
    descriptor.ciphertext_commitment =
        HashTaggedIndex(TAG_GENERIC_OUTPUT_CHUNK_PADDING_CIPHERTEXT, padding_index);
    return descriptor;
}

[[nodiscard]] bool ComputeProofShardPrefixState(Span<const ProofShardDescriptor> proof_shards,
                                                uint32_t initial_payload_offset,
                                                uint32_t& next_leaf_index,
                                                uint32_t& next_payload_offset)
{
    next_leaf_index = 0;
    next_payload_offset = initial_payload_offset;
    for (const auto& descriptor : proof_shards) {
        if (!descriptor.IsValid() ||
            descriptor.first_leaf_index != next_leaf_index ||
            descriptor.proof_payload_offset != next_payload_offset) {
            return false;
        }
        next_leaf_index += descriptor.leaf_count;
        next_payload_offset += descriptor.proof_payload_size;
    }
    return true;
}

[[nodiscard]] std::vector<ProofShardDescriptor> BuildCanonicalWireProofShards(
    Span<const ProofShardDescriptor> proof_shards,
    uint32_t payload_offset_base)
{
    std::vector<ProofShardDescriptor> padded(proof_shards.begin(), proof_shards.end());
    const size_t logical_count = padded.size();
    const size_t padded_count = CanonicalOpaqueVectorCount(logical_count, MAX_PROOF_SHARDS);
    uint32_t next_leaf_index{0};
    uint32_t next_payload_offset{0};
    if (!ComputeProofShardPrefixState({padded.data(), padded.size()},
                                      payload_offset_base,
                                      next_leaf_index,
                                      next_payload_offset)) {
        throw std::ios_base::failure("BuildCanonicalWireProofShards invalid logical proof shards");
    }
    for (size_t padding_index = 0; padded.size() < padded_count; ++padding_index) {
        padded.push_back(MakeGenericProofPaddingDescriptor(next_leaf_index,
                                                           next_payload_offset,
                                                           static_cast<uint32_t>(padding_index)));
        ++next_leaf_index;
        ++next_payload_offset;
    }
    return padded;
}

[[nodiscard]] bool StripCanonicalWireProofShardPadding(std::vector<ProofShardDescriptor>& proof_shards,
                                                       uint32_t payload_offset_base)
{
    if (proof_shards.empty() || proof_shards.size() > MAX_PROOF_SHARDS) {
        return false;
    }

    for (size_t logical_count = 0; logical_count <= proof_shards.size(); ++logical_count) {
        if (proof_shards.size() != CanonicalOpaqueVectorCount(logical_count, MAX_PROOF_SHARDS)) {
            continue;
        }
        uint32_t next_leaf_index{0};
        uint32_t next_payload_offset{0};
        if (!ComputeProofShardPrefixState({proof_shards.data(), logical_count},
                                          payload_offset_base,
                                          next_leaf_index,
                                          next_payload_offset)) {
            continue;
        }

        bool matches_padding{true};
        for (size_t pad_offset = 0; logical_count + pad_offset < proof_shards.size(); ++pad_offset) {
            const auto expected = MakeGenericProofPaddingDescriptor(
                next_leaf_index,
                next_payload_offset,
                static_cast<uint32_t>(pad_offset));
            if (!ProofShardDescriptorEquals(proof_shards[logical_count + pad_offset], expected)) {
                matches_padding = false;
                break;
            }
            ++next_leaf_index;
            ++next_payload_offset;
        }
        if (matches_padding) {
            proof_shards.resize(logical_count);
            return true;
        }
    }

    return false;
}

[[nodiscard]] std::vector<OutputChunkDescriptor> BuildCanonicalWireOutputChunks(
    Span<const OutputChunkDescriptor> output_chunks)
{
    std::vector<OutputChunkDescriptor> padded(output_chunks.begin(), output_chunks.end());
    const size_t padded_count = CanonicalOpaqueVectorCount(padded.size(), MAX_OUTPUT_CHUNKS);
    uint32_t next_output_index{0};
    for (const auto& descriptor : padded) {
        if (!descriptor.IsValid() || descriptor.first_output_index != next_output_index) {
            throw std::ios_base::failure("BuildCanonicalWireOutputChunks invalid logical output chunks");
        }
        next_output_index += descriptor.output_count;
    }
    for (size_t padding_index = 0; padded.size() < padded_count; ++padding_index) {
        padded.push_back(MakeGenericOutputChunkPaddingDescriptor(next_output_index,
                                                                 static_cast<uint32_t>(padding_index)));
        ++next_output_index;
    }
    return padded;
}

void ApplyScalarDigestPadding(uint256& value, std::string_view tag)
{
    if (value.IsNull()) {
        value = PlaceholderScalarDigest(tag);
    }
}

void StripScalarDigestPadding(uint256& value, std::string_view tag)
{
    if (value == PlaceholderScalarDigest(tag)) {
        value.SetNull();
    }
}

[[nodiscard]] bool IsPaddingNettingManifest(const NettingManifest& manifest)
{
    return ObjectsEqualBySerialization(manifest, MakeOpaquePaddingNettingManifest());
}

template <typename Stream>
void SerializeGenericOpaquePayloadWireMagic(Stream& s)
{
    s.write(AsBytes(Span<const uint8_t>{GENERIC_OPAQUE_PAYLOAD_WIRE_MAGIC.data(),
                                        GENERIC_OPAQUE_PAYLOAD_WIRE_MAGIC.size()}));
}

template <typename Stream>
void UnserializeGenericOpaquePayloadWireMagic(Stream& s)
{
    std::array<uint8_t, GENERIC_OPAQUE_PAYLOAD_WIRE_MAGIC.size()> magic{};
    s.read(AsWritableBytes(Span<uint8_t>{magic.data(), magic.size()}));
    if (magic != GENERIC_OPAQUE_PAYLOAD_WIRE_MAGIC) {
        throw std::ios_base::failure("GenericOpaquePayloadEnvelope::Unserialize invalid wire magic");
    }
}

template <typename Stream, typename T>
void SerializeOpaqueWireVector(Stream& s,
                               const std::vector<T>& values,
                               uint64_t max_size,
                               const char* error)
{
    detail::SerializeBoundedCompactSize(s, values.size(), max_size, error);
    for (const auto& value : values) {
        ::Serialize(s, value);
    }
}

template <typename Stream, typename T>
void UnserializeOpaqueWireVector(Stream& s,
                                 std::vector<T>& values,
                                 uint64_t max_size,
                                 const char* error)
{
    const uint64_t count = detail::UnserializeBoundedCompactSize(s, max_size, error);
    values.assign(count, {});
    for (auto& value : values) {
        ::Unserialize(s, value);
    }
}

[[nodiscard]] std::vector<uint8_t> SerializeGenericOpaquePayloadEnvelopeWire(
    const GenericOpaquePayloadEnvelope& padded_envelope)
{
    GenericOpaquePayloadEnvelope envelope = padded_envelope;
    if (!StripCanonicalOpaquePayloadPadding(envelope) || !envelope.IsValid()) {
        throw std::ios_base::failure("GenericOpaquePayloadEnvelope::Serialize invalid compact envelope");
    }

    DataStream ds;
    SerializeGenericOpaquePayloadWireMagic(ds);
    detail::SerializeVersion(ds, envelope.version, "GenericOpaquePayloadEnvelope::Serialize invalid version");
    ::Serialize(ds, envelope.spend_anchor);
    ::Serialize(ds, envelope.account_registry_anchor);
    ::Serialize(ds, envelope.settlement_anchor);
    ::Serialize(ds, envelope.ingress_root);
    ::Serialize(ds, envelope.l2_credit_root);
    ::Serialize(ds, envelope.aggregate_reserve_commitment);
    ::Serialize(ds, envelope.aggregate_fee_commitment);
    ::Serialize(ds, envelope.output_binding_digest);
    ::Serialize(ds, envelope.egress_root);
    ::Serialize(ds, envelope.settlement_binding_digest);
    ::Serialize(ds, envelope.batch_statement_digest);
    ::Serialize(ds, envelope.anchored_netting_manifest_id);
    ::Serialize(ds, envelope.transparent_binding_digest);
    detail::SerializeEnum(ds, static_cast<uint8_t>(envelope.output_encoding));
    detail::SerializeEnum(ds, static_cast<uint8_t>(envelope.output_note_class));
    detail::SerializeEnum(ds, static_cast<uint8_t>(envelope.output_scan_domain));
    detail::SerializeEnum(ds, static_cast<uint8_t>(envelope.reserve_output_encoding));
    ::Serialize(ds, envelope.allow_transparent_unwrap);
    ::Serialize(ds, envelope.has_netting_manifest);
    SerializeOpaqueWireVector(
        ds,
        envelope.spends,
        MAX_GENERIC_SPENDS,
        "GenericOpaquePayloadEnvelope::Serialize oversized spends");
    SerializeOpaqueWireVector(
        ds,
        envelope.outputs,
        MAX_GENERIC_OUTPUTS,
        "GenericOpaquePayloadEnvelope::Serialize oversized outputs");
    SerializeOpaqueWireVector(ds,
                              envelope.lifecycle_controls,
                              MAX_ADDRESS_LIFECYCLE_CONTROLS,
                              "GenericOpaquePayloadEnvelope::Serialize oversized lifecycle_controls");
    ::Serialize(ds, envelope.value_balance);
    ::Serialize(ds, envelope.fee);
    SerializeOpaqueWireVector(
        ds,
        envelope.ingress_leaves,
        MAX_BATCH_LEAVES,
        "GenericOpaquePayloadEnvelope::Serialize oversized ingress_leaves");
    SerializeOpaqueWireVector(
        ds,
        envelope.reserve_deltas,
        MAX_REBALANCE_DOMAINS,
        "GenericOpaquePayloadEnvelope::Serialize oversized reserve_deltas");
    if (envelope.has_netting_manifest) {
        ::Serialize(ds, envelope.netting_manifest);
    }
    SerializeOpaqueWireVector(ds,
                              envelope.imported_claim_ids,
                              MAX_SETTLEMENT_REFS,
                              "GenericOpaquePayloadEnvelope::Serialize oversized imported_claim_ids");
    SerializeOpaqueWireVector(ds,
                              envelope.imported_adapter_ids,
                              MAX_SETTLEMENT_REFS,
                              "GenericOpaquePayloadEnvelope::Serialize oversized imported_adapter_ids");
    SerializeOpaqueWireVector(ds,
                              envelope.proof_receipt_ids,
                              MAX_SETTLEMENT_REFS,
                              "GenericOpaquePayloadEnvelope::Serialize oversized proof_receipt_ids");
    SerializeOpaqueWireVector(ds,
                              envelope.batch_statement_digests,
                              MAX_SETTLEMENT_REFS,
                              "GenericOpaquePayloadEnvelope::Serialize oversized batch_statement_digests");
    const auto* begin = reinterpret_cast<const uint8_t*>(ds.data());
    return PadOpaqueBytes({begin, begin + ds.size()});
}

void ApplyCanonicalOpaquePayloadPadding(GenericOpaquePayloadEnvelope& envelope)
{
    ApplyScalarDigestPadding(envelope.spend_anchor, TAG_GENERIC_OPAQUE_PADDING_SCALAR_SPEND_ANCHOR);
    ApplyScalarDigestPadding(envelope.account_registry_anchor,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_REGISTRY_ANCHOR);
    ApplyScalarDigestPadding(envelope.settlement_anchor,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_SETTLEMENT_ANCHOR);
    ApplyScalarDigestPadding(envelope.ingress_root, TAG_GENERIC_OPAQUE_PADDING_SCALAR_INGRESS_ROOT);
    ApplyScalarDigestPadding(envelope.l2_credit_root, TAG_GENERIC_OPAQUE_PADDING_SCALAR_L2_ROOT);
    ApplyScalarDigestPadding(envelope.aggregate_reserve_commitment,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_RESERVE_COMMITMENT);
    ApplyScalarDigestPadding(envelope.aggregate_fee_commitment,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_FEE_COMMITMENT);
    ApplyScalarDigestPadding(envelope.output_binding_digest,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_OUTPUT_BINDING);
    ApplyScalarDigestPadding(envelope.egress_root, TAG_GENERIC_OPAQUE_PADDING_SCALAR_EGRESS_ROOT);
    ApplyScalarDigestPadding(envelope.settlement_binding_digest,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_SETTLEMENT_BINDING);
    ApplyScalarDigestPadding(envelope.batch_statement_digest,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_BATCH_STATEMENT);
    ApplyScalarDigestPadding(envelope.anchored_netting_manifest_id,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_NETTING_MANIFEST);
    ApplyScalarDigestPadding(envelope.transparent_binding_digest,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_TRANSPARENT_BINDING);

    envelope.output_encoding = SendOutputEncoding::LEGACY;
    envelope.output_note_class = NoteClass::USER;
    envelope.output_scan_domain = ScanDomain::OPAQUE;
    envelope.reserve_output_encoding = ReserveOutputEncoding::EXPLICIT;
    envelope.allow_transparent_unwrap = false;
    if (!envelope.has_netting_manifest) {
        envelope.netting_manifest = MakeOpaquePaddingNettingManifest();
    }
    envelope.has_netting_manifest = true;

    PadOpaqueVectorToCanonicalCount(
        envelope.spends,
        MAX_GENERIC_SPENDS,
        [](uint32_t padding_index, size_t) { return MakeOpaquePaddingSpendRecord(padding_index); });
    PadOpaqueVectorToCanonicalCount(
        envelope.outputs,
        MAX_GENERIC_OUTPUTS,
        [](uint32_t padding_index, size_t) { return MakeOpaquePaddingOutputRecord(padding_index); });
    PadOpaqueVectorToCanonicalCount(
        envelope.lifecycle_controls,
        MAX_ADDRESS_LIFECYCLE_CONTROLS,
        [](uint32_t padding_index, size_t) { return MakeOpaquePaddingLifecycleControl(padding_index); });
    PadOpaqueVectorToCanonicalCount(
        envelope.ingress_leaves,
        MAX_BATCH_LEAVES,
        [](uint32_t padding_index, size_t) { return MakeOpaquePaddingBatchLeaf(padding_index); });
    PadOpaqueVectorToCanonicalCount(
        envelope.reserve_deltas,
        MAX_REBALANCE_DOMAINS,
        [](uint32_t padding_index, size_t padding_count) {
            return MakeOpaquePaddingReserveDelta(padding_index, padding_count);
        });
    PadOpaqueVectorToCanonicalCount(
        envelope.imported_claim_ids,
        MAX_SETTLEMENT_REFS,
        [](uint32_t padding_index, size_t) { return MakeOpaquePaddingDigest(padding_index); });
    PadOpaqueVectorToCanonicalCount(
        envelope.imported_adapter_ids,
        MAX_SETTLEMENT_REFS,
        [](uint32_t padding_index, size_t) { return MakeOpaquePaddingDigest(padding_index); });
    PadOpaqueVectorToCanonicalCount(
        envelope.proof_receipt_ids,
        MAX_SETTLEMENT_REFS,
        [](uint32_t padding_index, size_t) { return MakeOpaquePaddingDigest(padding_index); });
    PadOpaqueVectorToCanonicalCount(
        envelope.batch_statement_digests,
        MAX_SETTLEMENT_REFS,
        [](uint32_t padding_index, size_t) { return MakeOpaquePaddingDigest(padding_index); });
}

[[nodiscard]] bool StripCanonicalOpaquePayloadPadding(GenericOpaquePayloadEnvelope& envelope)
{
    const bool stripped =
        StripOpaqueVectorPadding(
            envelope.spends,
            MAX_GENERIC_SPENDS,
            [](const GenericOpaqueSpendRecord& record, uint32_t padding_index, size_t) {
                return ObjectsEqualBySerialization(record, MakeOpaquePaddingSpendRecord(padding_index));
            }) &&
        StripOpaqueVectorPadding(
            envelope.outputs,
            MAX_GENERIC_OUTPUTS,
            [](const GenericOpaqueOutputRecord& record, uint32_t padding_index, size_t) {
                return ObjectsEqualBySerialization(record, MakeOpaquePaddingOutputRecord(padding_index));
            }) &&
        StripOpaqueVectorPadding(
            envelope.lifecycle_controls,
            MAX_ADDRESS_LIFECYCLE_CONTROLS,
            [](const AddressLifecycleControl& control, uint32_t padding_index, size_t) {
                return ObjectsEqualBySerialization(control,
                                                   MakeOpaquePaddingLifecycleControl(padding_index));
            }) &&
        StripOpaqueVectorPadding(
            envelope.ingress_leaves,
            MAX_BATCH_LEAVES,
            [](const BatchLeaf& leaf, uint32_t padding_index, size_t) {
                return ObjectsEqualBySerialization(leaf, MakeOpaquePaddingBatchLeaf(padding_index));
            }) &&
        StripReserveDeltaPadding(envelope.reserve_deltas) &&
        StripOpaqueVectorPadding(
            envelope.imported_claim_ids,
            MAX_SETTLEMENT_REFS,
            [](const uint256& digest, uint32_t padding_index, size_t) {
                return digest == MakeOpaquePaddingDigest(padding_index);
            }) &&
        StripOpaqueVectorPadding(
            envelope.imported_adapter_ids,
            MAX_SETTLEMENT_REFS,
            [](const uint256& digest, uint32_t padding_index, size_t) {
                return digest == MakeOpaquePaddingDigest(padding_index);
            }) &&
        StripOpaqueVectorPadding(
            envelope.proof_receipt_ids,
            MAX_SETTLEMENT_REFS,
            [](const uint256& digest, uint32_t padding_index, size_t) {
                return digest == MakeOpaquePaddingDigest(padding_index);
            }) &&
        StripOpaqueVectorPadding(
            envelope.batch_statement_digests,
            MAX_SETTLEMENT_REFS,
            [](const uint256& digest, uint32_t padding_index, size_t) {
                return digest == MakeOpaquePaddingDigest(padding_index);
            });
    if (!stripped) {
        return false;
    }

    StripScalarDigestPadding(envelope.spend_anchor, TAG_GENERIC_OPAQUE_PADDING_SCALAR_SPEND_ANCHOR);
    StripScalarDigestPadding(envelope.account_registry_anchor,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_REGISTRY_ANCHOR);
    StripScalarDigestPadding(envelope.settlement_anchor,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_SETTLEMENT_ANCHOR);
    StripScalarDigestPadding(envelope.ingress_root, TAG_GENERIC_OPAQUE_PADDING_SCALAR_INGRESS_ROOT);
    StripScalarDigestPadding(envelope.l2_credit_root, TAG_GENERIC_OPAQUE_PADDING_SCALAR_L2_ROOT);
    StripScalarDigestPadding(envelope.aggregate_reserve_commitment,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_RESERVE_COMMITMENT);
    StripScalarDigestPadding(envelope.aggregate_fee_commitment,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_FEE_COMMITMENT);
    StripScalarDigestPadding(envelope.output_binding_digest,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_OUTPUT_BINDING);
    StripScalarDigestPadding(envelope.egress_root, TAG_GENERIC_OPAQUE_PADDING_SCALAR_EGRESS_ROOT);
    StripScalarDigestPadding(envelope.settlement_binding_digest,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_SETTLEMENT_BINDING);
    StripScalarDigestPadding(envelope.batch_statement_digest,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_BATCH_STATEMENT);
    StripScalarDigestPadding(envelope.anchored_netting_manifest_id,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_NETTING_MANIFEST);
    StripScalarDigestPadding(envelope.transparent_binding_digest,
                             TAG_GENERIC_OPAQUE_PADDING_SCALAR_TRANSPARENT_BINDING);
    if (IsPaddingNettingManifest(envelope.netting_manifest)) {
        envelope.has_netting_manifest = false;
        envelope.netting_manifest = NettingManifest{};
    }
    return true;
}

[[nodiscard]] GenericOpaqueSpendRecord MakeGenericSpendRecord(const SpendDescription& spend)
{
    GenericOpaqueSpendRecord record;
    record.nullifier = spend.nullifier;
    record.account_leaf_commitment = spend.account_leaf_commitment;
    record.account_registry_proof = spend.account_registry_proof;
    record.note_commitment = spend.note_commitment;
    record.value_commitment = spend.value_commitment;
    return record;
}

[[nodiscard]] GenericOpaqueSpendRecord MakeGenericSpendRecord(const ConsumedAccountLeafSpend& spend)
{
    GenericOpaqueSpendRecord record;
    record.nullifier = spend.nullifier;
    record.account_leaf_commitment = spend.account_leaf_commitment;
    record.account_registry_proof = spend.account_registry_proof;
    return record;
}

[[nodiscard]] GenericOpaqueOutputRecord MakeGenericOutputRecord(const OutputDescription& output)
{
    GenericOpaqueOutputRecord record;
    record.note_class = output.note_class;
    record.scan_domain = output.encrypted_note.scan_domain;
    record.note_commitment = output.note_commitment;
    record.value_commitment = output.value_commitment;
    record.has_smile_account = output.smile_account.has_value();
    if (record.has_smile_account) {
        record.smile_account = *output.smile_account;
    }
    // When the compact account is present, the compact public key is derivable
    // and does not need to be duplicated in the generic opaque wire payload.
    record.has_smile_public_key =
        !record.has_smile_account && output.smile_public_key.has_value();
    if (record.has_smile_public_key) {
        record.smile_public_key = *output.smile_public_key;
    }
    record.encrypted_note = output.encrypted_note;
    return record;
}

[[nodiscard]] GenericOpaqueOutputRecord MakeGenericSendOutputRecord(const OutputDescription& output)
{
    GenericOpaqueOutputRecord record;
    record.note_class = output.note_class;
    record.scan_domain = output.encrypted_note.scan_domain;
    record.note_commitment = output.note_commitment;
    record.value_commitment = output.value_commitment;
    const auto key_data = output.smile_public_key.has_value()
        ? output.smile_public_key
        : (output.smile_account.has_value()
               ? std::make_optional(smile2::ExtractCompactPublicKeyData(*output.smile_account))
               : std::nullopt);
    if (!key_data.has_value() || !key_data->IsValid()) {
        throw std::ios_base::failure("MakeGenericSendOutputRecord missing smile public key");
    }
    record.has_smile_public_key = true;
    record.smile_public_key = *key_data;
    record.encrypted_note = output.encrypted_note;
    return record;
}

[[nodiscard]] std::optional<OutputDescription> MaterializeOutputDescription(const GenericOpaqueOutputRecord& record)
{
    if (!record.IsValid()) {
        return std::nullopt;
    }
    OutputDescription output;
    output.note_class = record.note_class;
    output.note_commitment = record.note_commitment;
    output.value_commitment = record.value_commitment;
    if (record.has_smile_account) {
        output.smile_account = record.smile_account;
    }
    if (record.has_smile_public_key) {
        output.smile_public_key = record.smile_public_key;
    } else if (record.has_smile_account) {
        output.smile_public_key = smile2::ExtractCompactPublicKeyData(record.smile_account);
    }
    output.encrypted_note = record.encrypted_note;
    return output;
}

[[nodiscard]] std::optional<NoteClass> DeriveSharedOutputNoteClass(
    Span<const OutputDescription> outputs)
{
    if (outputs.empty()) {
        return std::nullopt;
    }
    const NoteClass note_class = outputs.front().note_class;
    if (!std::all_of(outputs.begin(), outputs.end(), [note_class](const OutputDescription& output) {
            return output.note_class == note_class;
        })) {
        return std::nullopt;
    }
    return note_class;
}

[[nodiscard]] std::optional<ScanDomain> DeriveSharedOutputScanDomain(
    Span<const OutputDescription> outputs)
{
    if (outputs.empty()) {
        return std::nullopt;
    }
    const ScanDomain scan_domain = outputs.front().encrypted_note.scan_domain;
    if (!std::all_of(outputs.begin(), outputs.end(), [scan_domain](const OutputDescription& output) {
            return output.encrypted_note.scan_domain == scan_domain;
        })) {
        return std::nullopt;
    }
    return scan_domain;
}

[[nodiscard]] SendOutputEncoding DeriveGenericSendOutputEncoding(const SendPayload& payload)
{
    if (!payload.lifecycle_controls.empty() || payload.spends.empty()) {
        return SendOutputEncoding::LEGACY;
    }
    return SendOutputEncoding::SMILE_COMPACT_POSTFORK;
}

[[nodiscard]] ReserveOutputEncoding DeriveGenericIngressReserveOutputEncoding(
    const IngressBatchPayload& payload)
{
    if (!std::all_of(payload.reserve_outputs.begin(),
                     payload.reserve_outputs.end(),
                     [&](const OutputDescription& output) {
                         const uint32_t output_index =
                             static_cast<uint32_t>(&output - payload.reserve_outputs.data());
                         return output.value_commitment ==
                                ComputeV2IngressPlaceholderReserveValueCommitment(
                                    payload.settlement_binding_digest,
                                    output_index,
                                    output.note_commitment);
                     })) {
        return ReserveOutputEncoding::EXPLICIT;
    }
    return ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED;
}

[[nodiscard]] GenericOpaquePayloadEnvelope BuildGenericOpaquePayloadEnvelope(const FamilyPayload& payload)
{
    GenericOpaquePayloadEnvelope envelope;
    switch (GetPayloadFamily(payload)) {
    case TransactionFamily::V2_SEND: {
        const auto& send = std::get<SendPayload>(payload);
        envelope.spend_anchor = send.spend_anchor;
        envelope.account_registry_anchor = send.account_registry_anchor;
        envelope.output_encoding = send.output_encoding;
        envelope.output_note_class = send.output_note_class;
        envelope.output_scan_domain = send.output_scan_domain;
        envelope.lifecycle_controls = send.lifecycle_controls;
        envelope.value_balance = send.value_balance;
        envelope.fee = send.fee;
        envelope.spends.reserve(send.spends.size());
        for (const auto& spend : send.spends) {
            envelope.spends.push_back(MakeGenericSpendRecord(spend));
        }
        envelope.outputs.reserve(send.outputs.size());
        for (const auto& output : send.outputs) {
            envelope.outputs.push_back(IsCompactSendOutputEncoding(send.output_encoding)
                                           ? MakeGenericSendOutputRecord(output)
                                           : MakeGenericOutputRecord(output));
        }
        break;
    }
    case TransactionFamily::V2_LIFECYCLE: {
        const auto& lifecycle = std::get<LifecyclePayload>(payload);
        envelope.transparent_binding_digest = lifecycle.transparent_binding_digest;
        envelope.lifecycle_controls = lifecycle.lifecycle_controls;
        break;
    }
    case TransactionFamily::V2_INGRESS_BATCH: {
        const auto& ingress = std::get<IngressBatchPayload>(payload);
        envelope.spend_anchor = ingress.spend_anchor;
        envelope.account_registry_anchor = ingress.account_registry_anchor;
        envelope.ingress_root = ingress.ingress_root;
        envelope.l2_credit_root = ingress.l2_credit_root;
        envelope.aggregate_reserve_commitment = ingress.aggregate_reserve_commitment;
        envelope.aggregate_fee_commitment = ingress.aggregate_fee_commitment;
        envelope.settlement_binding_digest = ingress.settlement_binding_digest;
        envelope.reserve_output_encoding = ingress.reserve_output_encoding;
        envelope.fee = ingress.fee;
        envelope.spends.reserve(ingress.consumed_spends.size());
        for (const auto& spend : ingress.consumed_spends) {
            envelope.spends.push_back(MakeGenericSpendRecord(spend));
        }
        envelope.ingress_leaves = ingress.ingress_leaves;
        envelope.outputs.reserve(ingress.reserve_outputs.size());
        for (const auto& output : ingress.reserve_outputs) {
            envelope.outputs.push_back(MakeGenericOutputRecord(output));
        }
        break;
    }
    case TransactionFamily::V2_EGRESS_BATCH: {
        const auto& egress = std::get<EgressBatchPayload>(payload);
        envelope.settlement_anchor = egress.settlement_anchor;
        envelope.output_binding_digest = egress.output_binding_digest;
        envelope.egress_root = egress.egress_root;
        envelope.allow_transparent_unwrap = egress.allow_transparent_unwrap;
        envelope.settlement_binding_digest = egress.settlement_binding_digest;
        envelope.outputs.reserve(egress.outputs.size());
        for (const auto& output : egress.outputs) {
            envelope.outputs.push_back(MakeGenericOutputRecord(output));
        }
        break;
    }
    case TransactionFamily::V2_REBALANCE: {
        const auto& rebalance = std::get<RebalancePayload>(payload);
        envelope.settlement_binding_digest = rebalance.settlement_binding_digest;
        envelope.batch_statement_digest = rebalance.batch_statement_digest;
        envelope.has_netting_manifest = rebalance.has_netting_manifest;
        if (rebalance.has_netting_manifest) {
            envelope.netting_manifest = rebalance.netting_manifest;
        }
        envelope.reserve_deltas = rebalance.reserve_deltas;
        envelope.outputs.reserve(rebalance.reserve_outputs.size());
        for (const auto& output : rebalance.reserve_outputs) {
            envelope.outputs.push_back(MakeGenericOutputRecord(output));
        }
        break;
    }
    case TransactionFamily::V2_SETTLEMENT_ANCHOR: {
        const auto& anchor = std::get<SettlementAnchorPayload>(payload);
        envelope.imported_claim_ids = anchor.imported_claim_ids;
        envelope.imported_adapter_ids = anchor.imported_adapter_ids;
        envelope.proof_receipt_ids = anchor.proof_receipt_ids;
        envelope.batch_statement_digests = anchor.batch_statement_digests;
        envelope.reserve_deltas = anchor.reserve_deltas;
        envelope.anchored_netting_manifest_id = anchor.anchored_netting_manifest_id;
        break;
    }
    case TransactionFamily::V2_GENERIC:
        break;
    }
    ApplyCanonicalOpaquePayloadPadding(envelope);
    return envelope;
}

[[nodiscard]] bool EnvelopeUsesOnlySendSections(const GenericOpaquePayloadEnvelope& envelope)
{
    return envelope.settlement_anchor.IsNull() &&
           envelope.ingress_root.IsNull() &&
           envelope.l2_credit_root.IsNull() &&
           envelope.aggregate_reserve_commitment.IsNull() &&
           envelope.aggregate_fee_commitment.IsNull() &&
           envelope.output_binding_digest.IsNull() &&
           envelope.egress_root.IsNull() &&
           envelope.settlement_binding_digest.IsNull() &&
           envelope.batch_statement_digest.IsNull() &&
           envelope.anchored_netting_manifest_id.IsNull() &&
           envelope.transparent_binding_digest.IsNull() &&
           envelope.ingress_leaves.empty() &&
           envelope.reserve_deltas.empty() &&
           !envelope.allow_transparent_unwrap &&
           !envelope.has_netting_manifest &&
           envelope.imported_claim_ids.empty() &&
           envelope.imported_adapter_ids.empty() &&
           envelope.proof_receipt_ids.empty() &&
           envelope.batch_statement_digests.empty();
}

[[nodiscard]] bool EnvelopeUsesOnlyLifecycleSections(const GenericOpaquePayloadEnvelope& envelope)
{
    return envelope.spend_anchor.IsNull() &&
           envelope.account_registry_anchor.IsNull() &&
           envelope.settlement_anchor.IsNull() &&
           envelope.ingress_root.IsNull() &&
           envelope.l2_credit_root.IsNull() &&
           envelope.aggregate_reserve_commitment.IsNull() &&
           envelope.aggregate_fee_commitment.IsNull() &&
           envelope.output_binding_digest.IsNull() &&
           envelope.egress_root.IsNull() &&
           envelope.settlement_binding_digest.IsNull() &&
           envelope.batch_statement_digest.IsNull() &&
           envelope.anchored_netting_manifest_id.IsNull() &&
           !envelope.transparent_binding_digest.IsNull() &&
           envelope.spends.empty() &&
           envelope.outputs.empty() &&
           envelope.ingress_leaves.empty() &&
           envelope.reserve_deltas.empty() &&
           !envelope.allow_transparent_unwrap &&
           !envelope.has_netting_manifest &&
           envelope.imported_claim_ids.empty() &&
           envelope.imported_adapter_ids.empty() &&
           envelope.proof_receipt_ids.empty() &&
           envelope.batch_statement_digests.empty() &&
           envelope.value_balance == 0 &&
           envelope.fee == 0;
}

[[nodiscard]] bool EnvelopeUsesOnlyIngressSections(const GenericOpaquePayloadEnvelope& envelope)
{
    return envelope.settlement_anchor.IsNull() &&
           envelope.output_binding_digest.IsNull() &&
           envelope.egress_root.IsNull() &&
           envelope.batch_statement_digest.IsNull() &&
           envelope.anchored_netting_manifest_id.IsNull() &&
           envelope.transparent_binding_digest.IsNull() &&
           envelope.lifecycle_controls.empty() &&
           envelope.reserve_deltas.empty() &&
           !envelope.allow_transparent_unwrap &&
           !envelope.has_netting_manifest &&
           envelope.imported_claim_ids.empty() &&
           envelope.imported_adapter_ids.empty() &&
           envelope.proof_receipt_ids.empty() &&
           envelope.batch_statement_digests.empty();
}

[[nodiscard]] bool EnvelopeUsesOnlyEgressSections(const GenericOpaquePayloadEnvelope& envelope)
{
    return envelope.spend_anchor.IsNull() &&
           envelope.account_registry_anchor.IsNull() &&
           envelope.ingress_root.IsNull() &&
           envelope.l2_credit_root.IsNull() &&
           envelope.aggregate_reserve_commitment.IsNull() &&
           envelope.aggregate_fee_commitment.IsNull() &&
           envelope.batch_statement_digest.IsNull() &&
           envelope.anchored_netting_manifest_id.IsNull() &&
           envelope.transparent_binding_digest.IsNull() &&
           envelope.spends.empty() &&
           envelope.lifecycle_controls.empty() &&
           envelope.reserve_deltas.empty() &&
           envelope.ingress_leaves.empty() &&
           !envelope.has_netting_manifest &&
           envelope.imported_claim_ids.empty() &&
           envelope.imported_adapter_ids.empty() &&
           envelope.proof_receipt_ids.empty() &&
           envelope.batch_statement_digests.empty();
}

[[nodiscard]] bool EnvelopeUsesOnlyRebalanceSections(const GenericOpaquePayloadEnvelope& envelope)
{
    return envelope.spend_anchor.IsNull() &&
           envelope.account_registry_anchor.IsNull() &&
           envelope.settlement_anchor.IsNull() &&
           envelope.ingress_root.IsNull() &&
           envelope.l2_credit_root.IsNull() &&
           envelope.aggregate_reserve_commitment.IsNull() &&
           envelope.aggregate_fee_commitment.IsNull() &&
           envelope.output_binding_digest.IsNull() &&
           envelope.egress_root.IsNull() &&
           envelope.transparent_binding_digest.IsNull() &&
           envelope.spends.empty() &&
           envelope.lifecycle_controls.empty() &&
           envelope.ingress_leaves.empty() &&
           !envelope.allow_transparent_unwrap &&
           envelope.imported_claim_ids.empty() &&
           envelope.imported_adapter_ids.empty() &&
           envelope.proof_receipt_ids.empty() &&
           envelope.batch_statement_digests.empty() &&
           envelope.anchored_netting_manifest_id.IsNull();
}

[[nodiscard]] bool EnvelopeUsesOnlySettlementAnchorSections(const GenericOpaquePayloadEnvelope& envelope)
{
    return envelope.spend_anchor.IsNull() &&
           envelope.account_registry_anchor.IsNull() &&
           envelope.settlement_anchor.IsNull() &&
           envelope.ingress_root.IsNull() &&
           envelope.l2_credit_root.IsNull() &&
           envelope.aggregate_reserve_commitment.IsNull() &&
           envelope.aggregate_fee_commitment.IsNull() &&
           envelope.output_binding_digest.IsNull() &&
           envelope.egress_root.IsNull() &&
           envelope.settlement_binding_digest.IsNull() &&
           envelope.batch_statement_digest.IsNull() &&
           envelope.transparent_binding_digest.IsNull() &&
           envelope.spends.empty() &&
           envelope.outputs.empty() &&
           envelope.lifecycle_controls.empty() &&
           envelope.ingress_leaves.empty() &&
           !envelope.allow_transparent_unwrap &&
           !envelope.has_netting_manifest;
}

[[nodiscard]] std::optional<FamilyPayload> TryMaterializeGenericOpaquePayloadAs(
    const GenericOpaquePayloadEnvelope& envelope,
    TransactionFamily semantic_family)
{
    if (!envelope.IsValid()) {
        return std::nullopt;
    }

    switch (semantic_family) {
    case TransactionFamily::V2_SEND: {
        if (!EnvelopeUsesOnlySendSections(envelope)) {
            return std::nullopt;
        }
        SendPayload payload;
        payload.spend_anchor = envelope.spend_anchor;
        payload.account_registry_anchor = envelope.account_registry_anchor;
        payload.lifecycle_controls = envelope.lifecycle_controls;
        payload.value_balance = envelope.value_balance;
        payload.fee = envelope.fee;
        payload.spends.reserve(envelope.spends.size());
        for (const auto& spend_record : envelope.spends) {
            SpendDescription spend;
            spend.nullifier = spend_record.nullifier;
            spend.merkle_anchor = envelope.spend_anchor;
            spend.account_leaf_commitment = spend_record.account_leaf_commitment;
            spend.account_registry_proof = spend_record.account_registry_proof;
            spend.note_commitment = spend_record.note_commitment;
            spend.value_commitment = spend_record.value_commitment;
            payload.spends.push_back(std::move(spend));
        }
        payload.outputs.reserve(envelope.outputs.size());
        for (const auto& output_record : envelope.outputs) {
            auto output = MaterializeOutputDescription(output_record);
            if (!output.has_value()) return std::nullopt;
            payload.outputs.push_back(std::move(*output));
        }
        auto note_class = DeriveSharedOutputNoteClass(MakeSpan(payload.outputs));
        auto scan_domain = DeriveSharedOutputScanDomain(MakeSpan(payload.outputs));
        if (!note_class.has_value() || !scan_domain.has_value()) {
            return std::nullopt;
        }
        payload.output_note_class = *note_class;
        payload.output_scan_domain = *scan_domain;
        payload.output_encoding = DeriveGenericSendOutputEncoding(payload);
        if (!payload.IsValid()) {
            return std::nullopt;
        }
        return payload;
    }
    case TransactionFamily::V2_LIFECYCLE: {
        if (!EnvelopeUsesOnlyLifecycleSections(envelope)) {
            return std::nullopt;
        }
        LifecyclePayload payload;
        payload.transparent_binding_digest = envelope.transparent_binding_digest;
        payload.lifecycle_controls = envelope.lifecycle_controls;
        if (!payload.IsValid()) {
            return std::nullopt;
        }
        return payload;
    }
    case TransactionFamily::V2_INGRESS_BATCH: {
        if (!EnvelopeUsesOnlyIngressSections(envelope)) {
            return std::nullopt;
        }
        IngressBatchPayload payload;
        payload.spend_anchor = envelope.spend_anchor;
        payload.account_registry_anchor = envelope.account_registry_anchor;
        payload.ingress_root = envelope.ingress_root;
        payload.l2_credit_root = envelope.l2_credit_root;
        payload.aggregate_reserve_commitment = envelope.aggregate_reserve_commitment;
        payload.aggregate_fee_commitment = envelope.aggregate_fee_commitment;
        payload.fee = envelope.fee;
        payload.settlement_binding_digest = envelope.settlement_binding_digest;
        payload.consumed_spends.reserve(envelope.spends.size());
        for (const auto& spend_record : envelope.spends) {
            ConsumedAccountLeafSpend spend;
            spend.nullifier = spend_record.nullifier;
            spend.account_leaf_commitment = spend_record.account_leaf_commitment;
            spend.account_registry_proof = spend_record.account_registry_proof;
            payload.consumed_spends.push_back(std::move(spend));
        }
        payload.ingress_leaves = envelope.ingress_leaves;
        payload.reserve_outputs.reserve(envelope.outputs.size());
        for (const auto& output_record : envelope.outputs) {
            auto output = MaterializeOutputDescription(output_record);
            if (!output.has_value()) return std::nullopt;
            payload.reserve_outputs.push_back(std::move(*output));
        }
        payload.reserve_output_encoding = DeriveGenericIngressReserveOutputEncoding(payload);
        if (!payload.IsValid()) {
            return std::nullopt;
        }
        return payload;
    }
    case TransactionFamily::V2_EGRESS_BATCH: {
        if (!EnvelopeUsesOnlyEgressSections(envelope)) {
            return std::nullopt;
        }
        EgressBatchPayload payload;
        payload.settlement_anchor = envelope.settlement_anchor;
        payload.output_binding_digest = envelope.output_binding_digest;
        payload.egress_root = envelope.egress_root;
        payload.allow_transparent_unwrap = envelope.allow_transparent_unwrap;
        payload.settlement_binding_digest = envelope.settlement_binding_digest;
        payload.outputs.reserve(envelope.outputs.size());
        for (const auto& output_record : envelope.outputs) {
            auto output = MaterializeOutputDescription(output_record);
            if (!output.has_value()) return std::nullopt;
            payload.outputs.push_back(std::move(*output));
        }
        if (!payload.IsValid()) {
            return std::nullopt;
        }
        return payload;
    }
    case TransactionFamily::V2_REBALANCE: {
        if (!EnvelopeUsesOnlyRebalanceSections(envelope)) {
            return std::nullopt;
        }
        RebalancePayload payload;
        payload.reserve_deltas = envelope.reserve_deltas;
        payload.reserve_outputs.reserve(envelope.outputs.size());
        for (const auto& output_record : envelope.outputs) {
            auto output = MaterializeOutputDescription(output_record);
            if (!output.has_value()) return std::nullopt;
            payload.reserve_outputs.push_back(std::move(*output));
        }
        payload.settlement_binding_digest = envelope.settlement_binding_digest;
        payload.batch_statement_digest = envelope.batch_statement_digest;
        payload.has_netting_manifest = envelope.has_netting_manifest;
        if (envelope.has_netting_manifest) {
            payload.netting_manifest = envelope.netting_manifest;
        }
        if (!payload.IsValid()) {
            return std::nullopt;
        }
        return payload;
    }
    case TransactionFamily::V2_SETTLEMENT_ANCHOR: {
        if (!EnvelopeUsesOnlySettlementAnchorSections(envelope)) {
            return std::nullopt;
        }
        SettlementAnchorPayload payload;
        payload.imported_claim_ids = envelope.imported_claim_ids;
        payload.imported_adapter_ids = envelope.imported_adapter_ids;
        payload.proof_receipt_ids = envelope.proof_receipt_ids;
        payload.batch_statement_digests = envelope.batch_statement_digests;
        payload.reserve_deltas = envelope.reserve_deltas;
        payload.anchored_netting_manifest_id = envelope.anchored_netting_manifest_id;
        if (!payload.IsValid()) {
            return std::nullopt;
        }
        return payload;
    }
    case TransactionFamily::V2_GENERIC:
        return std::nullopt;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<GenericOpaquePayloadEnvelope> TryDeserializeGenericOpaquePayloadEnvelope(
    Span<const uint8_t> bytes,
    bool strip_padding)
{
    try {
        DataStream ds{std::vector<uint8_t>{bytes.begin(), bytes.end()}};
        GenericOpaquePayloadEnvelope envelope;
        UnserializeGenericOpaquePayloadWireMagic(ds);
        detail::UnserializeVersion(ds,
                                   envelope.version,
                                   "GenericOpaquePayloadEnvelope::Unserialize invalid version");
        ::Unserialize(ds, envelope.spend_anchor);
        ::Unserialize(ds, envelope.account_registry_anchor);
        ::Unserialize(ds, envelope.settlement_anchor);
        ::Unserialize(ds, envelope.ingress_root);
        ::Unserialize(ds, envelope.l2_credit_root);
        ::Unserialize(ds, envelope.aggregate_reserve_commitment);
        ::Unserialize(ds, envelope.aggregate_fee_commitment);
        ::Unserialize(ds, envelope.output_binding_digest);
        ::Unserialize(ds, envelope.egress_root);
        ::Unserialize(ds, envelope.settlement_binding_digest);
        ::Unserialize(ds, envelope.batch_statement_digest);
        ::Unserialize(ds, envelope.anchored_netting_manifest_id);
        ::Unserialize(ds, envelope.transparent_binding_digest);
        detail::UnserializeEnum(ds,
                                envelope.output_encoding,
                                IsValidSendOutputEncoding,
                                "GenericOpaquePayloadEnvelope::Unserialize invalid output_encoding");
        detail::UnserializeEnum(ds,
                                envelope.output_note_class,
                                IsValidNoteClass,
                                "GenericOpaquePayloadEnvelope::Unserialize invalid output_note_class");
        detail::UnserializeEnum(ds,
                                envelope.output_scan_domain,
                                IsValidScanDomain,
                                "GenericOpaquePayloadEnvelope::Unserialize invalid output_scan_domain");
        detail::UnserializeEnum(ds,
                                envelope.reserve_output_encoding,
                                IsValidReserveOutputEncoding,
                                "GenericOpaquePayloadEnvelope::Unserialize invalid reserve_output_encoding");
        ::Unserialize(ds, envelope.allow_transparent_unwrap);
        ::Unserialize(ds, envelope.has_netting_manifest);
        UnserializeOpaqueWireVector(ds,
                                    envelope.spends,
                                    MAX_GENERIC_SPENDS,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized spends");
        UnserializeOpaqueWireVector(ds,
                                    envelope.outputs,
                                    MAX_GENERIC_OUTPUTS,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized outputs");
        UnserializeOpaqueWireVector(ds,
                                    envelope.lifecycle_controls,
                                    MAX_ADDRESS_LIFECYCLE_CONTROLS,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized lifecycle_controls");
        ::Unserialize(ds, envelope.value_balance);
        ::Unserialize(ds, envelope.fee);
        UnserializeOpaqueWireVector(ds,
                                    envelope.ingress_leaves,
                                    MAX_BATCH_LEAVES,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized ingress_leaves");
        UnserializeOpaqueWireVector(ds,
                                    envelope.reserve_deltas,
                                    MAX_REBALANCE_DOMAINS,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized reserve_deltas");
        if (envelope.has_netting_manifest) {
            ::Unserialize(ds, envelope.netting_manifest);
        }
        UnserializeOpaqueWireVector(ds,
                                    envelope.imported_claim_ids,
                                    MAX_SETTLEMENT_REFS,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized imported_claim_ids");
        UnserializeOpaqueWireVector(ds,
                                    envelope.imported_adapter_ids,
                                    MAX_SETTLEMENT_REFS,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized imported_adapter_ids");
        UnserializeOpaqueWireVector(ds,
                                    envelope.proof_receipt_ids,
                                    MAX_SETTLEMENT_REFS,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized proof_receipt_ids");
        UnserializeOpaqueWireVector(ds,
                                    envelope.batch_statement_digests,
                                    MAX_SETTLEMENT_REFS,
                                    "GenericOpaquePayloadEnvelope::Unserialize oversized batch_statement_digests");
        if (!RemainingBytesAreZero(ds) || !envelope.IsValid()) {
            return std::nullopt;
        }
        if (!strip_padding) {
            ApplyCanonicalOpaquePayloadPadding(envelope);
        }
        return envelope;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace

std::vector<uint8_t> SerializePayloadBytes(const FamilyPayload& payload, TransactionFamily semantic_family)
{
    const auto envelope = BuildGenericOpaquePayloadEnvelope(payload);
    return SerializeGenericOpaquePayloadEnvelopeWire(envelope);
}

namespace {

[[nodiscard]] bool PayloadVariantIsValid(const FamilyPayload& payload)
{
    switch (GetPayloadFamily(payload)) {
    case TransactionFamily::V2_SEND:
        return std::get<SendPayload>(payload).IsValid();
    case TransactionFamily::V2_LIFECYCLE:
        return std::get<LifecyclePayload>(payload).IsValid();
    case TransactionFamily::V2_INGRESS_BATCH:
        return std::get<IngressBatchPayload>(payload).IsValid();
    case TransactionFamily::V2_EGRESS_BATCH:
        return std::get<EgressBatchPayload>(payload).IsValid();
    case TransactionFamily::V2_REBALANCE:
        return std::get<RebalancePayload>(payload).IsValid();
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
        return std::get<SettlementAnchorPayload>(payload).IsValid();
    case TransactionFamily::V2_GENERIC:
        return false;
    }
    return false;
}

[[nodiscard]] std::vector<TransactionFamily> CandidateFamiliesForOpaquePayload(const TransactionHeader& header)
{
    const auto& envelope = header.proof_envelope;
    switch (envelope.proof_kind) {
    case ProofKind::NONE:
        if (envelope.settlement_binding_kind == SettlementBindingKind::NONE) {
            return {TransactionFamily::V2_SEND, TransactionFamily::V2_LIFECYCLE};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::GENERIC_POSTFORK) {
            return {TransactionFamily::V2_SEND, TransactionFamily::V2_LIFECYCLE};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::GENERIC_SHIELDED) {
            return {TransactionFamily::V2_SEND};
        }
        return {};
    case ProofKind::DIRECT_MATRICT:
    case ProofKind::DIRECT_SMILE:
    case ProofKind::GENERIC_SMILE:
        if (envelope.settlement_binding_kind == SettlementBindingKind::NONE) {
            return {TransactionFamily::V2_SEND};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::GENERIC_POSTFORK) {
            return {TransactionFamily::V2_SEND};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::GENERIC_SHIELDED) {
            if (envelope.proof_kind == ProofKind::GENERIC_SMILE) {
                return {TransactionFamily::V2_SEND,
                        TransactionFamily::V2_INGRESS_BATCH,
                        TransactionFamily::V2_REBALANCE};
            }
            return {TransactionFamily::V2_SEND};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::NATIVE_BATCH) {
            return {TransactionFamily::V2_INGRESS_BATCH};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::NETTING_MANIFEST) {
            return {TransactionFamily::V2_REBALANCE};
        }
        return {};
    case ProofKind::GENERIC_OPAQUE:
        if (envelope.settlement_binding_kind == SettlementBindingKind::GENERIC_POSTFORK) {
            return {TransactionFamily::V2_SEND,
                    TransactionFamily::V2_INGRESS_BATCH,
                    TransactionFamily::V2_EGRESS_BATCH,
                    TransactionFamily::V2_REBALANCE,
                    TransactionFamily::V2_SETTLEMENT_ANCHOR};
        }
        if (IsGenericShieldedSettlementBindingKind(envelope.settlement_binding_kind)) {
            return {TransactionFamily::V2_SEND,
                    TransactionFamily::V2_INGRESS_BATCH,
                    TransactionFamily::V2_REBALANCE};
        }
        if (IsGenericBridgeSettlementBindingKind(envelope.settlement_binding_kind)) {
            return {TransactionFamily::V2_EGRESS_BATCH,
                    TransactionFamily::V2_SETTLEMENT_ANCHOR};
        }
        return {};
    case ProofKind::BATCH_MATRICT:
    case ProofKind::BATCH_SMILE:
        if (envelope.settlement_binding_kind == SettlementBindingKind::NATIVE_BATCH) {
            return {TransactionFamily::V2_INGRESS_BATCH};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::NETTING_MANIFEST) {
            return {TransactionFamily::V2_REBALANCE};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::GENERIC_SHIELDED) {
            return {TransactionFamily::V2_INGRESS_BATCH, TransactionFamily::V2_REBALANCE};
        }
        return {};
    case ProofKind::IMPORTED_RECEIPT:
    case ProofKind::GENERIC_BRIDGE:
        if (envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_RECEIPT) {
            return {TransactionFamily::V2_EGRESS_BATCH, TransactionFamily::V2_SETTLEMENT_ANCHOR};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::BRIDGE_CLAIM) {
            return {TransactionFamily::V2_SETTLEMENT_ANCHOR};
        }
        if (envelope.settlement_binding_kind == SettlementBindingKind::GENERIC_BRIDGE) {
            if (envelope.proof_kind == ProofKind::GENERIC_BRIDGE ||
                envelope.proof_kind == ProofKind::IMPORTED_RECEIPT) {
                return {TransactionFamily::V2_EGRESS_BATCH, TransactionFamily::V2_SETTLEMENT_ANCHOR};
            }
            return {TransactionFamily::V2_SETTLEMENT_ANCHOR};
        }
        return {};
    case ProofKind::IMPORTED_CLAIM:
        if (envelope.settlement_binding_kind == SettlementBindingKind::GENERIC_BRIDGE) {
            return {TransactionFamily::V2_SETTLEMENT_ANCHOR};
        }
        return {TransactionFamily::V2_SETTLEMENT_ANCHOR};
    }
    return {};
}

[[nodiscard]] std::optional<FamilyPayload> TryDeserializeOpaquePayloadAs(
    const GenericOpaquePayloadEnvelope& envelope,
    Span<const uint8_t> bytes,
    TransactionFamily semantic_family,
    const TransactionHeader& header)
{
    try {
        auto payload = TryMaterializeGenericOpaquePayloadAs(envelope, semantic_family);
        if (!payload.has_value()) {
            return std::nullopt;
        }
        if (!PayloadVariantIsValid(*payload) ||
            !ProofEnvelopeMatchesFamily(semantic_family, header.proof_envelope) ||
            ComputePayloadDigest(*payload) != header.payload_digest) {
            return std::nullopt;
        }
        if (SerializePayloadBytes(*payload, semantic_family) != std::vector<uint8_t>{bytes.begin(), bytes.end()}) {
            return std::nullopt;
        }
        return payload;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace

FamilyPayload DeserializeOpaquePayload(Span<const uint8_t> bytes, const TransactionHeader& header)
{
    auto envelope = TryDeserializeGenericOpaquePayloadEnvelope(bytes, /*strip_padding=*/true);
    if (!envelope.has_value()) {
        throw std::ios_base::failure("TransactionBundle::Unserialize invalid opaque payload");
    }
    std::optional<FamilyPayload> resolved;
    for (const TransactionFamily candidate : CandidateFamiliesForOpaquePayload(header)) {
        auto payload = TryDeserializeOpaquePayloadAs(*envelope, bytes, candidate, header);
        if (!payload.has_value()) {
            continue;
        }
        if (resolved.has_value()) {
            throw std::ios_base::failure("TransactionBundle::Unserialize ambiguous opaque payload");
        }
        resolved = std::move(payload);
    }
    if (!resolved.has_value()) {
        throw std::ios_base::failure("TransactionBundle::Unserialize invalid opaque payload");
    }
    return *resolved;
}

std::optional<GenericOpaquePayloadEnvelope> DeserializeOpaquePayloadEnvelopeWire(Span<const uint8_t> bytes,
                                                                                 bool strip_padding)
{
    return TryDeserializeGenericOpaquePayloadEnvelope(bytes, strip_padding);
}

std::vector<uint8_t> SerializeProofPayloadBytes(const TransactionBundle& bundle)
{
    if (!IsGenericTransactionFamily(bundle.header.family_id)) {
        return bundle.proof_payload;
    }
    return PadOpaqueBytes(bundle.proof_payload);
}

namespace {

[[nodiscard]] std::optional<size_t> ParseDirectWitnessPayloadSize(Span<const uint8_t> bytes,
                                                                  const TransactionHeader& header,
                                                                  const FamilyPayload& payload)
{
    DataStream ds{std::vector<uint8_t>{bytes.begin(), bytes.end()}};
    proof::V2SendWitness witness;
    try {
        ds >> witness;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!RemainingBytesAreZero(ds)) {
        return std::nullopt;
    }

    TransactionBundle bundle;
    bundle.header = header;
    bundle.payload = payload;
    const size_t consumed_size = bytes.size() - ds.size();
    bundle.proof_payload.assign(bytes.begin(), bytes.begin() + static_cast<ptrdiff_t>(consumed_size));

    std::string reject_reason;
    if (!proof::ParseV2SendWitness(bundle, reject_reason).has_value()) {
        return std::nullopt;
    }
    return consumed_size;
}

[[nodiscard]] std::optional<size_t> ParseSettlementWitnessPayloadSize(Span<const uint8_t> bytes)
{
    DataStream ds{std::vector<uint8_t>{bytes.begin(), bytes.end()}};
    proof::SettlementWitness witness;
    try {
        ds >> witness;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!RemainingBytesAreZero(ds)) {
        return std::nullopt;
    }

    const size_t consumed_size = bytes.size() - ds.size();
    std::string reject_reason;
    const std::vector<uint8_t> stripped_bytes(bytes.begin(),
                                              bytes.begin() + static_cast<ptrdiff_t>(consumed_size));
    if (!proof::ParseSettlementWitness(stripped_bytes, reject_reason).has_value()) {
        return std::nullopt;
    }
    return consumed_size;
}

[[nodiscard]] size_t ComputeUsedProofPayloadSize(Span<const ProofShardDescriptor> proof_shards)
{
    size_t used_size{0};
    for (const auto& descriptor : proof_shards) {
        used_size = std::max(used_size,
                             static_cast<size_t>(descriptor.proof_payload_offset) +
                                 static_cast<size_t>(descriptor.proof_payload_size));
    }
    return used_size;
}

} // namespace

TransactionBundleWireView BuildTransactionBundleWireView(const TransactionBundle& bundle)
{
    TransactionBundleWireView view;
    view.header = bundle.header;
    view.proof_shards = bundle.proof_shards;
    view.output_chunks = bundle.output_chunks;
    view.proof_payload = SerializeProofPayloadBytes(bundle);

    if (!IsGenericTransactionFamily(bundle.header.family_id)) {
        return view;
    }

    uint32_t proof_padding_offset_base = bundle.proof_shards.empty()
        ? 0
        : bundle.proof_shards.front().proof_payload_offset;
    if (GetPayloadFamily(bundle.payload) == TransactionFamily::V2_SEND &&
        bundle.proof_shards.empty()) {
        proof_padding_offset_base = static_cast<uint32_t>(bundle.proof_payload.size());
    }
    view.proof_shards = BuildCanonicalWireProofShards(
        Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()},
        proof_padding_offset_base);
    const size_t required_proof_bytes = ComputeUsedProofPayloadSize(
        Span<const ProofShardDescriptor>{view.proof_shards.data(), view.proof_shards.size()});
    if (bundle.proof_payload.size() > required_proof_bytes) {
        throw std::ios_base::failure("BuildTransactionBundleWireView invalid proof payload size");
    }
    std::vector<uint8_t> wire_proof_payload = bundle.proof_payload;
    wire_proof_payload.resize(required_proof_bytes, 0x00);
    view.proof_payload = PadOpaqueBytes(std::move(wire_proof_payload));
    view.header.proof_shard_count = static_cast<uint32_t>(view.proof_shards.size());
    view.header.proof_shard_root = view.proof_shards.empty()
        ? uint256::ZERO
        : ComputeProofShardRoot(Span<const ProofShardDescriptor>{view.proof_shards.data(),
                                                                 view.proof_shards.size()});

    if (UseDerivedGenericOutputChunkWire(view.header, bundle.payload)) {
        view.output_chunks = BuildCanonicalWireOutputChunks(
            Span<const OutputChunkDescriptor>{bundle.output_chunks.data(), bundle.output_chunks.size()});
        view.header.output_chunk_count = static_cast<uint32_t>(view.output_chunks.size());
        view.header.output_chunk_root = view.output_chunks.empty()
            ? uint256::ZERO
            : ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{view.output_chunks.data(),
                                                                       view.output_chunks.size()});
    }

    return view;
}

bool NormalizeGenericWireTransactionBundle(TransactionBundle& bundle,
                                          const TransactionHeader& wire_header,
                                          std::vector<ProofShardDescriptor> wire_proof_shards,
                                          uint32_t wire_output_chunk_count,
                                          std::vector<OutputChunkDescriptor> wire_output_chunks,
                                          std::vector<uint8_t> raw_proof_payload)
{
    uint32_t proof_padding_offset_base{0};
    switch (GetPayloadFamily(bundle.payload)) {
    case TransactionFamily::V2_SEND:
        if (wire_header.proof_envelope.proof_kind == ProofKind::NONE) {
            proof_padding_offset_base = 0;
        } else {
            const auto parsed_size = ParseDirectWitnessPayloadSize(
                Span<const uint8_t>{raw_proof_payload.data(), raw_proof_payload.size()},
                wire_header,
                bundle.payload);
            if (!parsed_size.has_value()) {
                return false;
            }
            proof_padding_offset_base = static_cast<uint32_t>(*parsed_size);
        }
        break;
    case TransactionFamily::V2_LIFECYCLE:
        proof_padding_offset_base = 0;
        break;
    case TransactionFamily::V2_INGRESS_BATCH:
        proof_padding_offset_base = wire_proof_shards.empty()
            ? 0
            : wire_proof_shards.front().proof_payload_offset;
        break;
    case TransactionFamily::V2_EGRESS_BATCH:
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case TransactionFamily::V2_REBALANCE:
    case TransactionFamily::V2_GENERIC:
        proof_padding_offset_base = 0;
        break;
    }

    auto semantic_proof_shards = wire_proof_shards;
    if (!StripCanonicalWireProofShardPadding(semantic_proof_shards, proof_padding_offset_base)) {
        return false;
    }

    const auto rebuilt_wire_proof_shards = BuildCanonicalWireProofShards(
        Span<const ProofShardDescriptor>{semantic_proof_shards.data(), semantic_proof_shards.size()},
        proof_padding_offset_base);
    if (rebuilt_wire_proof_shards.size() != wire_proof_shards.size() ||
        !std::equal(rebuilt_wire_proof_shards.begin(),
                    rebuilt_wire_proof_shards.end(),
                    wire_proof_shards.begin(),
                    [](const ProofShardDescriptor& lhs, const ProofShardDescriptor& rhs) {
                        return ProofShardDescriptorEquals(lhs, rhs);
                    })) {
        return false;
    }
    const uint256 expected_wire_proof_root = rebuilt_wire_proof_shards.empty()
        ? uint256::ZERO
        : ComputeProofShardRoot(Span<const ProofShardDescriptor>{rebuilt_wire_proof_shards.data(),
                                                                 rebuilt_wire_proof_shards.size()});
    if (wire_header.proof_shard_count != rebuilt_wire_proof_shards.size() ||
        wire_header.proof_shard_root != expected_wire_proof_root) {
        return false;
    }

    TransactionHeader semantic_header = wire_header;
    semantic_header.proof_shard_count = static_cast<uint32_t>(semantic_proof_shards.size());
    semantic_header.proof_shard_root = semantic_proof_shards.empty()
        ? uint256::ZERO
        : ComputeProofShardRoot(Span<const ProofShardDescriptor>{semantic_proof_shards.data(),
                                                                 semantic_proof_shards.size()});

    if (UseDerivedGenericOutputChunkWire(wire_header, bundle.payload)) {
        const auto rebuilt_wire_output_chunks = BuildCanonicalWireOutputChunks(
            Span<const OutputChunkDescriptor>{wire_output_chunks.data(), wire_output_chunks.size()});
        const uint256 expected_wire_output_root = rebuilt_wire_output_chunks.empty()
            ? uint256::ZERO
            : ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{rebuilt_wire_output_chunks.data(),
                                                                       rebuilt_wire_output_chunks.size()});
        if (wire_output_chunk_count != rebuilt_wire_output_chunks.size() ||
            wire_header.output_chunk_root != expected_wire_output_root) {
            return false;
        }
    } else {
        const uint256 expected_wire_output_root = wire_output_chunks.empty()
            ? uint256::ZERO
            : ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{wire_output_chunks.data(),
                                                                       wire_output_chunks.size()});
        if (wire_output_chunk_count != wire_output_chunks.size() ||
            wire_header.output_chunk_root != expected_wire_output_root) {
            return false;
        }
    }

    semantic_header.output_chunk_count = static_cast<uint32_t>(wire_output_chunks.size());
    semantic_header.output_chunk_root = wire_output_chunks.empty()
        ? uint256::ZERO
        : ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{wire_output_chunks.data(),
                                                                   wire_output_chunks.size()});

    const auto proof_payload = DeserializeProofPayloadBytes(
        Span<const uint8_t>{raw_proof_payload.data(), raw_proof_payload.size()},
        semantic_header,
        bundle.payload,
        Span<const ProofShardDescriptor>{semantic_proof_shards.data(), semantic_proof_shards.size()});

    bundle.header = semantic_header;
    bundle.proof_shards = std::move(semantic_proof_shards);
    bundle.output_chunks = std::move(wire_output_chunks);
    bundle.proof_payload = std::move(proof_payload);
    return true;
}

std::vector<uint8_t> DeserializeProofPayloadBytes(Span<const uint8_t> bytes,
                                                  const TransactionHeader& header,
                                                  const FamilyPayload& payload,
                                                  Span<const ProofShardDescriptor> proof_shards)
{
    std::vector<uint8_t> raw_bytes(bytes.begin(), bytes.end());
    if (!IsGenericTransactionFamily(header.family_id)) {
        return raw_bytes;
    }

    const TransactionFamily semantic_family = GetPayloadFamily(payload);
    size_t used_size{0};
    switch (semantic_family) {
    case TransactionFamily::V2_SEND:
        if (header.proof_envelope.proof_kind == ProofKind::NONE) {
            used_size = 0;
        } else {
            const auto parsed_size = ParseDirectWitnessPayloadSize(bytes, header, payload);
            if (!parsed_size.has_value()) {
                throw std::ios_base::failure("TransactionBundle::Unserialize invalid opaque proof_payload");
            }
            used_size = *parsed_size;
        }
        break;
    case TransactionFamily::V2_LIFECYCLE:
        used_size = 0;
        if (!TrailingBytesAreZero(bytes, used_size)) {
            throw std::ios_base::failure("TransactionBundle::Unserialize invalid opaque proof_payload");
        }
        break;
    case TransactionFamily::V2_EGRESS_BATCH:
    case TransactionFamily::V2_SETTLEMENT_ANCHOR: {
        const auto parsed_size = ParseSettlementWitnessPayloadSize(bytes);
        if (!parsed_size.has_value()) {
            throw std::ios_base::failure("TransactionBundle::Unserialize invalid opaque proof_payload");
        }
        used_size = *parsed_size;
        break;
    }
    case TransactionFamily::V2_INGRESS_BATCH:
    case TransactionFamily::V2_REBALANCE:
        used_size = ComputeUsedProofPayloadSize(proof_shards);
        if (!TrailingBytesAreZero(bytes, used_size)) {
            throw std::ios_base::failure("TransactionBundle::Unserialize invalid opaque proof_payload");
        }
        break;
    case TransactionFamily::V2_GENERIC:
        throw std::ios_base::failure("TransactionBundle::Unserialize invalid opaque proof_payload");
    }

    std::vector<uint8_t> stripped_bytes(bytes.begin(),
                                        bytes.begin() + static_cast<ptrdiff_t>(used_size));
    TransactionBundle bundle;
    bundle.header = header;
    bundle.payload = payload;
    bundle.proof_shards.assign(proof_shards.begin(), proof_shards.end());
    bundle.proof_payload = stripped_bytes;
    if (BuildTransactionBundleWireView(bundle).proof_payload != raw_bytes) {
        throw std::ios_base::failure("TransactionBundle::Unserialize invalid opaque proof_payload");
    }
    return stripped_bytes;
}

bool ProofShardCoverageIsCanonical(Span<const ProofShardDescriptor> proof_shards, size_t leaf_count, size_t proof_payload_size)
{
    if (proof_shards.empty()) {
        return leaf_count == 0;
    }

    size_t next_leaf_index{0};
    size_t next_payload_offset{0};
    for (const ProofShardDescriptor& descriptor : proof_shards) {
        if (!descriptor.IsValid()) return false;
        if (descriptor.leaf_count == 0 || descriptor.first_leaf_index != next_leaf_index) {
            return false;
        }
        const size_t payload_offset = descriptor.proof_payload_offset;
        const size_t payload_size = descriptor.proof_payload_size;
        if (payload_offset < next_payload_offset || payload_offset + payload_size > proof_payload_size) {
            return false;
        }
        next_leaf_index += descriptor.leaf_count;
        next_payload_offset = payload_offset + payload_size;
    }
    return next_leaf_index == leaf_count;
}

bool OutputChunkCoverageIsCanonical(Span<const OutputChunkDescriptor> output_chunks, size_t output_count)
{
    if (output_chunks.empty()) {
        return output_count == 0;
    }

    size_t next_output_index{0};
    for (const OutputChunkDescriptor& descriptor : output_chunks) {
        if (!descriptor.IsValid()) return false;
        if (descriptor.output_count == 0 || descriptor.first_output_index != next_output_index) {
            return false;
        }
        next_output_index += descriptor.output_count;
    }
    return next_output_index == output_count;
}

bool TransactionBundleOutputChunksAreCanonical(const TransactionBundle& bundle)
{
    const TransactionFamily semantic_family = GetBundleSemanticFamily(bundle);
    if (!WireFamilyMatchesPayload(bundle.header.family_id, bundle.payload) ||
        bundle.header.output_chunk_count != bundle.output_chunks.size()) {
        return false;
    }

    const uint256 expected_output_root = bundle.output_chunks.empty()
        ? uint256::ZERO
        : ComputeOutputChunkRoot(MakeSpan(bundle.output_chunks));
    if (bundle.header.output_chunk_root != expected_output_root) {
        return false;
    }

    switch (semantic_family) {
    case TransactionFamily::V2_SEND: {
        if (UseDerivedGenericOutputChunkWire(bundle.header, bundle.payload)) {
            auto derived_output_chunks = BuildDerivedGenericOutputChunks(bundle.payload);
            return derived_output_chunks.has_value() &&
                   derived_output_chunks->size() == bundle.output_chunks.size() &&
                   std::equal(bundle.output_chunks.begin(),
                              bundle.output_chunks.end(),
                              derived_output_chunks->begin(),
                              [](const OutputChunkDescriptor& lhs, const OutputChunkDescriptor& rhs) {
                                  return lhs.version == rhs.version &&
                                         lhs.scan_domain == rhs.scan_domain &&
                                         lhs.first_output_index == rhs.first_output_index &&
                                         lhs.output_count == rhs.output_count &&
                                         lhs.ciphertext_bytes == rhs.ciphertext_bytes &&
                                         lhs.scan_hint_commitment == rhs.scan_hint_commitment &&
                                         lhs.ciphertext_commitment == rhs.ciphertext_commitment;
                              });
        }
        return bundle.output_chunks.empty();
    }
    case TransactionFamily::V2_LIFECYCLE:
        return bundle.output_chunks.empty();
    case TransactionFamily::V2_INGRESS_BATCH: {
        if (UseDerivedGenericOutputChunkWire(bundle.header, bundle.payload)) {
            auto derived_output_chunks = BuildDerivedGenericOutputChunks(bundle.payload);
            return derived_output_chunks.has_value() &&
                   derived_output_chunks->size() == bundle.output_chunks.size() &&
                   std::equal(bundle.output_chunks.begin(),
                              bundle.output_chunks.end(),
                              derived_output_chunks->begin(),
                              [](const OutputChunkDescriptor& lhs, const OutputChunkDescriptor& rhs) {
                                  return lhs.version == rhs.version &&
                                         lhs.scan_domain == rhs.scan_domain &&
                                         lhs.first_output_index == rhs.first_output_index &&
                                         lhs.output_count == rhs.output_count &&
                                         lhs.ciphertext_bytes == rhs.ciphertext_bytes &&
                                         lhs.scan_hint_commitment == rhs.scan_hint_commitment &&
                                         lhs.ciphertext_commitment == rhs.ciphertext_commitment;
                              });
        }
        return bundle.output_chunks.empty();
    }
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
        return bundle.output_chunks.empty();
    case TransactionFamily::V2_EGRESS_BATCH: {
        if (UseDerivedGenericOutputChunkWire(bundle.header, bundle.payload)) {
            auto derived_output_chunks = BuildDerivedGenericOutputChunks(bundle.payload);
            return derived_output_chunks.has_value() &&
                   derived_output_chunks->size() == bundle.output_chunks.size() &&
                   std::equal(bundle.output_chunks.begin(),
                              bundle.output_chunks.end(),
                              derived_output_chunks->begin(),
                              [](const OutputChunkDescriptor& lhs, const OutputChunkDescriptor& rhs) {
                                  return lhs.version == rhs.version &&
                                         lhs.scan_domain == rhs.scan_domain &&
                                         lhs.first_output_index == rhs.first_output_index &&
                                         lhs.output_count == rhs.output_count &&
                                         lhs.ciphertext_bytes == rhs.ciphertext_bytes &&
                                         lhs.scan_hint_commitment == rhs.scan_hint_commitment &&
                                         lhs.ciphertext_commitment == rhs.ciphertext_commitment;
                              });
        }
        const auto& outputs = std::get<EgressBatchPayload>(bundle.payload).outputs;
        const Span<const OutputDescription> output_span{outputs.data(), outputs.size()};
        return OutputChunkCoverageIsCanonical(MakeSpan(bundle.output_chunks), outputs.size()) &&
               OutputChunksMatchOutputs(MakeSpan(bundle.output_chunks), output_span);
    }
    case TransactionFamily::V2_REBALANCE: {
        if (UseDerivedGenericOutputChunkWire(bundle.header, bundle.payload)) {
            auto derived_output_chunks = BuildDerivedGenericOutputChunks(bundle.payload);
            return derived_output_chunks.has_value() &&
                   derived_output_chunks->size() == bundle.output_chunks.size() &&
                   std::equal(bundle.output_chunks.begin(),
                              bundle.output_chunks.end(),
                              derived_output_chunks->begin(),
                              [](const OutputChunkDescriptor& lhs, const OutputChunkDescriptor& rhs) {
                                  return lhs.version == rhs.version &&
                                         lhs.scan_domain == rhs.scan_domain &&
                                         lhs.first_output_index == rhs.first_output_index &&
                                         lhs.output_count == rhs.output_count &&
                                         lhs.ciphertext_bytes == rhs.ciphertext_bytes &&
                                         lhs.scan_hint_commitment == rhs.scan_hint_commitment &&
                                         lhs.ciphertext_commitment == rhs.ciphertext_commitment;
                              });
        }
        const auto& outputs = std::get<RebalancePayload>(bundle.payload).reserve_outputs;
        if (bundle.output_chunks.empty()) {
            return true;
        }
        const Span<const OutputDescription> output_span{outputs.data(), outputs.size()};
        return OutputChunkCoverageIsCanonical(MakeSpan(bundle.output_chunks), outputs.size()) &&
               OutputChunksMatchOutputs(MakeSpan(bundle.output_chunks), output_span);
    }
    case TransactionFamily::V2_GENERIC:
        return false;
    }

    return false;
}

uint256 ComputeOutputChunkScanHintCommitment(Span<const OutputDescription> outputs)
{
    return ComputeOrderedRoot(outputs,
                              TAG_OUTPUT_CHUNK_SCAN_HINT_LEAF,
                              TAG_OUTPUT_CHUNK_SCAN_HINT_NODE,
                              ComputeOutputChunkScanHintLeaf);
}

uint256 ComputeOutputChunkCiphertextCommitment(Span<const OutputDescription> outputs)
{
    return ComputeOrderedRoot(outputs,
                              TAG_OUTPUT_CHUNK_CIPHERTEXT_LEAF,
                              TAG_OUTPUT_CHUNK_CIPHERTEXT_NODE,
                              ComputeOutputChunkCiphertextLeaf);
}

std::optional<OutputChunkDescriptor> BuildOutputChunkDescriptor(Span<const OutputDescription> outputs,
                                                                uint32_t first_output_index)
{
    if (outputs.empty() || !AllValid(outputs)) {
        return std::nullopt;
    }

    if (!std::all_of(outputs.begin(), outputs.end(), [](const OutputDescription& output) {
            return output.encrypted_note.scan_domain == ScanDomain::OPAQUE;
        })) {
        return std::nullopt;
    }

    const auto ciphertext_bytes = ComputeCiphertextByteCount(outputs);
    if (!ciphertext_bytes.has_value()) {
        return std::nullopt;
    }

    OutputChunkDescriptor descriptor;
    descriptor.scan_domain = ScanDomain::OPAQUE;
    descriptor.first_output_index = first_output_index;
    descriptor.output_count = outputs.size();
    descriptor.ciphertext_bytes = *ciphertext_bytes;
    descriptor.scan_hint_commitment = ComputeOutputChunkScanHintCommitment(outputs);
    descriptor.ciphertext_commitment = ComputeOutputChunkCiphertextCommitment(outputs);
    if (!descriptor.IsValid()) {
        return std::nullopt;
    }
    return descriptor;
}

bool UseDerivedGenericOutputChunkWire(const TransactionHeader& header, const FamilyPayload& payload)
{
    if (!IsGenericTransactionFamily(header.family_id)) {
        return false;
    }

    switch (GetPayloadFamily(payload)) {
    case TransactionFamily::V2_SEND:
    case TransactionFamily::V2_INGRESS_BATCH:
    case TransactionFamily::V2_EGRESS_BATCH:
    case TransactionFamily::V2_REBALANCE:
        return true;
    case TransactionFamily::V2_LIFECYCLE:
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case TransactionFamily::V2_GENERIC:
        return false;
    }
    return false;
}

std::optional<std::vector<OutputChunkDescriptor>> BuildDerivedGenericOutputChunks(const FamilyPayload& payload)
{
    std::vector<OutputChunkDescriptor> output_chunks;
    switch (GetPayloadFamily(payload)) {
    case TransactionFamily::V2_SEND: {
        const auto& outputs = std::get<SendPayload>(payload).outputs;
        if (outputs.empty()) {
            return output_chunks;
        }
        auto chunk = BuildOutputChunkDescriptor({outputs.data(), outputs.size()}, /*first_output_index=*/0);
        if (!chunk.has_value()) {
            return std::nullopt;
        }
        output_chunks.push_back(std::move(*chunk));
        return output_chunks;
    }
    case TransactionFamily::V2_LIFECYCLE:
        return output_chunks;
    case TransactionFamily::V2_INGRESS_BATCH: {
        const auto& outputs = std::get<IngressBatchPayload>(payload).reserve_outputs;
        if (outputs.empty()) {
            return output_chunks;
        }
        auto chunk = BuildOutputChunkDescriptor({outputs.data(), outputs.size()}, /*first_output_index=*/0);
        if (!chunk.has_value()) {
            return std::nullopt;
        }
        output_chunks.push_back(std::move(*chunk));
        return output_chunks;
    }
    case TransactionFamily::V2_EGRESS_BATCH: {
        const auto& outputs = std::get<EgressBatchPayload>(payload).outputs;
        auto chunk = BuildOutputChunkDescriptor({outputs.data(), outputs.size()}, /*first_output_index=*/0);
        if (!chunk.has_value()) {
            return std::nullopt;
        }
        output_chunks.push_back(std::move(*chunk));
        return output_chunks;
    }
    case TransactionFamily::V2_REBALANCE: {
        const auto& outputs = std::get<RebalancePayload>(payload).reserve_outputs;
        if (outputs.empty()) {
            return output_chunks;
        }
        auto chunk = BuildOutputChunkDescriptor({outputs.data(), outputs.size()}, /*first_output_index=*/0);
        if (!chunk.has_value()) {
            return std::nullopt;
        }
        output_chunks.push_back(std::move(*chunk));
        return output_chunks;
    }
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case TransactionFamily::V2_GENERIC:
        return output_chunks;
    }
    return std::nullopt;
}

std::optional<V2RebalanceBuildResult> BuildDeterministicV2RebalanceBundle(
    const V2RebalanceBuildInput& input,
    std::string& reject_reason,
    const Consensus::Params* consensus,
    int32_t validation_height)
{
    reject_reason.clear();

    const Span<const ReserveDelta> delta_span{input.reserve_deltas.data(), input.reserve_deltas.size()};
    if (input.reserve_deltas.size() < 2 || input.reserve_deltas.size() > MAX_REBALANCE_DOMAINS) {
        reject_reason = "bad-shielded-v2-rebalance-domain-count";
        return std::nullopt;
    }
    if (!ReserveDeltaSetIsCanonical(delta_span)) {
        reject_reason = "bad-shielded-v2-rebalance-deltas";
        return std::nullopt;
    }
    if (!input.netting_manifest.IsValid()) {
        reject_reason = "bad-shielded-v2-rebalance-manifest";
        return std::nullopt;
    }
    if (input.netting_manifest.binding_kind != SettlementBindingKind::NETTING_MANIFEST ||
        input.netting_manifest.domains.size() != input.reserve_deltas.size()) {
        reject_reason = "bad-shielded-v2-rebalance-manifest-binding";
        return std::nullopt;
    }
    for (size_t i = 0; i < input.reserve_deltas.size(); ++i) {
        if (input.netting_manifest.domains[i].l2_id != input.reserve_deltas[i].l2_id ||
            input.netting_manifest.domains[i].net_reserve_delta != input.reserve_deltas[i].reserve_delta) {
            reject_reason = "bad-shielded-v2-rebalance-manifest-domains";
            return std::nullopt;
        }
    }
    if (input.reserve_outputs.size() > MAX_BATCH_RESERVE_OUTPUTS) {
        reject_reason = "bad-shielded-v2-rebalance-outputs";
        return std::nullopt;
    }

    const uint256 manifest_id = ComputeNettingManifestId(input.netting_manifest);
    if (manifest_id.IsNull()) {
        reject_reason = "bad-shielded-v2-rebalance-manifest-id";
        return std::nullopt;
    }

    std::vector<OutputDescription> normalized_reserve_outputs = input.reserve_outputs;
    for (size_t output_index = 0; output_index < normalized_reserve_outputs.size(); ++output_index) {
        normalized_reserve_outputs[output_index].value_commitment =
            ComputeV2RebalanceOutputValueCommitment(static_cast<uint32_t>(output_index),
                                                    normalized_reserve_outputs[output_index].note_commitment);
    }
    const Span<const OutputDescription> output_span{normalized_reserve_outputs.data(), normalized_reserve_outputs.size()};
    if (!AllValid(output_span) || normalized_reserve_outputs.size() > MAX_BATCH_RESERVE_OUTPUTS) {
        reject_reason = "bad-shielded-v2-rebalance-outputs";
        return std::nullopt;
    }

    const uint256 reserve_delta_root = ComputeReserveDeltaRoot(delta_span);
    const uint256 reserve_output_root = normalized_reserve_outputs.empty()
        ? uint256::ZERO
        : ComputeOutputDescriptionRoot(output_span);
    const uint256 statement_digest =
        ComputeDeterministicRebalanceStatementDigest(manifest_id, reserve_delta_root, reserve_output_root);
    if (statement_digest.IsNull()) {
        reject_reason = "bad-shielded-v2-rebalance-statement";
        return std::nullopt;
    }

    RebalancePayload payload;
    payload.reserve_deltas = input.reserve_deltas;
    payload.reserve_outputs = std::move(normalized_reserve_outputs);
    payload.settlement_binding_digest = manifest_id;
    payload.batch_statement_digest = statement_digest;
    payload.has_netting_manifest = true;
    payload.netting_manifest = input.netting_manifest;
    if (!payload.IsValid()) {
        reject_reason = "bad-shielded-v2-rebalance-payload";
        return std::nullopt;
    }

    TransactionBundle bundle;
    bundle.header.family_id = GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_REBALANCE,
                                                                          consensus,
                                                                          validation_height);
    bundle.header.proof_envelope.proof_kind =
        GetWireProofKindForValidationHeight(TransactionFamily::V2_REBALANCE,
                                            ProofKind::BATCH_SMILE,
                                            consensus,
                                            validation_height);
    bundle.header.proof_envelope.membership_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_MEMBERSHIP,
                                                     consensus,
                                                     validation_height);
    bundle.header.proof_envelope.amount_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_BALANCE,
                                                     consensus,
                                                     validation_height);
    bundle.header.proof_envelope.balance_proof_kind =
        GetWireProofComponentKindForValidationHeight(ProofComponentKind::SMILE_BALANCE,
                                                     consensus,
                                                     validation_height);
    bundle.header.proof_envelope.settlement_binding_kind =
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_REBALANCE,
                                                        SettlementBindingKind::NETTING_MANIFEST,
                                                        consensus,
                                                        validation_height);
    bundle.header.proof_envelope.statement_digest = statement_digest;
    bundle.header.netting_manifest_version = input.netting_manifest.version;
    bundle.payload = payload;

    if (!input.reserve_outputs.empty()) {
        auto chunk = BuildOutputChunkDescriptor(output_span, /*first_output_index=*/0);
        if (!chunk.has_value()) {
            reject_reason = "bad-shielded-v2-rebalance-output-chunk";
            return std::nullopt;
        }
        bundle.output_chunks.push_back(std::move(*chunk));
    }

    uint32_t next_payload_offset{0};
    bundle.proof_shards.reserve(input.reserve_deltas.size());
    for (size_t shard_index = 0; shard_index < input.reserve_deltas.size(); ++shard_index) {
        const ReserveDelta& delta = input.reserve_deltas[shard_index];
        const auto shard_payload = SerializeDeterministicRebalanceShardPayload(delta,
                                                                               manifest_id,
                                                                               statement_digest,
                                                                               payload.settlement_binding_digest,
                                                                               reserve_output_root,
                                                                               static_cast<uint32_t>(shard_index));
        if (shard_payload.empty()) {
            reject_reason = "bad-shielded-v2-rebalance-proof-payload";
            return std::nullopt;
        }

        const uint256 shard_payload_digest = ComputeDeterministicRebalanceShardPayloadDigest(
            Span<const uint8_t>{shard_payload.data(), shard_payload.size()});

        ProofShardDescriptor descriptor;
        descriptor.settlement_domain = delta.l2_id;
        descriptor.first_leaf_index = static_cast<uint32_t>(shard_index);
        descriptor.leaf_count = 1;
        descriptor.leaf_subroot =
            ComputeDeterministicRebalanceShardLeafSubroot(delta, manifest_id, statement_digest);
        descriptor.nullifier_commitment =
            ComputeDeterministicRebalanceShardNullifierCommitment(delta, manifest_id);
        descriptor.value_commitment =
            ComputeDeterministicRebalanceShardValueCommitment(delta, reserve_output_root, shard_payload_digest);
        descriptor.statement_digest = statement_digest;
        descriptor.proof_metadata =
            ComputeDeterministicRebalanceShardMetadata(delta, manifest_id, shard_payload_digest);
        descriptor.proof_payload_offset = next_payload_offset;
        descriptor.proof_payload_size = static_cast<uint32_t>(shard_payload.size());
        if (!descriptor.IsValid()) {
            reject_reason = "bad-shielded-v2-rebalance-proof-shard";
            return std::nullopt;
        }

        next_payload_offset += descriptor.proof_payload_size;
        bundle.proof_payload.insert(bundle.proof_payload.end(), shard_payload.begin(), shard_payload.end());
        bundle.proof_shards.push_back(std::move(descriptor));
    }

    bundle.header.payload_digest = ComputeRebalancePayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot(
        Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    bundle.header.output_chunk_root = bundle.output_chunks.empty()
        ? uint256::ZERO
        : ComputeOutputChunkRoot(Span<const OutputChunkDescriptor>{bundle.output_chunks.data(),
                                                                   bundle.output_chunks.size()});
    bundle.header.output_chunk_count = bundle.output_chunks.size();

    if (!bundle.IsValid()) {
        reject_reason = "bad-shielded-v2-rebalance-bundle";
        return std::nullopt;
    }

    V2RebalanceBuildResult result;
    result.bundle = std::move(bundle);
    result.netting_manifest_id = manifest_id;
    return result;
}

bool OutputChunkMatchesOutputs(const OutputChunkDescriptor& descriptor,
                               Span<const OutputDescription> outputs)
{
    if (!descriptor.IsValid() ||
        outputs.empty() ||
        outputs.size() != descriptor.output_count ||
        !AllValid(outputs)) {
        return false;
    }

    if (descriptor.scan_domain != ScanDomain::OPAQUE ||
        !std::all_of(outputs.begin(), outputs.end(), [](const OutputDescription& output) {
            return output.encrypted_note.scan_domain == ScanDomain::OPAQUE;
        })) {
        return false;
    }

    const auto ciphertext_bytes = ComputeCiphertextByteCount(outputs);
    return ciphertext_bytes.has_value() &&
           *ciphertext_bytes == descriptor.ciphertext_bytes &&
           descriptor.scan_hint_commitment == ComputeOutputChunkScanHintCommitment(outputs) &&
           descriptor.ciphertext_commitment == ComputeOutputChunkCiphertextCommitment(outputs);
}

bool TransactionBundle::IsValid() const
{
    const TransactionFamily semantic_family = GetBundleSemanticFamily(*this);
    if (version != WIRE_VERSION ||
        !header.IsValid() ||
        !ProofEnvelopeMatchesFamily(semantic_family, header.proof_envelope) ||
        !WireFamilyMatchesPayload(header.family_id, payload) ||
        proof_shards.size() != header.proof_shard_count ||
        output_chunks.size() != header.output_chunk_count) {
        return false;
    }

    const uint256 expected_proof_root = proof_shards.empty() ? uint256::ZERO : ComputeProofShardRoot(MakeSpan(proof_shards));
    if (header.proof_shard_root != expected_proof_root ||
        !TransactionBundleOutputChunksAreCanonical(*this) ||
        proof_payload.size() > MAX_PROOF_PAYLOAD_BYTES) {
        return false;
    }

    switch (semantic_family) {
    case TransactionFamily::V2_SEND: {
        const SendPayload& send = std::get<SendPayload>(payload);
        if (!send.IsValid() ||
            !OutputsBindCanonicalSmileAccounts(MakeSpan(send.outputs)) ||
            !proof_shards.empty() ||
            header.netting_manifest_version != 0) {
            return false;
        }
        if (send.spends.empty()) {
            if (header.proof_envelope.proof_kind != ProofKind::NONE || !proof_payload.empty()) {
                return false;
            }
        } else if (header.proof_envelope.proof_kind == ProofKind::NONE ||
                   proof_payload.empty()) {
            return false;
        }
        break;
    }
    case TransactionFamily::V2_LIFECYCLE: {
        const LifecyclePayload& lifecycle = std::get<LifecyclePayload>(payload);
        if (!lifecycle.IsValid() ||
            !proof_shards.empty() ||
            !output_chunks.empty() ||
            !proof_payload.empty() ||
            header.proof_envelope.proof_kind != ProofKind::NONE ||
            header.netting_manifest_version != 0) {
            return false;
        }
        break;
    }
    case TransactionFamily::V2_INGRESS_BATCH: {
        const IngressBatchPayload& ingress = std::get<IngressBatchPayload>(payload);
        if (!ingress.IsValid() ||
            !OutputsBindCanonicalSmileAccounts(MakeSpan(ingress.reserve_outputs)) ||
            !ProofShardCoverageIsCanonical(MakeSpan(proof_shards), ingress.ingress_leaves.size(), proof_payload.size()) ||
            !ProofShardsMatchStatementDigest(MakeSpan(proof_shards), header.proof_envelope.statement_digest) ||
            header.netting_manifest_version != 0) {
            return false;
        }
        break;
    }
    case TransactionFamily::V2_EGRESS_BATCH: {
        const EgressBatchPayload& egress = std::get<EgressBatchPayload>(payload);
        if (!egress.IsValid() ||
            !OutputsBindCanonicalSmileAccounts(MakeSpan(egress.outputs)) ||
            !ProofShardCoverageIsCanonical(MakeSpan(proof_shards), 1, proof_payload.size()) ||
            !ProofShardsMatchStatementDigest(MakeSpan(proof_shards), header.proof_envelope.statement_digest) ||
            header.netting_manifest_version != 0) {
            return false;
        }
        break;
    }
    case TransactionFamily::V2_REBALANCE: {
        const RebalancePayload& rebalance = std::get<RebalancePayload>(payload);
        if (!rebalance.IsValid() ||
            !OutputsBindCanonicalSmileAccounts(MakeSpan(rebalance.reserve_outputs)) ||
            !rebalance.has_netting_manifest ||
            rebalance.batch_statement_digest != header.proof_envelope.statement_digest ||
            !ProofShardCoverageIsCanonical(MakeSpan(proof_shards), rebalance.reserve_deltas.size(), proof_payload.size()) ||
            !ProofShardsMatchStatementDigest(MakeSpan(proof_shards), header.proof_envelope.statement_digest) ||
            (!output_chunks.empty() && rebalance.reserve_outputs.empty())) {
            return false;
        }
        if (rebalance.has_netting_manifest) {
            if (header.netting_manifest_version != rebalance.netting_manifest.version ||
                (rebalance.netting_manifest.binding_kind != header.proof_envelope.settlement_binding_kind &&
                 !IsGenericShieldedSettlementBindingKind(header.proof_envelope.settlement_binding_kind))) {
                return false;
            }
        } else if (header.netting_manifest_version != 0) {
            return false;
        }
        break;
    }
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
        if (!std::get<SettlementAnchorPayload>(payload).IsValid() ||
            !ProofShardCoverageIsCanonical(MakeSpan(proof_shards), 1, proof_payload.size()) ||
            !ProofShardsMatchStatementDigest(MakeSpan(proof_shards), header.proof_envelope.statement_digest) ||
            !output_chunks.empty() ||
            !ContainsDigest(MakeSpan(std::get<SettlementAnchorPayload>(payload).batch_statement_digests),
                            header.proof_envelope.statement_digest) ||
            header.netting_manifest_version != 0) {
            return false;
        }
        break;
    case TransactionFamily::V2_GENERIC:
        return false;
    }

    try {
        return ComputePayloadDigest(payload) == header.payload_digest;
    } catch (const std::exception&) {
        return false;
    }
}

void PostProcessTransactionBundle(TransactionBundle& bundle)
{
    RehydrateDirectSendSmileAccounts(bundle);
}

uint256 ComputeSpendDescriptionHash(const SpendDescription& spend)
{
    return HashTaggedObject(TAG_SPEND_DESCRIPTION, spend);
}

uint256 ComputeSpendRoot(Span<const SpendDescription> spends)
{
    return ComputeOrderedRoot(spends, TAG_SPEND_ROOT_LEAF, TAG_SPEND_ROOT_NODE, ComputeSpendDescriptionHash);
}

uint256 ComputeOutputDescriptionHash(const OutputDescription& output)
{
    return HashTaggedObject(TAG_OUTPUT_DESCRIPTION, output);
}

uint256 ComputeOutputDescriptionRoot(Span<const OutputDescription> outputs)
{
    return ComputeOrderedRoot(outputs, TAG_OUTPUT_ROOT_LEAF, TAG_OUTPUT_ROOT_NODE, ComputeOutputDescriptionHash);
}

uint256 ComputeReserveDeltaHash(const ReserveDelta& delta)
{
    return HashTaggedObject(TAG_RESERVE_DELTA, delta);
}

uint256 ComputeReserveDeltaRoot(Span<const ReserveDelta> deltas)
{
    return ComputeOrderedRoot(deltas, TAG_RESERVE_DELTA_LEAF, TAG_RESERVE_DELTA_NODE, ComputeReserveDeltaHash);
}

uint256 ComputeSendPayloadDigest(const SendPayload& payload)
{
    return HashTaggedObject(TAG_SEND_PAYLOAD, payload);
}

uint256 ComputeLifecyclePayloadDigest(const LifecyclePayload& payload)
{
    return HashTaggedObject(TAG_LIFECYCLE_PAYLOAD, payload);
}

uint256 ComputeIngressBatchPayloadDigest(const IngressBatchPayload& payload)
{
    return HashTaggedObject(TAG_INGRESS_PAYLOAD, payload);
}

uint256 ComputeEgressBatchPayloadDigest(const EgressBatchPayload& payload)
{
    return HashTaggedObject(TAG_EGRESS_PAYLOAD, payload);
}

uint256 ComputeRebalancePayloadDigest(const RebalancePayload& payload)
{
    return HashTaggedObject(TAG_REBALANCE_PAYLOAD, payload);
}

uint256 ComputeSettlementAnchorPayloadDigest(const SettlementAnchorPayload& payload)
{
    return HashTaggedObject(TAG_SETTLEMENT_ANCHOR_PAYLOAD, payload);
}

uint256 ComputePayloadDigest(const FamilyPayload& payload)
{
    switch (GetPayloadFamily(payload)) {
    case TransactionFamily::V2_SEND:
        return ComputeSendPayloadDigest(std::get<SendPayload>(payload));
    case TransactionFamily::V2_LIFECYCLE:
        return ComputeLifecyclePayloadDigest(std::get<LifecyclePayload>(payload));
    case TransactionFamily::V2_INGRESS_BATCH:
        return ComputeIngressBatchPayloadDigest(std::get<IngressBatchPayload>(payload));
    case TransactionFamily::V2_EGRESS_BATCH:
        return ComputeEgressBatchPayloadDigest(std::get<EgressBatchPayload>(payload));
    case TransactionFamily::V2_REBALANCE:
        return ComputeRebalancePayloadDigest(std::get<RebalancePayload>(payload));
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
        return ComputeSettlementAnchorPayloadDigest(std::get<SettlementAnchorPayload>(payload));
    case TransactionFamily::V2_GENERIC:
        return uint256::ZERO;
    }
    return uint256::ZERO;
}

uint256 ComputeTransactionBundleId(const TransactionBundle& bundle)
{
    return HashTaggedObject(TAG_TRANSACTION_BUNDLE, bundle);
}

} // namespace shielded::v2
