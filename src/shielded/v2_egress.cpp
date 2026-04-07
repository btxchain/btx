// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_egress.h>

#include <hash.h>
#include <logging.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/public_account.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_send.h>
#include <serialize.h>
#include <streams.h>
#include <util/overflow.h>

#include <algorithm>
#include <array>
#include <numeric>
#include <string_view>
#include <utility>

namespace shielded::v2 {
namespace {

constexpr std::string_view TAG_EGRESS_NOTE_KEM_SEED{"BTX_ShieldedV2_Egress_Note_KemSeed_V1"};
constexpr std::string_view TAG_EGRESS_NOTE_NONCE{"BTX_ShieldedV2_Egress_Note_Nonce_V1"};

[[nodiscard]] bool HasUsableStatementFields(const BridgeBatchStatement& statement)
{
    if (statement.direction != BridgeDirection::BRIDGE_OUT ||
        !statement.ids.IsValid() ||
        statement.domain_id.IsNull() ||
        statement.source_epoch == 0 ||
        statement.data_root.IsNull()) {
        return false;
    }

    if (statement.version == 5) return statement.aggregate_commitment.IsValid();

    const uint8_t expected_version = statement.proof_policy.IsValid()
        ? (statement.verifier_set.IsValid() ? 4 : 3)
        : (statement.verifier_set.IsValid() ? 2 : 1);
    if (statement.version != expected_version) return false;
    if (statement.version < 2 && statement.verifier_set.IsValid()) return false;
    if (statement.version < 3 && statement.proof_policy.IsValid()) return false;
    return true;
}

[[nodiscard]] uint8_t ComputeOutputBindingStatementVersion(const BridgeBatchStatement& statement)
{
    return statement.proof_policy.IsValid()
        ? (statement.verifier_set.IsValid() ? 4 : 3)
        : (statement.verifier_set.IsValid() ? 2 : 1);
}

[[nodiscard]] std::optional<CAmount> SumRecipientAmounts(Span<const V2EgressRecipient> recipients)
{
    CAmount total{0};
    for (const auto& recipient : recipients) {
        if (!recipient.IsValid()) return std::nullopt;
        const auto next_total = CheckedAdd(total, recipient.amount);
        if (!next_total || !MoneyRange(*next_total)) return std::nullopt;
        total = *next_total;
    }
    return total;
}

[[nodiscard]] uint256 DeriveEgressHash(const BridgeBatchStatement& statement,
                                       std::string_view domain,
                                       uint32_t index,
                                       const V2EgressRecipient& recipient)
{
    HashWriter hw;
    hw << std::string{"BTX_ShieldedV2_Egress_V1"};
    hw << std::string{domain};
    hw << ComputeOutputBindingStatementVersion(statement);
    hw << static_cast<uint8_t>(statement.direction);
    hw << statement.ids;
    hw << statement.domain_id;
    hw << statement.source_epoch;
    hw << statement.data_root;
    if (statement.verifier_set.IsValid()) hw << statement.verifier_set;
    if (statement.proof_policy.IsValid()) hw << statement.proof_policy;
    hw << index;
    hw << recipient.recipient_pk_hash;
    hw << Span<const unsigned char>{recipient.recipient_kem_pk.data(), recipient.recipient_kem_pk.size()};
    hw << recipient.amount;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeV2EgressOutputBindingDigestImpl(const BridgeBatchStatement& statement)
{
    if (!HasUsableStatementFields(statement) ||
        statement.entry_count == 0 ||
        statement.total_amount <= 0) {
        return uint256{};
    }
    HashWriter hw;
    hw << std::string{"BTX_ShieldedV2_Egress_Output_Binding_V1"};
    hw << ComputeOutputBindingStatementVersion(statement);
    hw << static_cast<uint8_t>(statement.direction);
    hw << statement.ids;
    hw << statement.entry_count;
    hw << statement.total_amount;
    hw << statement.domain_id;
    hw << statement.source_epoch;
    hw << statement.data_root;
    if (statement.verifier_set.IsValid()) hw << statement.verifier_set;
    if (statement.proof_policy.IsValid()) hw << statement.proof_policy;
    return hw.GetSHA256();
}

template <size_t N>
[[nodiscard]] std::array<uint8_t, N> PrefixBytes(const uint256& hash)
{
    std::array<uint8_t, N> out{};
    std::copy_n(hash.begin(), N, out.begin());
    return out;
}

[[nodiscard]] bool ContainsDescriptor(Span<const BridgeProofDescriptor> descriptors,
                                      const BridgeProofDescriptor& target)
{
    return std::any_of(descriptors.begin(),
                       descriptors.end(),
                       [&](const BridgeProofDescriptor& descriptor) {
                           return descriptor.proof_system_id == target.proof_system_id &&
                                  descriptor.verifier_key_hash == target.verifier_key_hash;
                       });
}

[[nodiscard]] bool ContainsReceipt(Span<const BridgeProofReceipt> receipts,
                                   const BridgeProofReceipt& target)
{
    const uint256 target_hash = ComputeBridgeProofReceiptHash(target);
    if (target_hash.IsNull()) return false;

    return std::any_of(receipts.begin(), receipts.end(), [&](const BridgeProofReceipt& receipt) {
        return ComputeBridgeProofReceiptHash(receipt) == target_hash;
    });
}

[[nodiscard]] std::vector<uint8_t> SerializeWitness(const proof::SettlementWitness& witness)
{
    DataStream witness_stream;
    witness_stream << witness;
    if (witness_stream.empty()) return {};
    const auto* begin = reinterpret_cast<const uint8_t*>(witness_stream.data());
    return {begin, begin + witness_stream.size()};
}

[[nodiscard]] std::optional<std::vector<OutputChunkDescriptor>> BuildOutputChunks(
    Span<const OutputDescription> outputs,
    Span<const uint32_t> output_chunk_sizes)
{
    std::vector<OutputChunkDescriptor> output_chunks;
    if (outputs.empty()) return std::nullopt;

    if (output_chunk_sizes.empty()) {
        auto chunk = BuildOutputChunkDescriptor(outputs, /*first_output_index=*/0);
        if (!chunk.has_value()) return std::nullopt;
        output_chunks.push_back(std::move(*chunk));
        return output_chunks;
    }

    if (output_chunk_sizes.size() > MAX_OUTPUT_CHUNKS) return std::nullopt;

    uint64_t next_index{0};
    for (const uint32_t chunk_size : output_chunk_sizes) {
        if (chunk_size == 0) return std::nullopt;
        if (next_index + chunk_size > outputs.size()) return std::nullopt;

        auto chunk = BuildOutputChunkDescriptor(outputs.subspan(next_index, chunk_size),
                                                static_cast<uint32_t>(next_index));
        if (!chunk.has_value()) return std::nullopt;
        output_chunks.push_back(std::move(*chunk));
        next_index += chunk_size;
    }

    if (next_index != outputs.size()) return std::nullopt;
    return output_chunks;
}

} // namespace

uint256 ComputeV2EgressOutputBindingDigest(const BridgeBatchStatement& statement)
{
    return ComputeV2EgressOutputBindingDigestImpl(statement);
}

bool V2EgressRecipient::IsValid() const
{
    return !recipient_pk_hash.IsNull() &&
           std::any_of(recipient_kem_pk.begin(), recipient_kem_pk.end(), [](uint8_t byte) {
               return byte != 0;
           }) &&
           MoneyRange(amount) &&
           amount > 0;
}

bool V2EgressStatementTemplate::IsValid() const
{
    if (!ids.IsValid() || domain_id.IsNull() || source_epoch == 0 || data_root.IsNull()) {
        return false;
    }
    return (!verifier_set.IsValid() || verifier_set.version == 1) &&
           (!proof_policy.IsValid() || proof_policy.version == 1);
}

std::optional<std::vector<OutputDescription>> BuildDeterministicEgressOutputs(
    const BridgeBatchStatement& statement,
    Span<const V2EgressRecipient> recipients,
    std::string& reject_reason)
{
    reject_reason.clear();

    if (!HasUsableStatementFields(statement)) {
        reject_reason = "bad-shielded-v2-egress-derive-statement";
        return std::nullopt;
    }
    if (recipients.empty() || recipients.size() > MAX_EGRESS_OUTPUTS) {
        reject_reason = "bad-shielded-v2-egress-derive-recipient-count";
        return std::nullopt;
    }

    const auto total_amount = SumRecipientAmounts(recipients);
    if (!total_amount.has_value()) {
        reject_reason = "bad-shielded-v2-egress-derive-recipient-amount";
        return std::nullopt;
    }
    if (statement.entry_count != 0 && statement.entry_count != recipients.size()) {
        reject_reason = "bad-shielded-v2-egress-derive-entry-count";
        return std::nullopt;
    }
    if (statement.total_amount != 0 && statement.total_amount != *total_amount) {
        reject_reason = "bad-shielded-v2-egress-derive-total-amount";
        return std::nullopt;
    }

    std::vector<OutputDescription> outputs;
    outputs.reserve(recipients.size());
    const uint256 output_binding_digest = ::shielded::v2::ComputeV2EgressOutputBindingDigest(statement);
    if (output_binding_digest.IsNull()) {
        reject_reason = "bad-shielded-v2-egress-derive-binding";
        return std::nullopt;
    }
    for (size_t i = 0; i < recipients.size(); ++i) {
        const auto& recipient = recipients[i];
        const uint32_t index = static_cast<uint32_t>(i);

        ShieldedNote note_template;
        note_template.value = recipient.amount;
        note_template.recipient_pk_hash = recipient.recipient_pk_hash;
        if (note_template.value <= 0 || !MoneyRange(note_template.value) || note_template.recipient_pk_hash.IsNull()) {
            reject_reason = "bad-shielded-v2-egress-derive-note-template";
            return std::nullopt;
        }

        const auto kem_seed = PrefixBytes<mlkem::ENCAPS_SEEDBYTES>(
            DeriveEgressHash(statement, TAG_EGRESS_NOTE_KEM_SEED, index, recipient));
        const auto nonce = PrefixBytes<12>(
            DeriveEgressHash(statement, TAG_EGRESS_NOTE_NONCE, index, recipient));
        const auto bound_note = shielded::NoteEncryption::EncryptBoundNoteDeterministic(
            note_template, recipient.recipient_kem_pk, kem_seed, nonce);
        const ShieldedNote& note = bound_note.note;
        const shielded::EncryptedNote& encrypted_note = bound_note.encrypted_note;
        const auto payload = EncodeLegacyEncryptedNotePayload(encrypted_note,
                                                              recipient.recipient_kem_pk,
                                                              ScanDomain::BATCH);
        if (!payload.has_value()) {
            reject_reason = "bad-shielded-v2-egress-derive-payload";
            return std::nullopt;
        }

        OutputDescription output;
        output.note_class = NoteClass::USER;
        auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            note);
        if (!smile_account.has_value()) {
            reject_reason = "bad-shielded-v2-egress-derive-smile-account";
            return std::nullopt;
        }
        output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        output.value_commitment = ComputeV2EgressOutputValueCommitment(output_binding_digest,
                                                                       index,
                                                                       output.note_commitment);
        output.smile_account = std::move(*smile_account);
        output.encrypted_note = *payload;
        if (!output.IsValid()) {
            reject_reason = "bad-shielded-v2-egress-derive-output";
            return std::nullopt;
        }
        outputs.push_back(std::move(output));
    }

    const uint256 output_root = ComputeOutputDescriptionRoot(
        Span<const OutputDescription>{outputs.data(), outputs.size()});
    if (output_root.IsNull()) {
        reject_reason = "bad-shielded-v2-egress-derive-root";
        return std::nullopt;
    }
    if (!statement.batch_root.IsNull() && statement.batch_root != output_root) {
        reject_reason = "bad-shielded-v2-egress-derive-root-mismatch";
        return std::nullopt;
    }
    return outputs;
}

std::optional<BridgeBatchStatement> BuildV2EgressStatement(
    const V2EgressStatementTemplate& statement_template,
    Span<const V2EgressRecipient> recipients,
    std::string& reject_reason)
{
    reject_reason.clear();

    if (!statement_template.IsValid()) {
        reject_reason = "bad-shielded-v2-egress-statement-template";
        return std::nullopt;
    }
    const auto total_amount = SumRecipientAmounts(recipients);
    if (recipients.empty() || recipients.size() > MAX_EGRESS_OUTPUTS || !total_amount.has_value()) {
        reject_reason = "bad-shielded-v2-egress-statement-recipients";
        return std::nullopt;
    }

    BridgeBatchStatement statement;
    statement.direction = BridgeDirection::BRIDGE_OUT;
    statement.ids = statement_template.ids;
    statement.entry_count = static_cast<uint32_t>(recipients.size());
    statement.total_amount = *total_amount;
    statement.domain_id = statement_template.domain_id;
    statement.source_epoch = statement_template.source_epoch;
    statement.data_root = statement_template.data_root;
    statement.verifier_set = statement_template.verifier_set;
    statement.proof_policy = statement_template.proof_policy;
    statement.version = statement.proof_policy.IsValid()
        ? (statement.verifier_set.IsValid() ? 4 : 3)
        : (statement.verifier_set.IsValid() ? 2 : 1);

    auto outputs = BuildDeterministicEgressOutputs(statement, recipients, reject_reason);
    if (!outputs.has_value()) return std::nullopt;

    statement.batch_root = ComputeOutputDescriptionRoot(
        Span<const OutputDescription>{outputs->data(), outputs->size()});
    const auto aggregate_commitment = BuildDefaultBridgeBatchAggregateCommitment(statement.batch_root,
                                                                                 statement.data_root,
                                                                                 statement.proof_policy);
    if (!aggregate_commitment.has_value()) {
        reject_reason = "bad-shielded-v2-egress-statement";
        return std::nullopt;
    }
    statement.aggregate_commitment = *aggregate_commitment;
    statement.version = 5;
    if (!statement.IsValid()) {
        reject_reason = "bad-shielded-v2-egress-statement";
        return std::nullopt;
    }
    return statement;
}

bool V2EgressBuildInput::IsValid() const
{
    if (!statement.IsValid() ||
        statement.direction != BridgeDirection::BRIDGE_OUT ||
        allow_transparent_unwrap ||
        proof_descriptors.empty() ||
        !imported_descriptor.IsValid() ||
        proof_receipts.empty() ||
        !imported_receipt.IsValid() ||
        outputs.empty() ||
        outputs.size() > MAX_EGRESS_OUTPUTS) {
        return false;
    }

    if (signed_receipts.size() != signed_receipt_proofs.size()) return false;
    if (!statement.verifier_set.IsValid() &&
        (!signed_receipts.empty() || !signed_receipt_proofs.empty())) {
        return false;
    }

    if (!ContainsDescriptor(proof_descriptors, imported_descriptor) ||
        !ContainsReceipt(proof_receipts, imported_receipt)) {
        return false;
    }

    if (!std::all_of(outputs.begin(), outputs.end(), [](const OutputDescription& output) {
            return output.IsValid();
        })) {
        return false;
    }

    if (!output_chunk_sizes.empty()) {
        if (output_chunk_sizes.size() > MAX_OUTPUT_CHUNKS) return false;
        const uint64_t output_total = std::accumulate(output_chunk_sizes.begin(),
                                                      output_chunk_sizes.end(),
                                                      uint64_t{0});
        if (output_total != outputs.size()) return false;
        if (std::any_of(output_chunk_sizes.begin(), output_chunk_sizes.end(), [](uint32_t count) {
                return count == 0;
            })) {
            return false;
        }
    }

    return true;
}

bool V2EgressBuildResult::IsValid() const
{
    if (!tx.shielded_bundle.HasV2Bundle()) return false;
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr ||
        !BundleHasSemanticFamily(*bundle, TransactionFamily::V2_EGRESS_BATCH) ||
        !std::holds_alternative<EgressBatchPayload>(bundle->payload)) {
        return false;
    }

    return witness.IsValid();
}

std::optional<V2EgressBuildResult> BuildV2EgressBatchTransaction(const CMutableTransaction& tx_template,
                                                                 const V2EgressBuildInput& input,
                                                                 std::string& reject_reason,
                                                                 const Consensus::Params* consensus,
                                                                 int32_t validation_height)
{
    reject_reason.clear();

    if (tx_template.HasShieldedBundle()) {
        reject_reason = "bad-shielded-v2-egress-builder-existing-bundle";
        return std::nullopt;
    }
    if (!tx_template.vin.empty() || !tx_template.vout.empty()) {
        reject_reason = "bad-shielded-v2-egress-builder-transparent";
        return std::nullopt;
    }
    if (!input.IsValid()) {
        reject_reason = "bad-shielded-v2-egress-builder-input";
        return std::nullopt;
    }

    const uint256 egress_root = ComputeOutputDescriptionRoot(
        Span<const OutputDescription>{input.outputs.data(), input.outputs.size()});
    if (egress_root.IsNull() ||
        egress_root != input.statement.batch_root ||
        input.statement.entry_count != input.outputs.size()) {
        reject_reason = "bad-shielded-v2-egress-builder-outputs";
        return std::nullopt;
    }

    auto descriptor_proof = BuildBridgeProofPolicyProof(
        Span<const BridgeProofDescriptor>{input.proof_descriptors.data(), input.proof_descriptors.size()},
        input.imported_descriptor);
    if (!descriptor_proof.has_value()) {
        reject_reason = "bad-shielded-v2-egress-builder-descriptor";
        return std::nullopt;
    }

    proof::SettlementWitness witness;
    witness.statement = input.statement;
    witness.signed_receipts = input.signed_receipts;
    witness.signed_receipt_proofs = input.signed_receipt_proofs;
    witness.proof_receipts = input.proof_receipts;
    witness.descriptor_proof = std::move(*descriptor_proof);
    if (!witness.IsValid()) {
        reject_reason = "bad-shielded-v2-egress-builder-witness";
        return std::nullopt;
    }

    std::vector<uint8_t> proof_payload = SerializeWitness(witness);
    std::optional<BridgeVerificationBundle> verification_bundle;
    if (input.statement.verifier_set.IsValid()) {
        verification_bundle = BuildBridgeVerificationBundle(
            Span<const BridgeBatchReceipt>{input.signed_receipts.data(), input.signed_receipts.size()},
            Span<const BridgeProofReceipt>{input.proof_receipts.data(), input.proof_receipts.size()});
        if (!verification_bundle.has_value()) {
            reject_reason = "bad-shielded-v2-egress-builder-verification-bundle";
            return std::nullopt;
        }
    }
    auto wire_context =
        consensus != nullptr
            ? proof::DescribeImportedSettlementReceipt(input.imported_receipt,
                                                       proof::PayloadLocation::INLINE_WITNESS,
                                                       proof_payload,
                                                       *consensus,
                                                       validation_height,
                                                       input.imported_descriptor,
                                                       verification_bundle)
            : proof::DescribeImportedSettlementReceipt(input.imported_receipt,
                                                       proof::PayloadLocation::INLINE_WITNESS,
                                                       proof_payload,
                                                       input.imported_descriptor,
                                                       verification_bundle);

    std::optional<BridgeExternalAnchor> settlement_anchor;
    if (verification_bundle.has_value()) {
        settlement_anchor = BuildBridgeExternalAnchorFromHybridWitness(
            input.statement,
            Span<const BridgeBatchReceipt>{input.signed_receipts.data(), input.signed_receipts.size()},
            Span<const BridgeProofReceipt>{input.proof_receipts.data(), input.proof_receipts.size()});
    } else {
        settlement_anchor = BuildBridgeExternalAnchorFromProofReceipts(
            input.statement,
            Span<const BridgeProofReceipt>{input.proof_receipts.data(), input.proof_receipts.size()});
    }
    if (!settlement_anchor.has_value()) {
        reject_reason = "bad-shielded-v2-egress-builder-anchor";
        return std::nullopt;
    }

    const bool use_generic_wire = shielded::v2::UseGenericV2WireFamily(consensus, validation_height);
    if (use_generic_wire && !input.output_chunk_sizes.empty()) {
        reject_reason = "bad-shielded-v2-egress-builder-chunks";
        return std::nullopt;
    }

    const Span<const uint32_t> output_chunk_sizes = use_generic_wire
        ? Span<const uint32_t>{}
        : Span<const uint32_t>{input.output_chunk_sizes.data(), input.output_chunk_sizes.size()};
    auto output_chunks = BuildOutputChunks(
        Span<const OutputDescription>{input.outputs.data(), input.outputs.size()},
        output_chunk_sizes);
    if (!output_chunks.has_value()) {
        reject_reason = "bad-shielded-v2-egress-builder-chunks";
        return std::nullopt;
    }

    EgressBatchPayload payload;
    payload.settlement_anchor = proof::ComputeSettlementExternalAnchorDigest(*settlement_anchor);
    payload.egress_root = egress_root;
    payload.output_binding_digest = ::shielded::v2::ComputeV2EgressOutputBindingDigest(input.statement);
    payload.outputs = input.outputs;
    payload.allow_transparent_unwrap = false;
    payload.settlement_binding_digest = ComputeBridgeProofReceiptHash(input.imported_receipt);
    if (!payload.IsValid()) {
        reject_reason = "bad-shielded-v2-egress-builder-payload";
        return std::nullopt;
    }

    TransactionBundle bundle;
    bundle.header.family_id = GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_EGRESS_BATCH,
                                                                          consensus,
                                                                          validation_height);
    bundle.header.proof_envelope = wire_context.material.statement.envelope;
    bundle.payload = payload;
    bundle.proof_payload = std::move(proof_payload);
    bundle.proof_shards = wire_context.material.proof_shards;
    for (auto& proof_shard : bundle.proof_shards) {
        proof_shard.settlement_domain = input.statement.domain_id;
    }
    bundle.output_chunks = std::move(*output_chunks);
    bundle.header.payload_digest = ComputeEgressBatchPayloadDigest(payload);
    bundle.header.proof_shard_root = ComputeProofShardRoot(
        Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()});
    bundle.header.proof_shard_count = bundle.proof_shards.size();
    bundle.header.output_chunk_root = ComputeOutputChunkRoot(
        Span<const OutputChunkDescriptor>{bundle.output_chunks.data(), bundle.output_chunks.size()});
    bundle.header.output_chunk_count = bundle.output_chunks.size();

    const auto validate_bundle = [&bundle]() -> const char* {
        if (bundle.version != WIRE_VERSION) {
            return "bad-shielded-v2-egress-builder-bundle-version";
        }
        if (!bundle.header.IsValid()) {
            return "bad-shielded-v2-egress-builder-bundle-header";
        }
        if (!WireFamilyMatchesPayload(bundle.header.family_id, bundle.payload)) {
            return "bad-shielded-v2-egress-builder-bundle-wire-family";
        }
        if (bundle.proof_shards.size() != bundle.header.proof_shard_count) {
            return "bad-shielded-v2-egress-builder-bundle-proof-shard-count";
        }
        if (bundle.output_chunks.size() != bundle.header.output_chunk_count) {
            return "bad-shielded-v2-egress-builder-bundle-output-chunk-count";
        }
        const uint256 expected_proof_root = bundle.proof_shards.empty()
            ? uint256::ZERO
            : ComputeProofShardRoot(Span<const ProofShardDescriptor>{bundle.proof_shards.data(),
                                                                     bundle.proof_shards.size()});
        if (bundle.header.proof_shard_root != expected_proof_root) {
            return "bad-shielded-v2-egress-builder-bundle-proof-shard-root";
        }
        if (!TransactionBundleOutputChunksAreCanonical(bundle)) {
            return "bad-shielded-v2-egress-builder-bundle-output-chunks";
        }
        if (bundle.proof_payload.size() > MAX_PROOF_PAYLOAD_BYTES) {
            return "bad-shielded-v2-egress-builder-bundle-proof-payload";
        }
        const auto& egress = std::get<EgressBatchPayload>(bundle.payload);
        if (!egress.IsValid()) {
            return "bad-shielded-v2-egress-builder-bundle-payload";
        }
        if (!ProofShardCoverageIsCanonical(
                Span<const ProofShardDescriptor>{bundle.proof_shards.data(), bundle.proof_shards.size()},
                /*leaf_count=*/1,
                bundle.proof_payload.size())) {
            return "bad-shielded-v2-egress-builder-bundle-proof-shard-coverage";
        }
        if (bundle.header.netting_manifest_version != 0) {
            return "bad-shielded-v2-egress-builder-bundle-netting-version";
        }
        return nullptr;
    };

    if (const char* invalid_reason = validate_bundle()) {
        reject_reason = invalid_reason;
        return std::nullopt;
    }

    auto parsed_receipt =
        proof::ParseImportedSettlementReceipt(bundle.header.proof_envelope, bundle.proof_shards.front(), reject_reason);
    if (!parsed_receipt.has_value()) {
        return std::nullopt;
    }
    auto parsed_witness = proof::ParseSettlementWitness(bundle.proof_payload, reject_reason);
    if (!parsed_witness.has_value()) {
        return std::nullopt;
    }

    proof::SettlementContext verified_context;
    verified_context.material.statement.domain = proof::VerificationDomain::BATCH_SETTLEMENT;
    verified_context.material.statement.envelope = bundle.header.proof_envelope;
    verified_context.material.payload_location = proof::PayloadLocation::INLINE_WITNESS;
    verified_context.material.proof_shards = bundle.proof_shards;
    verified_context.material.proof_payload = bundle.proof_payload;
    verified_context.imported_receipt = *parsed_receipt;
    verified_context.descriptor =
        BridgeProofDescriptor{parsed_receipt->proof_system_id, parsed_receipt->verifier_key_hash};
    if (parsed_witness->statement.verifier_set.IsValid() ||
        !parsed_witness->signed_receipts.empty() ||
        !parsed_witness->signed_receipt_proofs.empty()) {
        verified_context.verification_bundle = BuildBridgeVerificationBundle(
            Span<const BridgeBatchReceipt>{parsed_witness->signed_receipts.data(), parsed_witness->signed_receipts.size()},
            Span<const BridgeProofReceipt>{parsed_witness->proof_receipts.data(), parsed_witness->proof_receipts.size()});
        if (!verified_context.verification_bundle.has_value()) {
            reject_reason = "bad-v2-settlement-verification-bundle";
            return std::nullopt;
        }
    }

    if (!verified_context.IsValid()) {
        if (!verified_context.material.statement.IsValid()) {
            reject_reason = "bad-shielded-v2-egress-builder-context-statement";
        } else if (!verified_context.material.IsValid(/*leaf_count=*/1)) {
            reject_reason = "bad-shielded-v2-egress-builder-context-material";
        } else if (!verified_context.imported_receipt.has_value() || verified_context.imported_claim.has_value()) {
            reject_reason = "bad-shielded-v2-egress-builder-context-import";
        } else if (!verified_context.imported_receipt->IsValid()) {
            reject_reason = "bad-shielded-v2-egress-builder-context-receipt";
        } else if (verified_context.material.statement.envelope.statement_digest !=
                   verified_context.imported_receipt->statement_hash) {
            reject_reason = "bad-shielded-v2-egress-builder-context-statement-digest";
        } else if (verified_context.material.statement.envelope.settlement_binding_kind !=
                       SettlementBindingKind::BRIDGE_RECEIPT &&
                   !shielded::v2::IsGenericBridgeSettlementBindingKind(
                       verified_context.material.statement.envelope.settlement_binding_kind)) {
            reject_reason = "bad-shielded-v2-egress-builder-context-binding";
        } else if (verified_context.material.statement.envelope.proof_kind != ProofKind::IMPORTED_RECEIPT &&
                   verified_context.material.statement.envelope.proof_kind != ProofKind::GENERIC_BRIDGE &&
                   verified_context.material.statement.envelope.proof_kind != ProofKind::GENERIC_OPAQUE) {
            reject_reason = "bad-shielded-v2-egress-builder-context-proof-kind";
        } else if (!verified_context.descriptor.has_value() ||
                   verified_context.descriptor->proof_system_id != verified_context.imported_receipt->proof_system_id ||
                   verified_context.descriptor->verifier_key_hash != verified_context.imported_receipt->verifier_key_hash) {
            reject_reason = "bad-shielded-v2-egress-builder-context-descriptor";
        } else {
            reject_reason = "bad-shielded-v2-egress-builder-context";
        }
        return std::nullopt;
    }
    if (!proof::VerifySettlementContext(verified_context, *parsed_witness, reject_reason)) {
        return std::nullopt;
    }

    V2EgressBuildResult result;
    result.tx = tx_template;
    result.tx.shielded_bundle.v2_bundle = std::move(bundle);
    result.witness = std::move(*parsed_witness);
    return result;
}

} // namespace shielded::v2
