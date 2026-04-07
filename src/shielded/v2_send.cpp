// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_send.h>

#include <consensus/amount.h>
#include <hash.h>
#include <serialize.h>
#include <shielded/lattice/params.h>
#include <shielded/smile2/verify_dispatch.h>
#include <streams.h>
#include <util/overflow.h>

#include <array>
#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace shielded::v2 {
namespace {

constexpr std::string_view TAG_RECIPIENT_SCAN_HINT{"BTX_ShieldedV2_Recipient_ScanHint_V1"};
constexpr std::string_view TAG_OPAQUE_SCAN_HINT{"BTX_ShieldedV2_Opaque_ScanHint_V1"};
constexpr std::string_view TAG_PLACEHOLDER_INPUT_VALUE{"BTX_ShieldedV2_Send_Input_Value_Placeholder_V1"};
constexpr std::string_view TAG_PLACEHOLDER_OUTPUT_VALUE{"BTX_ShieldedV2_Send_Output_Value_Placeholder_V1"};
constexpr ScanDomain PUBLIC_SCAN_DOMAIN{ScanDomain::OPAQUE};

[[nodiscard]] uint256 HashTaggedIndex(std::string_view tag, uint32_t index, const uint256& object_hash)
{
    HashWriter hw;
    hw << std::string{tag} << index << object_hash;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashLegacyEphemeralKey(const shielded::EncryptedNote& encrypted_note)
{
    const std::vector<uint8_t> serialized = encrypted_note.Serialize();
    return ComputeLegacyPayloadEphemeralKey(Span<const uint8_t>{serialized.data(), serialized.size()});
}

enum class SendProofMode {
    NONE,
    DIRECT_SMILE,
};

[[nodiscard]] TransactionBundle BuildEmptySendBundle(const SendPayload& payload,
                                                    SendProofMode proof_mode,
                                                    const Consensus::Params* consensus,
                                                    int32_t validation_height)
{
    TransactionBundle bundle;
    bundle.header.family_id = GetWireTransactionFamilyForValidationHeight(TransactionFamily::V2_SEND,
                                                                          consensus,
                                                                          validation_height);
    if (proof_mode == SendProofMode::DIRECT_SMILE) {
        bundle.header.proof_envelope.proof_kind =
            GetWireProofKindForValidationHeight(TransactionFamily::V2_SEND,
                                                ProofKind::DIRECT_SMILE,
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
    } else {
        bundle.header.proof_envelope.proof_kind = ProofKind::NONE;
        bundle.header.proof_envelope.membership_proof_kind = ProofComponentKind::NONE;
        bundle.header.proof_envelope.amount_proof_kind = ProofComponentKind::NONE;
        bundle.header.proof_envelope.balance_proof_kind = ProofComponentKind::NONE;
    }
    bundle.header.proof_envelope.settlement_binding_kind =
        GetWireSettlementBindingKindForValidationHeight(TransactionFamily::V2_SEND,
                                                        SettlementBindingKind::NONE,
                                                        consensus,
                                                        validation_height);
    bundle.header.proof_envelope.statement_digest = uint256{};
    bundle.payload = payload;
    bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
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

[[nodiscard]] std::optional<CAmount> SumNoteValues(const std::vector<ShieldedNote>& notes)
{
    CAmount total{0};
    for (const ShieldedNote& note : notes) {
        const auto next_total = CheckedAdd(total, note.value);
        if (!next_total || !MoneyRange(*next_total)) return std::nullopt;
        total = *next_total;
    }
    return total;
}

[[nodiscard]] std::vector<uint8_t> SerializeWitness(const proof::V2SendWitness& witness)
{
    DataStream witness_stream;
    witness_stream << witness;
    if (witness_stream.empty()) return {};
    const auto* begin = reinterpret_cast<const uint8_t*>(witness_stream.data());
    return {begin, begin + witness_stream.size()};
}

[[nodiscard]] std::vector<std::vector<smile2::CTPublicAccount>> BuildAccountRings(
    Span<const smile2::wallet::SmileRingMember> ring_members,
    Span<const SpendDescription> spends)
{
    std::vector<std::vector<smile2::CTPublicAccount>> account_rings;
    account_rings.reserve(spends.size());
    for (const auto& spend : spends) {
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

} // namespace

bool V2SendSpendInput::IsValid() const
{
    const uint256 effective_note_commitment =
        note_commitment.IsNull() ? note.GetCommitment() : note_commitment;
    const size_t ring_size = ring_positions.size();
    const bool smile_ring_valid =
        smile_ring_members.empty() ||
        (smile_ring_members.size() == ring_size &&
         real_index < smile_ring_members.size() &&
         std::all_of(smile_ring_members.begin(), smile_ring_members.end(), [](const auto& member) {
             return member.IsValid();
         }) &&
         smile_ring_members[real_index].note_commitment == effective_note_commitment);

    return note.IsValid() &&
           account_leaf_hint.has_value() &&
           account_leaf_hint->IsValid() &&
           !account_registry_anchor.IsNull() &&
           account_registry_proof.has_value() &&
           account_registry_proof->IsValid() &&
           shielded::lattice::IsSupportedRingSize(ring_size) &&
           ring_members.size() == ring_size &&
           real_index < ring_positions.size() &&
           ring_members[real_index] == effective_note_commitment &&
           smile_ring_valid;
}

bool V2SendOutputInput::IsValid() const
{
    return IsValidNoteClass(note_class) &&
           note.IsValid() &&
           encrypted_note.IsValid() &&
           (!lifecycle_control.has_value() ||
            (note_class == NoteClass::OPERATOR && lifecycle_control->IsValid()));
}

bool V2SendBuildResult::IsValid() const
{
    if (!tx.shielded_bundle.HasV2Bundle()) return false;
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr ||
        !BundleHasSemanticFamily(*bundle, TransactionFamily::V2_SEND) ||
        !std::holds_alternative<SendPayload>(bundle->payload)) {
        return false;
    }

    const auto& payload = std::get<SendPayload>(bundle->payload);
    if (payload.spends.empty()) {
        return bundle->header.proof_envelope.proof_kind == ProofKind::NONE &&
               bundle->proof_payload.empty() &&
               witness.IsValid(/*expected_input_count=*/0, payload.outputs.size());
    }
    return witness.IsValid(payload.spends.size(), payload.outputs.size());
}

std::array<uint8_t, SCAN_HINT_BYTES> ComputeLegacyRecipientScanHint(
    const shielded::EncryptedNote& encrypted_note,
    const mlkem::PublicKey& recipient_kem_pk,
    ScanDomain scan_domain)
{
    HashWriter hw;
    hw << std::string{TAG_RECIPIENT_SCAN_HINT}
       << uint8_t{SCAN_HINT_VERSION}
       << static_cast<uint8_t>(scan_domain)
       << HashLegacyEphemeralKey(encrypted_note)
       << shielded::NoteEncryption::ComputeViewTag(encrypted_note.kem_ciphertext, recipient_kem_pk);
    hw.write(AsBytes(Span<const uint8_t>{recipient_kem_pk.data(), recipient_kem_pk.size()}));

    std::array<uint8_t, SCAN_HINT_BYTES> scan_hint{};
    const uint256 digest = hw.GetSHA256();
    std::copy_n(digest.begin(), scan_hint.size(), scan_hint.begin());
    return scan_hint;
}

std::array<uint8_t, SCAN_HINT_BYTES> ComputeOpaquePublicScanHint(
    const shielded::EncryptedNote& encrypted_note)
{
    HashWriter hw;
    hw << std::string{TAG_OPAQUE_SCAN_HINT}
       << uint8_t{SCAN_HINT_VERSION}
       << HashLegacyEphemeralKey(encrypted_note);

    std::array<uint8_t, SCAN_HINT_BYTES> scan_hint{};
    const uint256 digest = hw.GetSHA256();
    std::copy_n(digest.begin(), scan_hint.size(), scan_hint.begin());
    return scan_hint;
}

std::optional<EncryptedNotePayload> EncodeLegacyEncryptedNotePayload(
    const shielded::EncryptedNote& encrypted_note,
    const mlkem::PublicKey& recipient_kem_pk,
    ScanDomain scan_domain)
{
    if (!IsValidScanDomain(scan_domain)) return std::nullopt;
    (void)recipient_kem_pk;

    EncryptedNotePayload payload;
    payload.scan_domain = PUBLIC_SCAN_DOMAIN;
    payload.scan_hint = ComputeOpaquePublicScanHint(encrypted_note);
    payload.ephemeral_key = HashLegacyEphemeralKey(encrypted_note);
    payload.ciphertext = encrypted_note.Serialize();
    if (!payload.IsValid()) return std::nullopt;
    return payload;
}

std::optional<shielded::EncryptedNote> DecodeLegacyEncryptedNotePayload(const EncryptedNotePayload& payload)
{
    if (!payload.IsValid()) return std::nullopt;

    auto encrypted_note = shielded::EncryptedNote::Deserialize(payload.ciphertext);
    if (!encrypted_note.has_value()) return std::nullopt;
    if (payload.ephemeral_key != HashLegacyEphemeralKey(*encrypted_note)) return std::nullopt;
    return encrypted_note;
}

bool LegacyEncryptedNotePayloadMatchesRecipient(const EncryptedNotePayload& payload,
                                                const shielded::EncryptedNote& encrypted_note,
                                                const mlkem::PublicKey& recipient_kem_pk)
{
    if (!payload.IsValid()) return false;
    if (payload.ephemeral_key != HashLegacyEphemeralKey(encrypted_note)) return false;
    if (payload.scan_domain == PUBLIC_SCAN_DOMAIN) return false;
    return payload.scan_hint ==
           ComputeLegacyRecipientScanHint(encrypted_note, recipient_kem_pk, payload.scan_domain);
}

std::optional<V2SendBuildResult> BuildV2SendTransaction(const CMutableTransaction& tx_template,
                                                        const uint256& spend_anchor,
                                                        const std::vector<V2SendSpendInput>& spend_inputs,
                                                        const std::vector<V2SendOutputInput>& output_inputs,
                                                        CAmount fee,
                                                        Span<const unsigned char> spending_key,
                                                        std::string& reject_reason,
                                                        Span<const unsigned char> rng_entropy,
                                                        const Consensus::Params* consensus,
                                                        int32_t validation_height)
{
    reject_reason.clear();
    if (tx_template.HasShieldedBundle()) {
        reject_reason = "bad-shielded-v2-builder-existing-bundle";
        return std::nullopt;
    }
    const bool has_shielded_spends = !spend_inputs.empty();
    if (has_shielded_spends && spend_anchor.IsNull()) {
        reject_reason = "bad-shielded-v2-builder-spend-anchor";
        return std::nullopt;
    }
    if (spend_inputs.size() > MAX_DIRECT_SPENDS) {
        reject_reason = "bad-shielded-v2-builder-spend-count";
        return std::nullopt;
    }
    if (!has_shielded_spends && tx_template.vin.empty()) {
        reject_reason = "bad-shielded-v2-builder-input-source";
        return std::nullopt;
    }
    if (has_shielded_spends && !tx_template.vin.empty()) {
        reject_reason = "bad-shielded-v2-builder-transparent-inputs";
        return std::nullopt;
    }
    if (output_inputs.empty() || output_inputs.size() > MAX_DIRECT_OUTPUTS) {
        reject_reason = "bad-shielded-v2-builder-output-count";
        return std::nullopt;
    }
    if (fee < 0 || !MoneyRange(fee)) {
        reject_reason = "bad-shielded-v2-builder-fee";
        return std::nullopt;
    }
    if (has_shielded_spends && spending_key.size() != 32) {
        reject_reason = "bad-shielded-v2-builder-spending-key";
        return std::nullopt;
    }

    if ((has_shielded_spends && spend_inputs.size() > MAX_LIVE_DIRECT_SMILE_SPENDS) ||
        (has_shielded_spends && spend_inputs.size() > smile2::MAX_CT_INPUTS) ||
        output_inputs.size() > smile2::MAX_CT_OUTPUTS) {
        reject_reason = "bad-shielded-v2-builder-smile-limits";
        return std::nullopt;
    }

    bool use_smile = has_shielded_spends && !spend_inputs.front().smile_ring_members.empty();
    if (use_smile) {
        const auto& reference_positions = spend_inputs.front().ring_positions;
        const auto& reference_members = spend_inputs.front().smile_ring_members;
        use_smile = std::all_of(spend_inputs.begin(), spend_inputs.end(), [&](const V2SendSpendInput& input) {
            if (input.smile_ring_members.size() != reference_members.size() ||
                input.ring_positions != reference_positions) {
                return false;
            }
            for (size_t i = 0; i < reference_members.size(); ++i) {
                const auto& lhs = input.smile_ring_members[i];
                const auto& rhs = reference_members[i];
                if (lhs.note_commitment != rhs.note_commitment ||
                    lhs.account_leaf_commitment != rhs.account_leaf_commitment ||
                    lhs.public_key.pk != rhs.public_key.pk ||
                    lhs.public_key.A != rhs.public_key.A ||
                    lhs.public_coin.t0 != rhs.public_coin.t0 ||
                    lhs.public_coin.t_msg != rhs.public_coin.t_msg) {
                    return false;
                }
            }
            return true;
        });
    }
    if (has_shielded_spends && !use_smile) {
        reject_reason = "bad-shielded-v2-builder-smile-ring-members";
        return std::nullopt;
    }

    SendPayload payload;
    payload.spend_anchor = has_shielded_spends ? spend_anchor : uint256{};
    payload.fee = fee;

    std::vector<ShieldedNote> input_notes;
    input_notes.reserve(spend_inputs.size());
    std::vector<ShieldedNote> output_notes;
    output_notes.reserve(output_inputs.size());

    for (size_t i = 0; i < spend_inputs.size(); ++i) {
        const V2SendSpendInput& spend_input = spend_inputs[i];
        const uint256 effective_note_commitment =
            spend_input.note_commitment.IsNull() ? spend_input.note.GetCommitment() : spend_input.note_commitment;
        if (!spend_input.IsValid()) {
            reject_reason = "bad-shielded-v2-builder-input";
            return std::nullopt;
        }

        SpendDescription spend;
        spend.merkle_anchor = spend_anchor;
        spend.value_commitment = HashTaggedIndex(TAG_PLACEHOLDER_INPUT_VALUE,
                                                 static_cast<uint32_t>(i),
                                                 effective_note_commitment);
        spend.nullifier = HashTaggedIndex(TAG_PLACEHOLDER_INPUT_VALUE,
                                          static_cast<uint32_t>(i),
                                          effective_note_commitment);
        if (!use_smile) {
            if (!shielded::ringct::DeriveInputNullifierForNote(spend.nullifier,
                                                               spending_key,
                                                               spend_input.note,
                                                               effective_note_commitment)) {
                reject_reason = "bad-shielded-v2-builder-nullifier";
                return std::nullopt;
            }
        }
        const auto account_leaf_commitments =
            shielded::registry::CollectAccountLeafCommitmentCandidatesFromNote(spend_input.note,
                                                                               effective_note_commitment,
                                                                               *spend_input.account_leaf_hint);
        if (account_leaf_commitments.empty()) {
            reject_reason = "bad-shielded-v2-builder-account-leaf";
            return std::nullopt;
        }
        if (!spend_input.account_registry_proof.has_value() ||
            std::find(account_leaf_commitments.begin(),
                      account_leaf_commitments.end(),
                      spend_input.account_registry_proof->account_leaf_commitment) ==
                account_leaf_commitments.end()) {
            reject_reason = "bad-shielded-v2-builder-account-leaf-proof";
            return std::nullopt;
        }
        if (payload.account_registry_anchor.IsNull()) {
            payload.account_registry_anchor = spend_input.account_registry_anchor;
        } else if (payload.account_registry_anchor != spend_input.account_registry_anchor) {
            reject_reason = "bad-shielded-v2-builder-account-registry-anchor";
            return std::nullopt;
        }
        spend.account_leaf_commitment = spend_input.account_registry_proof->account_leaf_commitment;
        spend.account_registry_proof = *spend_input.account_registry_proof;

        payload.spends.push_back(std::move(spend));
        input_notes.push_back(spend_input.note);
    }

    const bool has_lifecycle_controls =
        std::any_of(output_inputs.begin(), output_inputs.end(), [](const V2SendOutputInput& output) {
            return output.lifecycle_control.has_value();
        });
    payload.output_note_class = output_inputs.front().note_class;
    payload.output_scan_domain = output_inputs.front().encrypted_note.scan_domain;
    const bool postfork =
        consensus != nullptr &&
        consensus->IsShieldedMatRiCTDisabled(validation_height);
    const bool use_postfork_compact_send_encoding =
        postfork && has_shielded_spends;
    if (has_lifecycle_controls) {
        if (postfork || has_shielded_spends || output_inputs.size() != 1) {
            reject_reason = "bad-shielded-v2-builder-lifecycle-control";
            return std::nullopt;
        }
    }
    payload.output_encoding = !has_shielded_spends
        ? (use_postfork_compact_send_encoding
               ? SendOutputEncoding::SMILE_COMPACT_POSTFORK
               : SendOutputEncoding::LEGACY)
        : use_postfork_compact_send_encoding
            ? SendOutputEncoding::SMILE_COMPACT_POSTFORK
            : SendOutputEncoding::SMILE_COMPACT;
    for (size_t i = 0; i < output_inputs.size(); ++i) {
        const V2SendOutputInput& output_input = output_inputs[i];
        if (!output_input.IsValid()) {
            reject_reason = "bad-shielded-v2-builder-output";
            return std::nullopt;
        }
        if (output_input.note_class != payload.output_note_class ||
            output_input.encrypted_note.scan_domain != payload.output_scan_domain) {
            reject_reason = "bad-shielded-v2-builder-output-shared-metadata";
            return std::nullopt;
        }

        OutputDescription output;
        output.note_class = output_input.note_class;
        auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            output_input.note);
        if (!smile_account.has_value()) {
            reject_reason = "bad-shielded-v2-builder-smile-account";
            return std::nullopt;
        }
        output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        output.value_commitment = HashTaggedIndex(TAG_PLACEHOLDER_OUTPUT_VALUE,
                                                  static_cast<uint32_t>(i),
                                                  output.note_commitment);
        output.smile_account = std::move(*smile_account);
        output.encrypted_note = output_input.encrypted_note;
        payload.outputs.push_back(std::move(output));
        if (output_input.lifecycle_control.has_value()) {
            auto control = *output_input.lifecycle_control;
            control.output_index = static_cast<uint32_t>(i);
            if (!VerifyAddressLifecycleControl(control, payload.outputs.back().note_commitment)) {
                reject_reason = "bad-shielded-v2-builder-lifecycle-control";
                return std::nullopt;
            }
            payload.lifecycle_controls.push_back(std::move(control));
        }
        output_notes.push_back(output_input.note);
    }

    const auto total_output_value = SumNoteValues(output_notes);
    CAmount transparent_value_out{0};
    for (const auto& txout : tx_template.vout) {
        if (!MoneyRange(txout.nValue)) {
            reject_reason = "bad-shielded-v2-builder-transparent-output";
            return std::nullopt;
        }
        const auto next_value = CheckedAdd(transparent_value_out, txout.nValue);
        if (!next_value || !MoneyRange(*next_value)) {
            reject_reason = "bad-shielded-v2-builder-transparent-output";
            return std::nullopt;
        }
        transparent_value_out = *next_value;
    }
    if (!total_output_value) {
        reject_reason = "bad-shielded-v2-builder-balance";
        return std::nullopt;
    }
    if (has_shielded_spends) {
        const auto total_input_value = SumNoteValues(input_notes);
        const auto total_public_value = CheckedAdd(transparent_value_out, fee);
        const auto total_output_plus_public =
            total_public_value ? CheckedAdd(*total_output_value, *total_public_value) : std::nullopt;
        if (!total_input_value || !total_output_plus_public || !MoneyRange(*total_output_plus_public) ||
            *total_input_value != *total_output_plus_public) {
            reject_reason = "bad-shielded-v2-builder-balance";
            return std::nullopt;
        }
        payload.value_balance = *total_public_value;
    } else {
        payload.value_balance = -*total_output_value;
    }

    proof::V2SendWitness witness;
    witness.spends.reserve(spend_inputs.size());
    for (const V2SendSpendInput& spend_input : spend_inputs) {
        proof::V2SendSpendWitness spend_witness;
        spend_witness.ring_positions = spend_input.ring_positions;
        witness.spends.push_back(std::move(spend_witness));
    }

    CMutableTransaction tx_result{tx_template};
    if (!has_shielded_spends) {
        for (auto& output : payload.outputs) {
            if (!output.smile_account.has_value()) {
                reject_reason = "bad-shielded-v2-builder-smile-account";
                return std::nullopt;
            }
            output.value_commitment = smile2::ComputeSmileOutputCoinHash(output.smile_account->public_coin);
        }
        tx_result.shielded_bundle.v2_bundle = BuildEmptySendBundle(payload,
                                                                   SendProofMode::NONE,
                                                                   consensus,
                                                                   validation_height);

        V2SendBuildResult result;
        result.tx = std::move(tx_result);
        result.witness = std::move(witness);
        if (!result.IsValid()) {
            reject_reason = "bad-shielded-v2-builder-result";
            return std::nullopt;
        }
        return result;
    }

    if (use_smile) {
        const bool bind_smile_anonset_context =
            consensus != nullptr && consensus->IsShieldedMatRiCTDisabled(validation_height);
        std::vector<smile2::wallet::SmileInputMaterial> smile_inputs;
        smile_inputs.reserve(spend_inputs.size());
        for (const auto& spend_input : spend_inputs) {
            smile_inputs.push_back({spend_input.note,
                                    spend_input.note_commitment,
                                    payload.spends[smile_inputs.size()].account_leaf_commitment,
                                    spend_input.real_index});
        }

        std::vector<uint256> serial_hashes;
        const auto& shared_smile_ring_members = spend_inputs.front().smile_ring_members;
        auto smile_result = smile2::wallet::CreateSmileProof(
            smile2::wallet::SMILE_GLOBAL_SEED,
            smile_inputs,
            output_notes,
            Span<const smile2::wallet::SmileRingMember>{shared_smile_ring_members.data(),
                                                        shared_smile_ring_members.size()},
            rng_entropy,
            serial_hashes,
            payload.value_balance,
            smile2::SmileProofCodecPolicy::CANONICAL_NO_RICE,
            bind_smile_anonset_context);
        if (!smile_result.has_value() ||
            serial_hashes.size() != payload.spends.size() ||
            smile_result->output_coins.size() != payload.outputs.size()) {
            reject_reason = "bad-shielded-v2-builder-proof";
            return std::nullopt;
        }

        for (size_t i = 0; i < payload.spends.size(); ++i) {
            payload.spends[i].nullifier = serial_hashes[i];
            payload.spends[i].value_commitment = smile2::ComputeSmileDirectInputBindingHash(
                Span<const smile2::wallet::SmileRingMember>{shared_smile_ring_members.data(),
                                                            shared_smile_ring_members.size()},
                payload.spends[i].merkle_anchor,
                static_cast<uint32_t>(i),
                serial_hashes[i]);
        }
        for (size_t i = 0; i < payload.outputs.size(); ++i) {
            if (!payload.outputs[i].smile_account.has_value() ||
                smile2::ComputeSmileOutputCoinHash(payload.outputs[i].smile_account->public_coin) !=
                    smile2::ComputeSmileOutputCoinHash(smile_result->output_coins[i])) {
                reject_reason = "bad-shielded-v2-builder-smile-account";
                return std::nullopt;
            }
            payload.outputs[i].value_commitment = smile2::ComputeSmileOutputCoinHash(smile_result->output_coins[i]);
        }

        tx_result.shielded_bundle.v2_bundle = BuildEmptySendBundle(payload,
                                                                   SendProofMode::DIRECT_SMILE,
                                                                   consensus,
                                                                   validation_height);
        if (tx_result.shielded_bundle.v2_bundle.has_value()) {
            tx_result.shielded_bundle.v2_bundle->header.proof_envelope.extension_digest =
                proof::ComputeV2SendExtensionDigest(CTransaction{tx_result});
        }
        const CTransaction final_immutable{tx_result};
        const proof::ProofStatement statement = consensus != nullptr
            ? proof::DescribeV2SendStatement(final_immutable, *consensus, validation_height)
            : proof::DescribeV2SendStatement(final_immutable);
        if (!statement.IsValid()) {
            reject_reason = "bad-shielded-v2-builder-statement-final";
            return std::nullopt;
        }

        witness.use_smile = true;
        witness.smile_proof_bytes = std::move(smile_result->proof_bytes);
        witness.smile_output_coins = std::move(smile_result->output_coins);

        auto* bundle = tx_result.shielded_bundle.v2_bundle ? &*tx_result.shielded_bundle.v2_bundle : nullptr;
        if (bundle == nullptr) {
            reject_reason = "bad-shielded-v2-builder-bundle";
            return std::nullopt;
        }
        bundle->header.proof_envelope = statement.envelope;
        bundle->proof_payload = SerializeWitness(witness);
        bundle->payload = payload;
        bundle->header.payload_digest = ComputeSendPayloadDigest(payload);
        if (!bundle->IsValid()) {
            reject_reason = "bad-shielded-v2-builder-bundle";
            return std::nullopt;
        }

        std::vector<smile2::BDLOPCommitment> shared_coin_ring;
        shared_coin_ring.reserve(shared_smile_ring_members.size());
        for (const auto& member : shared_smile_ring_members) {
            shared_coin_ring.push_back(member.public_coin);
        }
        smile2::CTPublicData pub;
        pub.anon_set = smile2::wallet::BuildAnonymitySet(
            Span<const smile2::wallet::SmileRingMember>{shared_smile_ring_members.data(),
                                                        shared_smile_ring_members.size()});
        pub.coin_rings.assign(payload.spends.size(), shared_coin_ring);
        pub.account_rings = BuildAccountRings(
            Span<const smile2::wallet::SmileRingMember>{shared_smile_ring_members.data(),
                                                        shared_smile_ring_members.size()},
            Span<const SpendDescription>{payload.spends.data(), payload.spends.size()});
        if (auto verify_err = smile2::VerifySmile2CTFromBytes(witness.smile_proof_bytes,
                                                              payload.spends.size(),
                                                              payload.outputs.size(),
                                                              witness.smile_output_coins,
                                                              pub,
                                                              payload.value_balance,
                                                              /*reject_rice_codec=*/false,
                                                              bind_smile_anonset_context);
            verify_err.has_value()) {
            reject_reason = "bad-shielded-v2-builder-proof";
            return std::nullopt;
        }

        V2SendBuildResult result;
        result.tx = std::move(tx_result);
        result.witness = std::move(witness);
        if (!result.IsValid()) {
            reject_reason = "bad-shielded-v2-builder-result";
            return std::nullopt;
        }
        return result;
    }

    reject_reason = "bad-shielded-v2-builder-smile-ring-members";
    return std::nullopt;
}

} // namespace shielded::v2
