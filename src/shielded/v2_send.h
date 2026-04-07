// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_V2_SEND_H
#define BTX_SHIELDED_V2_SEND_H

#include <consensus/amount.h>
#include <consensus/params.h>
#include <primitives/transaction.h>
#include <shielded/account_registry.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_proof.h>

#include <span.h>

#include <optional>
#include <string>
#include <vector>
#include <limits>

namespace shielded::v2 {

// The wire surface can encode more inputs, but the live audited direct-SMILE
// proving path is only considered production-ready for up to two shielded
// spends per transaction. Wider spend sets should be consolidated first.
static constexpr uint64_t MAX_LIVE_DIRECT_SMILE_SPENDS{2};

struct V2SendSpendInput
{
    ShieldedNote note;
    uint256 note_commitment;
    std::optional<shielded::registry::AccountLeafHint> account_leaf_hint;
    uint256 account_registry_anchor;
    std::optional<shielded::registry::ShieldedAccountRegistrySpendWitness> account_registry_proof;
    std::vector<uint64_t> ring_positions;
    std::vector<uint256> ring_members;
    std::vector<smile2::wallet::SmileRingMember> smile_ring_members;
    uint32_t real_index{0};

    [[nodiscard]] bool IsValid() const;
};

struct V2SendOutputInput
{
    NoteClass note_class{NoteClass::USER};
    ShieldedNote note;
    EncryptedNotePayload encrypted_note;
    std::optional<AddressLifecycleControl> lifecycle_control;

    [[nodiscard]] bool IsValid() const;
};

struct V2SendBuildResult
{
    CMutableTransaction tx;
    proof::V2SendWitness witness;

    [[nodiscard]] bool IsValid() const;
};

[[nodiscard]] std::array<uint8_t, SCAN_HINT_BYTES> ComputeLegacyRecipientScanHint(
    const shielded::EncryptedNote& encrypted_note,
    const mlkem::PublicKey& recipient_kem_pk,
    ScanDomain scan_domain);

[[nodiscard]] std::array<uint8_t, SCAN_HINT_BYTES> ComputeOpaquePublicScanHint(
    const shielded::EncryptedNote& encrypted_note);

[[nodiscard]] std::optional<EncryptedNotePayload> EncodeLegacyEncryptedNotePayload(
    const shielded::EncryptedNote& encrypted_note,
    const mlkem::PublicKey& recipient_kem_pk,
    ScanDomain scan_domain);

[[nodiscard]] std::optional<shielded::EncryptedNote> DecodeLegacyEncryptedNotePayload(
    const EncryptedNotePayload& payload);

[[nodiscard]] bool LegacyEncryptedNotePayloadMatchesRecipient(
    const EncryptedNotePayload& payload,
    const shielded::EncryptedNote& encrypted_note,
    const mlkem::PublicKey& recipient_kem_pk);

[[nodiscard]] std::optional<V2SendBuildResult> BuildV2SendTransaction(
    const CMutableTransaction& tx_template,
    const uint256& spend_anchor,
    const std::vector<V2SendSpendInput>& spend_inputs,
    const std::vector<V2SendOutputInput>& output_inputs,
    CAmount fee,
    Span<const unsigned char> spending_key,
    std::string& reject_reason,
    Span<const unsigned char> rng_entropy = {},
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max());

} // namespace shielded::v2

#endif // BTX_SHIELDED_V2_SEND_H
