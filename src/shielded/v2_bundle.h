// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_V2_BUNDLE_H
#define BTX_SHIELDED_V2_BUNDLE_H

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/ml_kem.h>
#include <pqkey.h>
#include <serialize.h>
#include <shielded/account_registry_proof.h>
#include <shielded/smile2/public_account.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/v2_types.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <ios>
#include <optional>
#include <variant>
#include <vector>

class CTransaction;

namespace Consensus {
struct Params;
}

namespace shielded::v2 {

static constexpr uint64_t MAX_DIRECT_SPENDS{64};
static constexpr uint64_t MAX_DIRECT_OUTPUTS{64};
static constexpr uint64_t MAX_BATCH_NULLIFIERS{20'000};
static constexpr uint64_t MAX_BATCH_LEAVES{20'000};
static constexpr uint64_t MAX_BATCH_RESERVE_OUTPUTS{64};
static constexpr uint64_t MAX_EGRESS_OUTPUTS{20'000};
static constexpr uint64_t MAX_REBALANCE_DOMAINS{MAX_NETTING_DOMAINS};
static constexpr uint64_t MAX_SETTLEMENT_REFS{512};
static constexpr uint64_t MAX_PROOF_SHARDS{256};
static constexpr uint64_t MAX_OUTPUT_CHUNKS{512};
static constexpr uint64_t MAX_PROOF_PAYLOAD_BYTES{6 * 1024 * 1024};
static constexpr uint64_t MAX_OPAQUE_FAMILY_PAYLOAD_BYTES{MAX_BLOCK_SERIALIZED_SIZE};
static constexpr uint64_t OPAQUE_FAMILY_PAYLOAD_PAD_QUANTUM{256};
static constexpr uint64_t MAX_GENERIC_SPENDS{MAX_BATCH_NULLIFIERS};
static constexpr uint64_t MAX_GENERIC_OUTPUTS{MAX_EGRESS_OUTPUTS};
static constexpr uint64_t MAX_ADDRESS_LIFECYCLE_CONTROLS{1};
static constexpr uint64_t MAX_ADDRESS_LIFECYCLE_PUBKEY_BYTES{MLDSA44_PUBKEY_SIZE};
static constexpr uint64_t MAX_ADDRESS_LIFECYCLE_SIGNATURE_BYTES{MLDSA44_SIGNATURE_SIZE};

enum class SendOutputEncoding : uint8_t {
    LEGACY = 0,
    SMILE_COMPACT = 1,
    SMILE_COMPACT_POSTFORK = 2,
};

[[nodiscard]] inline bool IsValidSendOutputEncoding(SendOutputEncoding encoding)
{
    switch (encoding) {
    case SendOutputEncoding::LEGACY:
    case SendOutputEncoding::SMILE_COMPACT:
    case SendOutputEncoding::SMILE_COMPACT_POSTFORK:
        return true;
    }
    return false;
}

[[nodiscard]] inline bool IsCompactSendOutputEncoding(SendOutputEncoding encoding)
{
    switch (encoding) {
    case SendOutputEncoding::SMILE_COMPACT:
    case SendOutputEncoding::SMILE_COMPACT_POSTFORK:
        return true;
    case SendOutputEncoding::LEGACY:
        return false;
    }
    return false;
}

[[nodiscard]] inline bool SendOutputEncodingElidesValueBalance(SendOutputEncoding encoding)
{
    return encoding == SendOutputEncoding::SMILE_COMPACT_POSTFORK;
}

namespace detail {

template <typename Stream, typename Parser>
bool TryParseWithStreamCheckpoint(Stream& s, Parser&& parser)
{
    if constexpr (requires { s.GetPos(); s.SetPos(uint64_t{0}); }) {
        const auto checkpoint = s.GetPos();
        try {
            parser();
            return true;
        } catch (const std::exception&) {
            if (!s.SetPos(checkpoint)) throw;
            return false;
        }
    } else if constexpr (requires { s.size(); s.Rewind(size_t{0}); }) {
        const auto before = s.size();
        try {
            parser();
            return true;
        } catch (const std::exception&) {
            const auto after = s.size();
            if (after > before) throw;
            if (!s.Rewind(before - after)) throw;
            return false;
        }
    }

    parser();
    return true;
}

} // namespace detail

enum class ReserveOutputEncoding : uint8_t {
    EXPLICIT = 0,
    INGRESS_PLACEHOLDER_DERIVED = 1,
};

[[nodiscard]] inline bool IsValidReserveOutputEncoding(ReserveOutputEncoding encoding)
{
    switch (encoding) {
    case ReserveOutputEncoding::EXPLICIT:
    case ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED:
        return true;
    }
    return false;
}

enum class AddressLifecycleControlKind : uint8_t {
    ROTATE = 1,
    REVOKE = 2,
};

[[nodiscard]] inline bool IsValidAddressLifecycleControlKind(AddressLifecycleControlKind kind)
{
    switch (kind) {
    case AddressLifecycleControlKind::ROTATE:
    case AddressLifecycleControlKind::REVOKE:
        return true;
    }
    return false;
}

struct LifecycleAddress
{
    uint8_t version{0x00};
    uint8_t algo_byte{0x00};
    uint256 pk_hash;
    uint256 kem_pk_hash;
    bool has_kem_public_key{false};
    std::array<uint8_t, mlkem::PUBLICKEYBYTES> kem_public_key{};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, algo_byte);
        ::Serialize(s, pk_hash);
        ::Serialize(s, kem_pk_hash);
        ::Serialize(s, has_kem_public_key);
        if (has_kem_public_key) {
            s.write(AsBytes(Span<const uint8_t>{kem_public_key.data(), kem_public_key.size()}));
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, algo_byte);
        ::Unserialize(s, pk_hash);
        ::Unserialize(s, kem_pk_hash);
        ::Unserialize(s, has_kem_public_key);
        kem_public_key.fill(0);
        if (has_kem_public_key) {
            s.read(AsWritableBytes(Span<uint8_t>{kem_public_key.data(), kem_public_key.size()}));
        }
    }
};

struct AddressLifecycleControl
{
    uint8_t version{WIRE_VERSION};
    AddressLifecycleControlKind kind{AddressLifecycleControlKind::REVOKE};
    uint32_t output_index{0};
    LifecycleAddress subject;
    bool has_successor{false};
    LifecycleAddress successor;
    std::vector<uint8_t> subject_spending_pubkey;
    std::vector<uint8_t> signature;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "AddressLifecycleControl::Serialize invalid version");
        detail::SerializeEnum(s, static_cast<uint8_t>(kind));
        ::Serialize(s, output_index);
        ::Serialize(s, subject);
        ::Serialize(s, has_successor);
        if (has_successor) {
            ::Serialize(s, successor);
        }
        detail::SerializeBytes(s,
                               subject_spending_pubkey,
                               MAX_ADDRESS_LIFECYCLE_PUBKEY_BYTES,
                               "AddressLifecycleControl::Serialize oversized subject_spending_pubkey");
        detail::SerializeBytes(s,
                               signature,
                               MAX_ADDRESS_LIFECYCLE_SIGNATURE_BYTES,
                               "AddressLifecycleControl::Serialize oversized signature");
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "AddressLifecycleControl::Unserialize invalid version");
        detail::UnserializeEnum(s,
                                kind,
                                IsValidAddressLifecycleControlKind,
                                "AddressLifecycleControl::Unserialize invalid kind");
        ::Unserialize(s, output_index);
        ::Unserialize(s, subject);
        ::Unserialize(s, has_successor);
        if (has_successor) {
            ::Unserialize(s, successor);
        } else {
            successor = LifecycleAddress{};
        }
        detail::UnserializeBytes(s,
                                 subject_spending_pubkey,
                                 MAX_ADDRESS_LIFECYCLE_PUBKEY_BYTES,
                                 "AddressLifecycleControl::Unserialize oversized subject_spending_pubkey");
        detail::UnserializeBytes(s,
                                 signature,
                                 MAX_ADDRESS_LIFECYCLE_SIGNATURE_BYTES,
                                 "AddressLifecycleControl::Unserialize oversized signature");
    }
};

[[nodiscard]] uint256 ComputeAddressLifecycleControlSigHash(const AddressLifecycleControl& control,
                                                            const uint256& note_commitment);
[[nodiscard]] bool VerifyAddressLifecycleControl(const AddressLifecycleControl& control,
                                                const uint256& note_commitment);
[[nodiscard]] uint256 ComputeV2LifecycleTransparentBindingDigest(const CTransaction& tx);
[[nodiscard]] uint256 ComputeAddressLifecycleRecordSigHash(
    const AddressLifecycleControl& control,
    const uint256& transparent_binding_digest);
[[nodiscard]] bool VerifyAddressLifecycleRecord(const AddressLifecycleControl& control,
                                                const uint256& transparent_binding_digest);

[[nodiscard]] uint256 ComputeV2IngressPlaceholderReserveValueCommitment(const uint256& settlement_binding_digest,
                                                                        uint32_t output_index,
                                                                        const uint256& note_commitment);
[[nodiscard]] uint256 ComputeV2EgressOutputValueCommitment(const uint256& output_binding_digest,
                                                           uint32_t output_index,
                                                           const uint256& note_commitment);
[[nodiscard]] uint256 ComputeV2RebalanceOutputValueCommitment(uint32_t output_index,
                                                              const uint256& note_commitment);

struct SpendDescription
{
    uint8_t version{WIRE_VERSION};
    uint256 nullifier;
    uint256 merkle_anchor;
    uint256 account_leaf_commitment;
    shielded::registry::ShieldedAccountRegistrySpendWitness account_registry_proof;
    uint256 note_commitment;
    uint256 value_commitment;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("SpendDescription::Serialize invalid version");
        }
        ::Serialize(s, nullifier);
        ::Serialize(s, merkle_anchor);
        ::Serialize(s, account_leaf_commitment);
        ::Serialize(s, account_registry_proof);
        ::Serialize(s, note_commitment);
        ::Serialize(s, value_commitment);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        version = WIRE_VERSION;
        ::Unserialize(s, nullifier);
        ::Unserialize(s, merkle_anchor);
        ::Unserialize(s, account_leaf_commitment);
        ::Unserialize(s, account_registry_proof);
        ::Unserialize(s, note_commitment);
        ::Unserialize(s, value_commitment);
    }
};

struct ConsumedAccountLeafSpend
{
    uint8_t version{WIRE_VERSION};
    uint256 nullifier;
    uint256 account_leaf_commitment;
    shielded::registry::ShieldedAccountRegistrySpendWitness account_registry_proof;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "ConsumedAccountLeafSpend::Serialize invalid version");
        ::Serialize(s, nullifier);
        ::Serialize(s, account_leaf_commitment);
        ::Serialize(s, account_registry_proof);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "ConsumedAccountLeafSpend::Unserialize invalid version");
        ::Unserialize(s, nullifier);
        ::Unserialize(s, account_leaf_commitment);
        ::Unserialize(s, account_registry_proof);
    }
};

struct OutputDescription
{
    uint8_t version{WIRE_VERSION};
    NoteClass note_class{NoteClass::USER};
    uint256 note_commitment;
    uint256 value_commitment;
    std::optional<smile2::CompactPublicAccount> smile_account;
    std::optional<smile2::CompactPublicKeyData> smile_public_key;
    EncryptedNotePayload encrypted_note;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("OutputDescription::Serialize invalid version");
        }
        detail::SerializeEnum(s, static_cast<uint8_t>(note_class));
        ::Serialize(s, value_commitment);
        if (!smile_account.has_value()) {
            throw std::ios_base::failure("OutputDescription::Serialize missing smile_account");
        }
        ::Serialize(s, *smile_account);
        ::Serialize(s, encrypted_note);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        version = WIRE_VERSION;
        detail::UnserializeEnum(s, note_class, IsValidNoteClass, "OutputDescription::Unserialize invalid note_class");
        ::Unserialize(s, value_commitment);
        smile_account.emplace();
        ::Unserialize(s, *smile_account);
        smile_public_key = smile2::ExtractCompactPublicKeyData(*smile_account);
        note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        ::Unserialize(s, encrypted_note);
    }

    template <typename Stream>
    void SerializeWithSharedMetadata(Stream& s,
                                     NoteClass shared_note_class,
                                     ScanDomain shared_scan_domain) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("OutputDescription::SerializeWithSharedMetadata invalid version");
        }
        if (note_class != shared_note_class) {
            throw std::ios_base::failure("OutputDescription::SerializeWithSharedMetadata mismatched note_class");
        }
        if (!smile_account.has_value()) {
            throw std::ios_base::failure("OutputDescription::SerializeWithSharedMetadata missing smile_account");
        }
        if (note_commitment != smile2::ComputeCompactPublicAccountHash(*smile_account)) {
            throw std::ios_base::failure("OutputDescription::SerializeWithSharedMetadata mismatched note_commitment");
        }
        ::Serialize(s, value_commitment);
        ::Serialize(s, *smile_account);
        encrypted_note.SerializeWithSharedScanDomain(s, shared_scan_domain);
    }

    template <typename Stream>
    void UnserializeWithSharedMetadata(Stream& s,
                                       NoteClass shared_note_class,
                                       ScanDomain shared_scan_domain)
    {
        version = WIRE_VERSION;
        note_class = shared_note_class;
        ::Unserialize(s, value_commitment);
        smile_account.emplace();
        ::Unserialize(s, *smile_account);
        smile_public_key = smile2::ExtractCompactPublicKeyData(*smile_account);
        note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        encrypted_note.UnserializeWithSharedScanDomain(s, shared_scan_domain);
    }

    template <typename Stream>
    void SerializeEgressOutput(Stream& s,
                               const uint256& output_binding_digest,
                               uint32_t output_index) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("OutputDescription::SerializeEgressOutput invalid version");
        }
        if (note_class != NoteClass::USER) {
            throw std::ios_base::failure("OutputDescription::SerializeEgressOutput mismatched note_class");
        }
        if (!smile_account.has_value()) {
            throw std::ios_base::failure("OutputDescription::SerializeEgressOutput missing smile_account");
        }
        if (note_commitment != smile2::ComputeCompactPublicAccountHash(*smile_account)) {
            throw std::ios_base::failure("OutputDescription::SerializeEgressOutput mismatched note_commitment");
        }
        if (value_commitment != ComputeV2EgressOutputValueCommitment(output_binding_digest,
                                                                     output_index,
                                                                     note_commitment)) {
            throw std::ios_base::failure("OutputDescription::SerializeEgressOutput mismatched value_commitment");
        }
        ::Serialize(s, *smile_account);
        encrypted_note.SerializeWithSharedScanDomain(s, ScanDomain::OPAQUE);
    }

    template <typename Stream>
    void UnserializeEgressOutput(Stream& s,
                                 const uint256& output_binding_digest,
                                 uint32_t output_index)
    {
        version = WIRE_VERSION;
        note_class = NoteClass::USER;
        smile_account.emplace();
        ::Unserialize(s, *smile_account);
        smile_public_key = smile2::ExtractCompactPublicKeyData(*smile_account);
        note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        value_commitment = ComputeV2EgressOutputValueCommitment(output_binding_digest,
                                                                output_index,
                                                                note_commitment);
        encrypted_note.UnserializeWithSharedScanDomain(s, ScanDomain::OPAQUE);
    }

    template <typename Stream>
    void SerializeIngressReserve(Stream& s,
                                 const uint256& settlement_binding_digest,
                                 uint32_t output_index) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("OutputDescription::SerializeIngressReserve invalid version");
        }
        if (!smile_account.has_value()) {
            throw std::ios_base::failure("OutputDescription::SerializeIngressReserve missing smile_account");
        }
        if (note_class != NoteClass::RESERVE) {
            throw std::ios_base::failure("OutputDescription::SerializeIngressReserve mismatched note_class");
        }
        if (note_commitment != smile2::ComputeCompactPublicAccountHash(*smile_account)) {
            throw std::ios_base::failure("OutputDescription::SerializeIngressReserve mismatched note_commitment");
        }
        if (value_commitment != ComputeV2IngressPlaceholderReserveValueCommitment(
                                    settlement_binding_digest,
                                    output_index,
                                    note_commitment)) {
            throw std::ios_base::failure("OutputDescription::SerializeIngressReserve mismatched value_commitment");
        }
        ::Serialize(s, *smile_account);
        encrypted_note.SerializeWithSharedScanDomain(s, ScanDomain::OPAQUE);
    }

    template <typename Stream>
    void UnserializeIngressReserve(Stream& s,
                                   const uint256& settlement_binding_digest,
                                   uint32_t output_index)
    {
        version = WIRE_VERSION;
        note_class = NoteClass::RESERVE;
        smile_account.emplace();
        ::Unserialize(s, *smile_account);
        smile_public_key = smile2::ExtractCompactPublicKeyData(*smile_account);
        note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        value_commitment = ComputeV2IngressPlaceholderReserveValueCommitment(
            settlement_binding_digest,
            output_index,
            note_commitment);
        encrypted_note.UnserializeWithSharedScanDomain(s, ScanDomain::OPAQUE);
    }

    template <typename Stream>
    void SerializeRebalanceReserve(Stream& s, uint32_t output_index) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("OutputDescription::SerializeRebalanceReserve invalid version");
        }
        if (!smile_account.has_value()) {
            throw std::ios_base::failure("OutputDescription::SerializeRebalanceReserve missing smile_account");
        }
        if (note_class != NoteClass::RESERVE) {
            throw std::ios_base::failure("OutputDescription::SerializeRebalanceReserve mismatched note_class");
        }
        if (note_commitment != smile2::ComputeCompactPublicAccountHash(*smile_account)) {
            throw std::ios_base::failure("OutputDescription::SerializeRebalanceReserve mismatched note_commitment");
        }
        if (value_commitment != ComputeV2RebalanceOutputValueCommitment(output_index, note_commitment)) {
            throw std::ios_base::failure("OutputDescription::SerializeRebalanceReserve mismatched value_commitment");
        }
        ::Serialize(s, *smile_account);
        encrypted_note.SerializeWithSharedScanDomain(s, ScanDomain::OPAQUE);
    }

    template <typename Stream>
    void UnserializeRebalanceReserve(Stream& s, uint32_t output_index)
    {
        version = WIRE_VERSION;
        note_class = NoteClass::RESERVE;
        smile_account.emplace();
        ::Unserialize(s, *smile_account);
        smile_public_key = smile2::ExtractCompactPublicKeyData(*smile_account);
        note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        value_commitment = ComputeV2RebalanceOutputValueCommitment(output_index, note_commitment);
        encrypted_note.UnserializeWithSharedScanDomain(s, ScanDomain::OPAQUE);
    }

    template <typename Stream>
    void SerializeDirectSend(Stream& s,
                             NoteClass shared_note_class,
                             ScanDomain shared_scan_domain) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("OutputDescription::SerializeDirectSend invalid version");
        }
        if (note_class != shared_note_class) {
            throw std::ios_base::failure("OutputDescription::SerializeDirectSend mismatched note_class");
        }
        const auto key_data = smile_public_key.has_value()
            ? smile_public_key
            : (smile_account.has_value()
                   ? std::make_optional(smile2::ExtractCompactPublicKeyData(*smile_account))
                   : std::nullopt);
        if (!key_data.has_value() || !key_data->IsValid()) {
            throw std::ios_base::failure("OutputDescription::SerializeDirectSend missing smile_public_key");
        }
        if (smile_account.has_value() && key_data->public_key != smile_account->public_key) {
            throw std::ios_base::failure("OutputDescription::SerializeDirectSend mismatched smile_public_key");
        }
        if (smile_account.has_value() &&
            note_commitment != smile2::ComputeCompactPublicAccountHash(*smile_account)) {
            throw std::ios_base::failure("OutputDescription::SerializeDirectSend mismatched note_commitment");
        }
        if (smile_account.has_value() &&
            value_commitment != smile2::ComputeSmileOutputCoinHash(smile_account->public_coin)) {
            throw std::ios_base::failure("OutputDescription::SerializeDirectSend mismatched value_commitment");
        }
        ::Serialize(s, note_commitment);
        ::Serialize(s, value_commitment);
        ::Serialize(s, *key_data);
        encrypted_note.SerializeWithSharedScanDomain(s, shared_scan_domain);
    }

    template <typename Stream>
    void UnserializeDirectSend(Stream& s,
                               NoteClass shared_note_class,
                               ScanDomain shared_scan_domain)
    {
        version = WIRE_VERSION;
        note_class = shared_note_class;
        smile_account.reset();
        ::Unserialize(s, note_commitment);
        ::Unserialize(s, value_commitment);
        smile_public_key.emplace();
        ::Unserialize(s, *smile_public_key);
        encrypted_note.UnserializeWithSharedScanDomain(s, shared_scan_domain);
    }
};

struct ReserveDelta
{
    uint8_t version{WIRE_VERSION};
    uint256 l2_id;
    CAmount reserve_delta{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "ReserveDelta::Serialize invalid version");
        ::Serialize(s, l2_id);
        ::Serialize(s, reserve_delta);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "ReserveDelta::Unserialize invalid version");
        ::Unserialize(s, l2_id);
        ::Unserialize(s, reserve_delta);
    }
};

[[nodiscard]] uint256 ComputeV2IngressL2CreditRoot(Span<const BatchLeaf> leaves);
[[nodiscard]] uint256 ComputeV2IngressAggregateFeeCommitment(Span<const BatchLeaf> leaves);
[[nodiscard]] uint256 ComputeV2IngressAggregateReserveCommitment(
    Span<const OutputDescription> reserve_outputs);
[[nodiscard]] uint256 ComputeOutputDescriptionRoot(Span<const OutputDescription> outputs);
[[nodiscard]] uint256 ComputeV2RebalanceStatementDigest(const uint256& settlement_binding_digest,
                                                        Span<const ReserveDelta> reserve_deltas,
                                                        Span<const OutputDescription> reserve_outputs);

struct SendPayload
{
    uint8_t version{WIRE_VERSION};
    uint256 spend_anchor;
    uint256 account_registry_anchor;
    std::vector<SpendDescription> spends;
    SendOutputEncoding output_encoding{SendOutputEncoding::LEGACY};
    NoteClass output_note_class{NoteClass::USER};
    ScanDomain output_scan_domain{ScanDomain::OPAQUE};
    std::vector<OutputDescription> outputs;
    std::vector<AddressLifecycleControl> lifecycle_controls;
    CAmount value_balance{0};
    CAmount fee{0};
    // Preserve the historical pre-lifecycle LEGACY wire form for txid/merkle stability
    // when we deserialize old chain data that omitted the lifecycle_controls count.
    bool legacy_omit_lifecycle_controls_count{false};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("SendPayload::Serialize invalid version");
        }
        const bool elide_value_balance =
            SendOutputEncodingElidesValueBalance(output_encoding) && lifecycle_controls.empty();
        ::Serialize(s, spend_anchor);
        ::Serialize(s, account_registry_anchor);
        detail::SerializeEnum(s, static_cast<uint8_t>(output_encoding));
        if (IsCompactSendOutputEncoding(output_encoding)) {
            detail::SerializeEnum(s, static_cast<uint8_t>(output_note_class));
            detail::SerializeEnum(s, static_cast<uint8_t>(output_scan_domain));
        }
        detail::SerializeBoundedCompactSize(s, spends.size(), MAX_DIRECT_SPENDS, "SendPayload::Serialize oversized spends");
        for (const SpendDescription& spend : spends) {
            ::Serialize(s, spend.nullifier);
            ::Serialize(s, spend.account_leaf_commitment);
            ::Serialize(s, spend.account_registry_proof);
            if (!IsCompactSendOutputEncoding(output_encoding)) {
                ::Serialize(s, spend.value_commitment);
            }
        }
        detail::SerializeBoundedCompactSize(s, outputs.size(), MAX_DIRECT_OUTPUTS, "SendPayload::Serialize oversized outputs");
        for (const OutputDescription& output : outputs) {
            if (IsCompactSendOutputEncoding(output_encoding)) {
                output.SerializeDirectSend(s, output_note_class, output_scan_domain);
            } else {
                ::Serialize(s, output);
            }
        }
        if (output_encoding == SendOutputEncoding::LEGACY) {
            const bool omit_legacy_lifecycle_controls =
                legacy_omit_lifecycle_controls_count && lifecycle_controls.empty();
            if (!omit_legacy_lifecycle_controls) {
                detail::SerializeBoundedCompactSize(s,
                                                   lifecycle_controls.size(),
                                                   MAX_ADDRESS_LIFECYCLE_CONTROLS,
                                                   "SendPayload::Serialize oversized lifecycle_controls");
                for (const AddressLifecycleControl& control : lifecycle_controls) {
                    ::Serialize(s, control);
                }
            }
        }
        if (!elide_value_balance) {
            ::Serialize(s, value_balance);
        }
        ::Serialize(s, fee);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        version = WIRE_VERSION;
        ::Unserialize(s, spend_anchor);
        ::Unserialize(s, account_registry_anchor);
        detail::UnserializeEnum(s, output_encoding, IsValidSendOutputEncoding, "SendPayload::Unserialize invalid output_encoding");
        if (IsCompactSendOutputEncoding(output_encoding)) {
            detail::UnserializeEnum(s, output_note_class, IsValidNoteClass, "SendPayload::Unserialize invalid output_note_class");
            detail::UnserializeEnum(s, output_scan_domain, IsValidScanDomain, "SendPayload::Unserialize invalid output_scan_domain");
        } else {
            output_note_class = NoteClass::USER;
            output_scan_domain = ScanDomain::OPAQUE;
        }
        const uint64_t spend_count = detail::UnserializeBoundedCompactSize(s, MAX_DIRECT_SPENDS, "SendPayload::Unserialize oversized spends");
        spends.assign(spend_count, {});
        for (SpendDescription& spend : spends) {
            spend.version = WIRE_VERSION;
            ::Unserialize(s, spend.nullifier);
            ::Unserialize(s, spend.account_leaf_commitment);
            ::Unserialize(s, spend.account_registry_proof);
            spend.merkle_anchor = spend_anchor;
            spend.note_commitment.SetNull();
            if (IsCompactSendOutputEncoding(output_encoding)) {
                spend.value_commitment.SetNull();
            } else {
                ::Unserialize(s, spend.value_commitment);
            }
        }
        const uint64_t output_count = detail::UnserializeBoundedCompactSize(s, MAX_DIRECT_OUTPUTS, "SendPayload::Unserialize oversized outputs");
        outputs.assign(output_count, {});
        for (OutputDescription& output : outputs) {
            if (IsCompactSendOutputEncoding(output_encoding)) {
                output.UnserializeDirectSend(s, output_note_class, output_scan_domain);
            } else {
                ::Unserialize(s, output);
            }
        }
        if (output_encoding == SendOutputEncoding::LEGACY && !outputs.empty()) {
            // Legacy direct-send outputs carry note-class and scan-domain metadata
            // per output rather than through the shared compact header fields.
            output_note_class = outputs.front().note_class;
            output_scan_domain = outputs.front().encrypted_note.scan_domain;
        }
        legacy_omit_lifecycle_controls_count = false;
        lifecycle_controls.clear();
        const auto parse_value_balance_and_fee = [&]() {
            const bool elide_value_balance =
                SendOutputEncodingElidesValueBalance(output_encoding) && lifecycle_controls.empty();
            if (elide_value_balance) {
                value_balance = 0;
            } else {
                ::Unserialize(s, value_balance);
            }
            ::Unserialize(s, fee);
            if (elide_value_balance) {
                value_balance = fee;
            }
        };
        if (output_encoding == SendOutputEncoding::LEGACY) {
            const auto parse_extended_legacy_tail = [&]() {
                const uint64_t control_count = detail::UnserializeBoundedCompactSize(
                    s,
                    MAX_ADDRESS_LIFECYCLE_CONTROLS,
                    "SendPayload::Unserialize oversized lifecycle_controls");
                lifecycle_controls.assign(control_count, {});
                for (AddressLifecycleControl& control : lifecycle_controls) {
                    ::Unserialize(s, control);
                }
                legacy_omit_lifecycle_controls_count = false;
                parse_value_balance_and_fee();
                if (!IsValid()) {
                    throw std::ios_base::failure("SendPayload::Unserialize invalid lifecycle-aware legacy tail");
                }
            };
            if (!detail::TryParseWithStreamCheckpoint(s, parse_extended_legacy_tail)) {
                lifecycle_controls.clear();
                legacy_omit_lifecycle_controls_count = true;
                parse_value_balance_and_fee();
            }
        } else {
            parse_value_balance_and_fee();
        }
        if (output_encoding == SendOutputEncoding::LEGACY &&
            legacy_omit_lifecycle_controls_count &&
            !IsValid()) {
            throw std::ios_base::failure("SendPayload::Unserialize invalid legacy tail");
        }
    }
};

struct LifecyclePayload
{
    uint8_t version{WIRE_VERSION};
    uint256 transparent_binding_digest;
    std::vector<AddressLifecycleControl> lifecycle_controls;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "LifecyclePayload::Serialize invalid version");
        ::Serialize(s, transparent_binding_digest);
        detail::SerializeBoundedCompactSize(s,
                                           lifecycle_controls.size(),
                                           MAX_ADDRESS_LIFECYCLE_CONTROLS,
                                           "LifecyclePayload::Serialize oversized lifecycle_controls");
        for (const AddressLifecycleControl& control : lifecycle_controls) {
            ::Serialize(s, control);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "LifecyclePayload::Unserialize invalid version");
        ::Unserialize(s, transparent_binding_digest);
        const uint64_t control_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_ADDRESS_LIFECYCLE_CONTROLS,
            "LifecyclePayload::Unserialize oversized lifecycle_controls");
        lifecycle_controls.assign(control_count, {});
        for (AddressLifecycleControl& control : lifecycle_controls) {
            ::Unserialize(s, control);
        }
    }
};

struct IngressBatchPayload
{
    uint8_t version{WIRE_VERSION};
    uint256 spend_anchor;
    uint256 account_registry_anchor;
    std::vector<ConsumedAccountLeafSpend> consumed_spends;
    std::vector<BatchLeaf> ingress_leaves;
    uint256 ingress_root;
    uint256 l2_credit_root;
    ReserveOutputEncoding reserve_output_encoding{ReserveOutputEncoding::EXPLICIT};
    std::vector<OutputDescription> reserve_outputs;
    uint256 aggregate_reserve_commitment;
    uint256 aggregate_fee_commitment;
    CAmount fee{0};
    uint256 settlement_binding_digest;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "IngressBatchPayload::Serialize invalid version");
        const Span<const BatchLeaf> leaf_span{ingress_leaves.data(), ingress_leaves.size()};
        const Span<const OutputDescription> output_span{reserve_outputs.data(), reserve_outputs.size()};
        ::Serialize(s, spend_anchor);
        ::Serialize(s, account_registry_anchor);
        detail::SerializeBoundedCompactSize(s, consumed_spends.size(), MAX_BATCH_NULLIFIERS, "IngressBatchPayload::Serialize oversized consumed_spends");
        for (const ConsumedAccountLeafSpend& spend : consumed_spends) {
            ::Serialize(s, spend);
        }
        detail::SerializeBoundedCompactSize(s, ingress_leaves.size(), MAX_BATCH_LEAVES, "IngressBatchPayload::Serialize oversized ingress_leaves");
        for (const BatchLeaf& leaf : ingress_leaves) {
            ::Serialize(s, leaf);
        }
        if (ingress_root != ComputeBatchLeafRoot(leaf_span)) {
            throw std::ios_base::failure("IngressBatchPayload::Serialize mismatched ingress_root");
        }
        if (l2_credit_root != ComputeV2IngressL2CreditRoot(leaf_span)) {
            throw std::ios_base::failure("IngressBatchPayload::Serialize mismatched l2_credit_root");
        }
        ::Serialize(s, settlement_binding_digest);
        detail::SerializeEnum(s, static_cast<uint8_t>(reserve_output_encoding));
        detail::SerializeBoundedCompactSize(s, reserve_outputs.size(), MAX_BATCH_RESERVE_OUTPUTS, "IngressBatchPayload::Serialize oversized reserve_outputs");
        for (size_t output_index = 0; output_index < reserve_outputs.size(); ++output_index) {
            const OutputDescription& output = reserve_outputs[output_index];
            if (reserve_output_encoding == ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED) {
                output.SerializeIngressReserve(s, settlement_binding_digest, static_cast<uint32_t>(output_index));
            } else {
                output.SerializeWithSharedMetadata(s, NoteClass::RESERVE, ScanDomain::OPAQUE);
            }
        }
        if (aggregate_reserve_commitment != ComputeV2IngressAggregateReserveCommitment(output_span)) {
            throw std::ios_base::failure("IngressBatchPayload::Serialize mismatched aggregate_reserve_commitment");
        }
        if (aggregate_fee_commitment != ComputeV2IngressAggregateFeeCommitment(leaf_span)) {
            throw std::ios_base::failure("IngressBatchPayload::Serialize mismatched aggregate_fee_commitment");
        }
        ::Serialize(s, fee);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "IngressBatchPayload::Unserialize invalid version");
        ::Unserialize(s, spend_anchor);
        ::Unserialize(s, account_registry_anchor);
        const uint64_t spend_count = detail::UnserializeBoundedCompactSize(s, MAX_BATCH_NULLIFIERS, "IngressBatchPayload::Unserialize oversized consumed_spends");
        consumed_spends.assign(spend_count, {});
        for (ConsumedAccountLeafSpend& spend : consumed_spends) {
            ::Unserialize(s, spend);
        }
        const uint64_t leaf_count = detail::UnserializeBoundedCompactSize(s, MAX_BATCH_LEAVES, "IngressBatchPayload::Unserialize oversized ingress_leaves");
        ingress_leaves.assign(leaf_count, {});
        for (BatchLeaf& leaf : ingress_leaves) {
            ::Unserialize(s, leaf);
        }
        ::Unserialize(s, settlement_binding_digest);
        detail::UnserializeEnum(s,
                                reserve_output_encoding,
                                IsValidReserveOutputEncoding,
                                "IngressBatchPayload::Unserialize invalid reserve_output_encoding");
        const uint64_t output_count = detail::UnserializeBoundedCompactSize(s, MAX_BATCH_RESERVE_OUTPUTS, "IngressBatchPayload::Unserialize oversized reserve_outputs");
        reserve_outputs.assign(output_count, {});
        for (size_t output_index = 0; output_index < reserve_outputs.size(); ++output_index) {
            OutputDescription& output = reserve_outputs[output_index];
            if (reserve_output_encoding == ReserveOutputEncoding::INGRESS_PLACEHOLDER_DERIVED) {
                output.UnserializeIngressReserve(s,
                                                 settlement_binding_digest,
                                                 static_cast<uint32_t>(output_index));
            } else {
                output.UnserializeWithSharedMetadata(s, NoteClass::RESERVE, ScanDomain::OPAQUE);
            }
        }
        ::Unserialize(s, fee);
        const Span<const BatchLeaf> leaf_span{ingress_leaves.data(), ingress_leaves.size()};
        const Span<const OutputDescription> output_span{reserve_outputs.data(), reserve_outputs.size()};
        ingress_root = ComputeBatchLeafRoot(leaf_span);
        l2_credit_root = ComputeV2IngressL2CreditRoot(leaf_span);
        aggregate_reserve_commitment = ComputeV2IngressAggregateReserveCommitment(output_span);
        aggregate_fee_commitment = ComputeV2IngressAggregateFeeCommitment(leaf_span);
    }
};

struct EgressBatchPayload
{
    uint8_t version{WIRE_VERSION};
    uint256 settlement_anchor;
    uint256 egress_root;
    uint256 output_binding_digest;
    std::vector<OutputDescription> outputs;
    bool allow_transparent_unwrap{false};
    uint256 settlement_binding_digest;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "EgressBatchPayload::Serialize invalid version");
        const Span<const OutputDescription> output_span{outputs.data(), outputs.size()};
        ::Serialize(s, settlement_anchor);
        if (egress_root != ComputeOutputDescriptionRoot(output_span)) {
            throw std::ios_base::failure("EgressBatchPayload::Serialize mismatched egress_root");
        }
        ::Serialize(s, output_binding_digest);
        detail::SerializeBoundedCompactSize(s, outputs.size(), MAX_EGRESS_OUTPUTS, "EgressBatchPayload::Serialize oversized outputs");
        for (size_t output_index = 0; output_index < outputs.size(); ++output_index) {
            outputs[output_index].SerializeEgressOutput(s,
                                                        output_binding_digest,
                                                        static_cast<uint32_t>(output_index));
        }
        ::Serialize(s, allow_transparent_unwrap);
        ::Serialize(s, settlement_binding_digest);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "EgressBatchPayload::Unserialize invalid version");
        ::Unserialize(s, settlement_anchor);
        ::Unserialize(s, output_binding_digest);
        const uint64_t output_count = detail::UnserializeBoundedCompactSize(s, MAX_EGRESS_OUTPUTS, "EgressBatchPayload::Unserialize oversized outputs");
        outputs.assign(output_count, {});
        for (size_t output_index = 0; output_index < outputs.size(); ++output_index) {
            outputs[output_index].UnserializeEgressOutput(s,
                                                          output_binding_digest,
                                                          static_cast<uint32_t>(output_index));
        }
        ::Unserialize(s, allow_transparent_unwrap);
        ::Unserialize(s, settlement_binding_digest);
        egress_root = ComputeOutputDescriptionRoot(Span<const OutputDescription>{outputs.data(), outputs.size()});
    }
};

struct RebalancePayload
{
    uint8_t version{WIRE_VERSION};
    std::vector<ReserveDelta> reserve_deltas;
    std::vector<OutputDescription> reserve_outputs;
    uint256 settlement_binding_digest;
    uint256 batch_statement_digest;
    bool has_netting_manifest{false};
    NettingManifest netting_manifest;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "RebalancePayload::Serialize invalid version");
        if (!has_netting_manifest) {
            throw std::ios_base::failure("RebalancePayload::Serialize missing netting_manifest");
        }
        detail::SerializeBoundedCompactSize(s, reserve_deltas.size(), MAX_REBALANCE_DOMAINS, "RebalancePayload::Serialize oversized reserve_deltas");
        for (const ReserveDelta& delta : reserve_deltas) {
            ::Serialize(s, delta);
        }
        detail::SerializeBoundedCompactSize(s, reserve_outputs.size(), MAX_BATCH_RESERVE_OUTPUTS, "RebalancePayload::Serialize oversized reserve_outputs");
        for (size_t output_index = 0; output_index < reserve_outputs.size(); ++output_index) {
            reserve_outputs[output_index].SerializeRebalanceReserve(s,
                                                                    static_cast<uint32_t>(output_index));
        }
        const uint256 derived_settlement_binding_digest = ComputeNettingManifestId(netting_manifest);
        if (settlement_binding_digest != derived_settlement_binding_digest) {
            throw std::ios_base::failure("RebalancePayload::Serialize mismatched settlement_binding_digest");
        }
        if (batch_statement_digest != ComputeV2RebalanceStatementDigest(
                                         derived_settlement_binding_digest,
                                         Span<const ReserveDelta>{reserve_deltas.data(), reserve_deltas.size()},
                                         Span<const OutputDescription>{reserve_outputs.data(), reserve_outputs.size()})) {
            throw std::ios_base::failure("RebalancePayload::Serialize mismatched batch_statement_digest");
        }
        ::Serialize(s, netting_manifest);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "RebalancePayload::Unserialize invalid version");
        const uint64_t delta_count = detail::UnserializeBoundedCompactSize(s, MAX_REBALANCE_DOMAINS, "RebalancePayload::Unserialize oversized reserve_deltas");
        reserve_deltas.assign(delta_count, {});
        for (ReserveDelta& delta : reserve_deltas) {
            ::Unserialize(s, delta);
        }
        const uint64_t output_count = detail::UnserializeBoundedCompactSize(s, MAX_BATCH_RESERVE_OUTPUTS, "RebalancePayload::Unserialize oversized reserve_outputs");
        reserve_outputs.assign(output_count, {});
        for (size_t output_index = 0; output_index < reserve_outputs.size(); ++output_index) {
            reserve_outputs[output_index].UnserializeRebalanceReserve(s,
                                                                      static_cast<uint32_t>(output_index));
        }
        has_netting_manifest = true;
        ::Unserialize(s, netting_manifest);
        settlement_binding_digest = ComputeNettingManifestId(netting_manifest);
        batch_statement_digest = ComputeV2RebalanceStatementDigest(
            settlement_binding_digest,
            Span<const ReserveDelta>{reserve_deltas.data(), reserve_deltas.size()},
            Span<const OutputDescription>{reserve_outputs.data(), reserve_outputs.size()});
    }
};

struct SettlementAnchorPayload
{
    uint8_t version{WIRE_VERSION};
    std::vector<uint256> imported_claim_ids;
    std::vector<uint256> imported_adapter_ids;
    std::vector<uint256> proof_receipt_ids;
    std::vector<uint256> batch_statement_digests;
    std::vector<ReserveDelta> reserve_deltas;
    uint256 anchored_netting_manifest_id;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "SettlementAnchorPayload::Serialize invalid version");
        detail::SerializeBoundedCompactSize(s, imported_claim_ids.size(), MAX_SETTLEMENT_REFS, "SettlementAnchorPayload::Serialize oversized imported_claim_ids");
        for (const uint256& id : imported_claim_ids) {
            ::Serialize(s, id);
        }
        detail::SerializeBoundedCompactSize(s, imported_adapter_ids.size(), MAX_SETTLEMENT_REFS, "SettlementAnchorPayload::Serialize oversized imported_adapter_ids");
        for (const uint256& id : imported_adapter_ids) {
            ::Serialize(s, id);
        }
        detail::SerializeBoundedCompactSize(s, proof_receipt_ids.size(), MAX_SETTLEMENT_REFS, "SettlementAnchorPayload::Serialize oversized proof_receipt_ids");
        for (const uint256& id : proof_receipt_ids) {
            ::Serialize(s, id);
        }
        detail::SerializeBoundedCompactSize(s, batch_statement_digests.size(), MAX_SETTLEMENT_REFS, "SettlementAnchorPayload::Serialize oversized batch_statement_digests");
        for (const uint256& digest : batch_statement_digests) {
            ::Serialize(s, digest);
        }
        detail::SerializeBoundedCompactSize(s, reserve_deltas.size(), MAX_REBALANCE_DOMAINS, "SettlementAnchorPayload::Serialize oversized reserve_deltas");
        for (const ReserveDelta& delta : reserve_deltas) {
            ::Serialize(s, delta);
        }
        ::Serialize(s, anchored_netting_manifest_id);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "SettlementAnchorPayload::Unserialize invalid version");
        const uint64_t claim_count = detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "SettlementAnchorPayload::Unserialize oversized imported_claim_ids");
        imported_claim_ids.assign(claim_count, {});
        for (uint256& id : imported_claim_ids) {
            ::Unserialize(s, id);
        }
        const uint64_t adapter_count = detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "SettlementAnchorPayload::Unserialize oversized imported_adapter_ids");
        imported_adapter_ids.assign(adapter_count, {});
        for (uint256& id : imported_adapter_ids) {
            ::Unserialize(s, id);
        }
        const uint64_t receipt_count = detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "SettlementAnchorPayload::Unserialize oversized proof_receipt_ids");
        proof_receipt_ids.assign(receipt_count, {});
        for (uint256& id : proof_receipt_ids) {
            ::Unserialize(s, id);
        }
        const uint64_t digest_count = detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "SettlementAnchorPayload::Unserialize oversized batch_statement_digests");
        batch_statement_digests.assign(digest_count, {});
        for (uint256& digest : batch_statement_digests) {
            ::Unserialize(s, digest);
        }
        const uint64_t delta_count = detail::UnserializeBoundedCompactSize(s, MAX_REBALANCE_DOMAINS, "SettlementAnchorPayload::Unserialize oversized reserve_deltas");
        reserve_deltas.assign(delta_count, {});
        for (ReserveDelta& delta : reserve_deltas) {
            ::Unserialize(s, delta);
        }
        ::Unserialize(s, anchored_netting_manifest_id);
    }
};

struct GenericOpaqueSpendRecord
{
    uint8_t version{WIRE_VERSION};
    uint256 nullifier;
    uint256 account_leaf_commitment;
    shielded::registry::ShieldedAccountRegistrySpendWitness account_registry_proof;
    uint256 note_commitment;
    uint256 value_commitment;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "GenericOpaqueSpendRecord::Serialize invalid version");
        ::Serialize(s, nullifier);
        ::Serialize(s, account_leaf_commitment);
        ::Serialize(s, account_registry_proof);
        ::Serialize(s, note_commitment);
        ::Serialize(s, value_commitment);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "GenericOpaqueSpendRecord::Unserialize invalid version");
        ::Unserialize(s, nullifier);
        ::Unserialize(s, account_leaf_commitment);
        ::Unserialize(s, account_registry_proof);
        ::Unserialize(s, note_commitment);
        ::Unserialize(s, value_commitment);
    }
};

struct GenericOpaqueOutputRecord
{
    uint8_t version{WIRE_VERSION};
    NoteClass note_class{NoteClass::USER};
    ScanDomain scan_domain{ScanDomain::OPAQUE};
    uint256 note_commitment;
    uint256 value_commitment;
    bool has_smile_account{false};
    smile2::CompactPublicAccount smile_account;
    bool has_smile_public_key{false};
    smile2::CompactPublicKeyData smile_public_key;
    EncryptedNotePayload encrypted_note;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "GenericOpaqueOutputRecord::Serialize invalid version");
        detail::SerializeEnum(s, static_cast<uint8_t>(note_class));
        detail::SerializeEnum(s, static_cast<uint8_t>(scan_domain));
        ::Serialize(s, note_commitment);
        ::Serialize(s, value_commitment);
        ::Serialize(s, has_smile_account);
        if (has_smile_account) {
            ::Serialize(s, smile_account);
        }
        ::Serialize(s, has_smile_public_key);
        if (has_smile_public_key) {
            ::Serialize(s, smile_public_key);
        }
        ::Serialize(s, encrypted_note);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "GenericOpaqueOutputRecord::Unserialize invalid version");
        detail::UnserializeEnum(s, note_class, IsValidNoteClass, "GenericOpaqueOutputRecord::Unserialize invalid note_class");
        detail::UnserializeEnum(s, scan_domain, IsValidScanDomain, "GenericOpaqueOutputRecord::Unserialize invalid scan_domain");
        ::Unserialize(s, note_commitment);
        ::Unserialize(s, value_commitment);
        ::Unserialize(s, has_smile_account);
        if (has_smile_account) {
            ::Unserialize(s, smile_account);
        } else {
            smile_account = smile2::CompactPublicAccount{};
        }
        ::Unserialize(s, has_smile_public_key);
        if (has_smile_public_key) {
            ::Unserialize(s, smile_public_key);
        } else {
            smile_public_key = smile2::CompactPublicKeyData{};
        }
        ::Unserialize(s, encrypted_note);
    }
};

struct GenericOpaquePayloadEnvelope
{
    uint8_t version{WIRE_VERSION};
    uint256 spend_anchor;
    uint256 account_registry_anchor;
    uint256 settlement_anchor;
    uint256 ingress_root;
    uint256 l2_credit_root;
    uint256 aggregate_reserve_commitment;
    uint256 aggregate_fee_commitment;
    uint256 output_binding_digest;
    uint256 egress_root;
    uint256 settlement_binding_digest;
    uint256 batch_statement_digest;
    uint256 anchored_netting_manifest_id;
    uint256 transparent_binding_digest;
    SendOutputEncoding output_encoding{SendOutputEncoding::LEGACY};
    NoteClass output_note_class{NoteClass::USER};
    ScanDomain output_scan_domain{ScanDomain::OPAQUE};
    ReserveOutputEncoding reserve_output_encoding{ReserveOutputEncoding::EXPLICIT};
    bool allow_transparent_unwrap{false};
    bool has_netting_manifest{false};
    std::vector<GenericOpaqueSpendRecord> spends;
    std::vector<GenericOpaqueOutputRecord> outputs;
    std::vector<AddressLifecycleControl> lifecycle_controls;
    CAmount value_balance{0};
    CAmount fee{0};
    std::vector<BatchLeaf> ingress_leaves;
    std::vector<ReserveDelta> reserve_deltas;
    NettingManifest netting_manifest;
    std::vector<uint256> imported_claim_ids;
    std::vector<uint256> imported_adapter_ids;
    std::vector<uint256> proof_receipt_ids;
    std::vector<uint256> batch_statement_digests;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "GenericOpaquePayloadEnvelope::Serialize invalid version");
        ::Serialize(s, spend_anchor);
        ::Serialize(s, account_registry_anchor);
        ::Serialize(s, settlement_anchor);
        ::Serialize(s, ingress_root);
        ::Serialize(s, l2_credit_root);
        ::Serialize(s, aggregate_reserve_commitment);
        ::Serialize(s, aggregate_fee_commitment);
        ::Serialize(s, output_binding_digest);
        ::Serialize(s, egress_root);
        ::Serialize(s, settlement_binding_digest);
        ::Serialize(s, batch_statement_digest);
        ::Serialize(s, anchored_netting_manifest_id);
        ::Serialize(s, transparent_binding_digest);
        detail::SerializeEnum(s, static_cast<uint8_t>(output_encoding));
        detail::SerializeEnum(s, static_cast<uint8_t>(output_note_class));
        detail::SerializeEnum(s, static_cast<uint8_t>(output_scan_domain));
        detail::SerializeEnum(s, static_cast<uint8_t>(reserve_output_encoding));
        ::Serialize(s, allow_transparent_unwrap);
        ::Serialize(s, has_netting_manifest);
        detail::SerializeBoundedCompactSize(s, spends.size(), MAX_GENERIC_SPENDS, "GenericOpaquePayloadEnvelope::Serialize oversized spends");
        for (const auto& spend : spends) {
            ::Serialize(s, spend);
        }
        detail::SerializeBoundedCompactSize(s, outputs.size(), MAX_GENERIC_OUTPUTS, "GenericOpaquePayloadEnvelope::Serialize oversized outputs");
        for (const auto& output : outputs) {
            ::Serialize(s, output);
        }
        detail::SerializeBoundedCompactSize(s,
                                           lifecycle_controls.size(),
                                           MAX_ADDRESS_LIFECYCLE_CONTROLS,
                                           "GenericOpaquePayloadEnvelope::Serialize oversized lifecycle_controls");
        for (const auto& control : lifecycle_controls) {
            ::Serialize(s, control);
        }
        ::Serialize(s, value_balance);
        ::Serialize(s, fee);
        detail::SerializeBoundedCompactSize(s, ingress_leaves.size(), MAX_BATCH_LEAVES, "GenericOpaquePayloadEnvelope::Serialize oversized ingress_leaves");
        for (const auto& leaf : ingress_leaves) {
            ::Serialize(s, leaf);
        }
        detail::SerializeBoundedCompactSize(s, reserve_deltas.size(), MAX_REBALANCE_DOMAINS, "GenericOpaquePayloadEnvelope::Serialize oversized reserve_deltas");
        for (const auto& delta : reserve_deltas) {
            ::Serialize(s, delta);
        }
        if (has_netting_manifest) {
            ::Serialize(s, netting_manifest);
        }
        detail::SerializeBoundedCompactSize(s, imported_claim_ids.size(), MAX_SETTLEMENT_REFS, "GenericOpaquePayloadEnvelope::Serialize oversized imported_claim_ids");
        for (const auto& id : imported_claim_ids) {
            ::Serialize(s, id);
        }
        detail::SerializeBoundedCompactSize(s, imported_adapter_ids.size(), MAX_SETTLEMENT_REFS, "GenericOpaquePayloadEnvelope::Serialize oversized imported_adapter_ids");
        for (const auto& id : imported_adapter_ids) {
            ::Serialize(s, id);
        }
        detail::SerializeBoundedCompactSize(s, proof_receipt_ids.size(), MAX_SETTLEMENT_REFS, "GenericOpaquePayloadEnvelope::Serialize oversized proof_receipt_ids");
        for (const auto& id : proof_receipt_ids) {
            ::Serialize(s, id);
        }
        detail::SerializeBoundedCompactSize(s, batch_statement_digests.size(), MAX_SETTLEMENT_REFS, "GenericOpaquePayloadEnvelope::Serialize oversized batch_statement_digests");
        for (const auto& digest : batch_statement_digests) {
            ::Serialize(s, digest);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "GenericOpaquePayloadEnvelope::Unserialize invalid version");
        ::Unserialize(s, spend_anchor);
        ::Unserialize(s, account_registry_anchor);
        ::Unserialize(s, settlement_anchor);
        ::Unserialize(s, ingress_root);
        ::Unserialize(s, l2_credit_root);
        ::Unserialize(s, aggregate_reserve_commitment);
        ::Unserialize(s, aggregate_fee_commitment);
        ::Unserialize(s, output_binding_digest);
        ::Unserialize(s, egress_root);
        ::Unserialize(s, settlement_binding_digest);
        ::Unserialize(s, batch_statement_digest);
        ::Unserialize(s, anchored_netting_manifest_id);
        ::Unserialize(s, transparent_binding_digest);
        detail::UnserializeEnum(s, output_encoding, IsValidSendOutputEncoding, "GenericOpaquePayloadEnvelope::Unserialize invalid output_encoding");
        detail::UnserializeEnum(s, output_note_class, IsValidNoteClass, "GenericOpaquePayloadEnvelope::Unserialize invalid output_note_class");
        detail::UnserializeEnum(s, output_scan_domain, IsValidScanDomain, "GenericOpaquePayloadEnvelope::Unserialize invalid output_scan_domain");
        detail::UnserializeEnum(s, reserve_output_encoding, IsValidReserveOutputEncoding, "GenericOpaquePayloadEnvelope::Unserialize invalid reserve_output_encoding");
        ::Unserialize(s, allow_transparent_unwrap);
        ::Unserialize(s, has_netting_manifest);
        const uint64_t spend_count = detail::UnserializeBoundedCompactSize(s, MAX_GENERIC_SPENDS, "GenericOpaquePayloadEnvelope::Unserialize oversized spends");
        spends.assign(spend_count, {});
        for (auto& spend : spends) {
            ::Unserialize(s, spend);
        }
        const uint64_t output_count = detail::UnserializeBoundedCompactSize(s, MAX_GENERIC_OUTPUTS, "GenericOpaquePayloadEnvelope::Unserialize oversized outputs");
        outputs.assign(output_count, {});
        for (auto& output : outputs) {
            ::Unserialize(s, output);
        }
        const uint64_t control_count = detail::UnserializeBoundedCompactSize(
            s,
            MAX_ADDRESS_LIFECYCLE_CONTROLS,
            "GenericOpaquePayloadEnvelope::Unserialize oversized lifecycle_controls");
        lifecycle_controls.assign(control_count, {});
        for (auto& control : lifecycle_controls) {
            ::Unserialize(s, control);
        }
        ::Unserialize(s, value_balance);
        ::Unserialize(s, fee);
        const uint64_t leaf_count = detail::UnserializeBoundedCompactSize(s, MAX_BATCH_LEAVES, "GenericOpaquePayloadEnvelope::Unserialize oversized ingress_leaves");
        ingress_leaves.assign(leaf_count, {});
        for (auto& leaf : ingress_leaves) {
            ::Unserialize(s, leaf);
        }
        const uint64_t delta_count = detail::UnserializeBoundedCompactSize(s, MAX_REBALANCE_DOMAINS, "GenericOpaquePayloadEnvelope::Unserialize oversized reserve_deltas");
        reserve_deltas.assign(delta_count, {});
        for (auto& delta : reserve_deltas) {
            ::Unserialize(s, delta);
        }
        if (has_netting_manifest) {
            ::Unserialize(s, netting_manifest);
        } else {
            netting_manifest = NettingManifest{};
        }
        const uint64_t claim_count = detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "GenericOpaquePayloadEnvelope::Unserialize oversized imported_claim_ids");
        imported_claim_ids.assign(claim_count, {});
        for (auto& id : imported_claim_ids) {
            ::Unserialize(s, id);
        }
        const uint64_t adapter_count = detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "GenericOpaquePayloadEnvelope::Unserialize oversized imported_adapter_ids");
        imported_adapter_ids.assign(adapter_count, {});
        for (auto& id : imported_adapter_ids) {
            ::Unserialize(s, id);
        }
        const uint64_t receipt_count = detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "GenericOpaquePayloadEnvelope::Unserialize oversized proof_receipt_ids");
        proof_receipt_ids.assign(receipt_count, {});
        for (auto& id : proof_receipt_ids) {
            ::Unserialize(s, id);
        }
        const uint64_t digest_count = detail::UnserializeBoundedCompactSize(s, MAX_SETTLEMENT_REFS, "GenericOpaquePayloadEnvelope::Unserialize oversized batch_statement_digests");
        batch_statement_digests.assign(digest_count, {});
        for (auto& digest : batch_statement_digests) {
            ::Unserialize(s, digest);
        }
    }
};

struct TransactionBundle;
using FamilyPayload =
    std::variant<SendPayload,
                 LifecyclePayload,
                 IngressBatchPayload,
                 EgressBatchPayload,
                 RebalancePayload,
                 SettlementAnchorPayload>;

struct TransactionBundleWireView
{
    TransactionHeader header;
    std::vector<ProofShardDescriptor> proof_shards;
    std::vector<OutputChunkDescriptor> output_chunks;
    std::vector<uint8_t> proof_payload;
};

[[nodiscard]] TransactionFamily GetPayloadFamily(const FamilyPayload& payload);
[[nodiscard]] bool IsGenericTransactionFamily(TransactionFamily family);
[[nodiscard]] bool IsGenericPostforkSettlementBindingKind(SettlementBindingKind kind);
[[nodiscard]] bool IsGenericShieldedSettlementBindingKind(SettlementBindingKind kind);
[[nodiscard]] bool IsGenericBridgeSettlementBindingKind(SettlementBindingKind kind);
[[nodiscard]] bool WireFamilyMatchesPayload(TransactionFamily wire_family, const FamilyPayload& payload);
[[nodiscard]] TransactionFamily GetBundleSemanticFamily(const TransactionBundle& bundle);
[[nodiscard]] bool BundleHasSemanticFamily(const TransactionBundle& bundle, TransactionFamily family);
[[nodiscard]] bool UseGenericV2WireFamily(const Consensus::Params* consensus, int32_t validation_height);
[[nodiscard]] bool UseGenericV2ProofEnvelope(const Consensus::Params* consensus, int32_t validation_height);
[[nodiscard]] bool UseGenericV2SettlementBinding(const Consensus::Params* consensus, int32_t validation_height);
[[nodiscard]] bool IsGenericOpaqueProofComponentKind(ProofComponentKind kind);
[[nodiscard]] bool IsGenericOpaqueProofKind(ProofKind kind);
[[nodiscard]] bool IsGenericSmileProofKind(ProofKind kind);
[[nodiscard]] bool IsGenericBridgeProofKind(ProofKind kind);
[[nodiscard]] TransactionFamily GetWireTransactionFamilyForValidationHeight(TransactionFamily semantic_family,
                                                                           const Consensus::Params* consensus,
                                                                           int32_t validation_height);
[[nodiscard]] ProofComponentKind GetWireProofComponentKindForValidationHeight(
    ProofComponentKind semantic_component_kind,
    const Consensus::Params* consensus,
    int32_t validation_height);
[[nodiscard]] ProofKind GetWireProofKindForValidationHeight(TransactionFamily semantic_family,
                                                            ProofKind semantic_proof_kind,
                                                            const Consensus::Params* consensus,
                                                            int32_t validation_height);
[[nodiscard]] SettlementBindingKind GetWireSettlementBindingKindForValidationHeight(
    TransactionFamily semantic_family,
    SettlementBindingKind semantic_binding_kind,
    const Consensus::Params* consensus,
    int32_t validation_height);
[[nodiscard]] std::vector<uint8_t> SerializePayloadBytes(const FamilyPayload& payload,
                                                         TransactionFamily semantic_family);
[[nodiscard]] std::optional<GenericOpaquePayloadEnvelope> DeserializeOpaquePayloadEnvelopeWire(
    Span<const uint8_t> bytes,
    bool strip_padding = true);
[[nodiscard]] FamilyPayload DeserializeOpaquePayload(Span<const uint8_t> bytes,
                                                     const TransactionHeader& header);
[[nodiscard]] std::vector<uint8_t> SerializeProofPayloadBytes(const TransactionBundle& bundle);
[[nodiscard]] std::vector<uint8_t> DeserializeProofPayloadBytes(
    Span<const uint8_t> bytes,
    const TransactionHeader& header,
    const FamilyPayload& payload,
    Span<const ProofShardDescriptor> proof_shards);
[[nodiscard]] TransactionBundleWireView BuildTransactionBundleWireView(const TransactionBundle& bundle);
[[nodiscard]] bool NormalizeGenericWireTransactionBundle(TransactionBundle& bundle,
                                                         const TransactionHeader& wire_header,
                                                         std::vector<ProofShardDescriptor> wire_proof_shards,
                                                         uint32_t wire_output_chunk_count,
                                                         std::vector<OutputChunkDescriptor> wire_output_chunks,
                                                         std::vector<uint8_t> raw_proof_payload);
[[nodiscard]] bool UseDerivedGenericOutputChunkWire(const TransactionHeader& header,
                                                    const FamilyPayload& payload);
[[nodiscard]] std::optional<std::vector<OutputChunkDescriptor>> BuildDerivedGenericOutputChunks(
    const FamilyPayload& payload);
template <typename Stream>
void SerializePayload(Stream& s, const FamilyPayload& payload, TransactionFamily family);
template <typename Stream>
FamilyPayload DeserializePayload(Stream& s, TransactionFamily family);
void PostProcessTransactionBundle(TransactionBundle& bundle);

struct TransactionBundle
{
    uint8_t version{WIRE_VERSION};
    TransactionHeader header;
    FamilyPayload payload;
    std::vector<ProofShardDescriptor> proof_shards;
    std::vector<OutputChunkDescriptor> output_chunks;
    std::vector<uint8_t> proof_payload;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const auto wire_view = BuildTransactionBundleWireView(*this);
        detail::SerializeVersion(s, version, "TransactionBundle::Serialize invalid version");
        if (!WireFamilyMatchesPayload(header.family_id, payload)) {
            throw std::ios_base::failure("TransactionBundle::Serialize family/payload mismatch");
        }
        ::Serialize(s, wire_view.header);
        if (IsGenericTransactionFamily(wire_view.header.family_id)) {
            detail::SerializeBytes(s,
                                   SerializePayloadBytes(payload, GetPayloadFamily(payload)),
                                   MAX_OPAQUE_FAMILY_PAYLOAD_BYTES,
                                   "TransactionBundle::Serialize oversized opaque payload");
        } else {
            SerializePayload(s, payload, GetPayloadFamily(payload));
        }
        detail::SerializeBoundedCompactSize(s, wire_view.proof_shards.size(), MAX_PROOF_SHARDS, "TransactionBundle::Serialize oversized proof_shards");
        for (const ProofShardDescriptor& descriptor : wire_view.proof_shards) {
            ::Serialize(s, descriptor);
        }
        detail::SerializeBoundedCompactSize(s, wire_view.output_chunks.size(), MAX_OUTPUT_CHUNKS, "TransactionBundle::Serialize oversized output_chunks");
        if (!UseDerivedGenericOutputChunkWire(wire_view.header, payload)) {
            for (const OutputChunkDescriptor& descriptor : wire_view.output_chunks) {
                ::Serialize(s, descriptor);
            }
        }
        detail::SerializeBytes(s,
                               wire_view.proof_payload,
                               MAX_PROOF_PAYLOAD_BYTES,
                               "TransactionBundle::Serialize oversized proof_payload");
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "TransactionBundle::Unserialize invalid version");
        TransactionHeader wire_header;
        ::Unserialize(s, wire_header);
        if (IsGenericTransactionFamily(wire_header.family_id)) {
            std::vector<uint8_t> payload_bytes;
            detail::UnserializeBytes(s,
                                     payload_bytes,
                                     MAX_OPAQUE_FAMILY_PAYLOAD_BYTES,
                                     "TransactionBundle::Unserialize oversized opaque payload");
            payload = DeserializeOpaquePayload(
                Span<const uint8_t>{payload_bytes.data(), payload_bytes.size()},
                wire_header);
        } else {
            payload = DeserializePayload(s, wire_header.family_id);
        }
        const uint64_t proof_shard_count = detail::UnserializeBoundedCompactSize(s, MAX_PROOF_SHARDS, "TransactionBundle::Unserialize oversized proof_shards");
        std::vector<ProofShardDescriptor> wire_proof_shards(proof_shard_count);
        for (ProofShardDescriptor& descriptor : wire_proof_shards) {
            ::Unserialize(s, descriptor);
        }
        const uint64_t output_chunk_count = detail::UnserializeBoundedCompactSize(s, MAX_OUTPUT_CHUNKS, "TransactionBundle::Unserialize oversized output_chunks");
        std::vector<OutputChunkDescriptor> wire_output_chunks;
        if (UseDerivedGenericOutputChunkWire(wire_header, payload)) {
            auto derived_output_chunks = BuildDerivedGenericOutputChunks(payload);
            if (!derived_output_chunks.has_value()) {
                throw std::ios_base::failure("TransactionBundle::Unserialize invalid derived output_chunks");
            }
            wire_output_chunks = std::move(*derived_output_chunks);
        } else {
            wire_output_chunks.assign(output_chunk_count, {});
            for (OutputChunkDescriptor& descriptor : wire_output_chunks) {
                ::Unserialize(s, descriptor);
            }
        }
        std::vector<uint8_t> raw_proof_payload;
        detail::UnserializeBytes(s,
                                 raw_proof_payload,
                                 MAX_PROOF_PAYLOAD_BYTES,
                                 "TransactionBundle::Unserialize oversized proof_payload");
        if (IsGenericTransactionFamily(wire_header.family_id)) {
            if (!NormalizeGenericWireTransactionBundle(*this,
                                                       wire_header,
                                                       std::move(wire_proof_shards),
                                                       static_cast<uint32_t>(output_chunk_count),
                                                       std::move(wire_output_chunks),
                                                       std::move(raw_proof_payload))) {
                throw std::ios_base::failure("TransactionBundle::Unserialize invalid generic wire metadata");
            }
        } else {
            header = wire_header;
            proof_shards = std::move(wire_proof_shards);
            output_chunks = std::move(wire_output_chunks);
            proof_payload = DeserializeProofPayloadBytes(
                Span<const uint8_t>{raw_proof_payload.data(), raw_proof_payload.size()},
                header,
                payload,
                Span<const ProofShardDescriptor>{proof_shards.data(), proof_shards.size()});
        }
        PostProcessTransactionBundle(*this);
    }
};

struct V2RebalanceBuildInput
{
    std::vector<ReserveDelta> reserve_deltas;
    std::vector<OutputDescription> reserve_outputs;
    NettingManifest netting_manifest;
};

struct V2RebalanceBuildResult
{
    TransactionBundle bundle;
    uint256 netting_manifest_id;
};

template <typename Stream>
void SerializePayload(Stream& s, const FamilyPayload& payload, TransactionFamily family)
{
    switch (family) {
    case TransactionFamily::V2_SEND:
        ::Serialize(s, std::get<SendPayload>(payload));
        break;
    case TransactionFamily::V2_LIFECYCLE:
        ::Serialize(s, std::get<LifecyclePayload>(payload));
        break;
    case TransactionFamily::V2_INGRESS_BATCH:
        ::Serialize(s, std::get<IngressBatchPayload>(payload));
        break;
    case TransactionFamily::V2_EGRESS_BATCH:
        ::Serialize(s, std::get<EgressBatchPayload>(payload));
        break;
    case TransactionFamily::V2_REBALANCE:
        ::Serialize(s, std::get<RebalancePayload>(payload));
        break;
    case TransactionFamily::V2_SETTLEMENT_ANCHOR:
        ::Serialize(s, std::get<SettlementAnchorPayload>(payload));
        break;
    case TransactionFamily::V2_GENERIC:
        throw std::ios_base::failure("TransactionBundle::Serialize generic family requires opaque payload encoding");
    }
}

template <typename Stream>
FamilyPayload DeserializePayload(Stream& s, TransactionFamily family)
{
    switch (family) {
    case TransactionFamily::V2_SEND: {
        SendPayload payload_obj;
        ::Unserialize(s, payload_obj);
        return payload_obj;
    }
    case TransactionFamily::V2_LIFECYCLE: {
        LifecyclePayload payload_obj;
        ::Unserialize(s, payload_obj);
        return payload_obj;
    }
    case TransactionFamily::V2_INGRESS_BATCH: {
        IngressBatchPayload payload_obj;
        ::Unserialize(s, payload_obj);
        return payload_obj;
    }
    case TransactionFamily::V2_EGRESS_BATCH: {
        EgressBatchPayload payload_obj;
        ::Unserialize(s, payload_obj);
        return payload_obj;
    }
    case TransactionFamily::V2_REBALANCE: {
        RebalancePayload payload_obj;
        ::Unserialize(s, payload_obj);
        return payload_obj;
    }
    case TransactionFamily::V2_SETTLEMENT_ANCHOR: {
        SettlementAnchorPayload payload_obj;
        ::Unserialize(s, payload_obj);
        return payload_obj;
    }
    case TransactionFamily::V2_GENERIC:
        throw std::ios_base::failure("TransactionBundle::Unserialize generic family requires opaque payload decoding");
    }
    throw std::ios_base::failure("TransactionBundle::Unserialize invalid family_id");
}

[[nodiscard]] uint256 ComputeSpendDescriptionHash(const SpendDescription& spend);
[[nodiscard]] uint256 ComputeSpendRoot(Span<const SpendDescription> spends);
[[nodiscard]] uint256 ComputeOutputDescriptionHash(const OutputDescription& output);
[[nodiscard]] uint256 ComputeReserveDeltaHash(const ReserveDelta& delta);
[[nodiscard]] uint256 ComputeReserveDeltaRoot(Span<const ReserveDelta> deltas);
[[nodiscard]] bool ReserveDeltaSetIsCanonical(Span<const ReserveDelta> deltas);

[[nodiscard]] uint256 ComputeSendPayloadDigest(const SendPayload& payload);
[[nodiscard]] uint256 ComputeLifecyclePayloadDigest(const LifecyclePayload& payload);
[[nodiscard]] uint256 ComputeIngressBatchPayloadDigest(const IngressBatchPayload& payload);
[[nodiscard]] uint256 ComputeEgressBatchPayloadDigest(const EgressBatchPayload& payload);
[[nodiscard]] uint256 ComputeRebalancePayloadDigest(const RebalancePayload& payload);
[[nodiscard]] uint256 ComputeSettlementAnchorPayloadDigest(const SettlementAnchorPayload& payload);
[[nodiscard]] uint256 ComputePayloadDigest(const FamilyPayload& payload);
[[nodiscard]] uint256 ComputeTransactionBundleId(const TransactionBundle& bundle);

[[nodiscard]] uint256 ComputeOutputChunkScanHintCommitment(Span<const OutputDescription> outputs);
[[nodiscard]] uint256 ComputeOutputChunkCiphertextCommitment(Span<const OutputDescription> outputs);
[[nodiscard]] std::optional<OutputChunkDescriptor> BuildOutputChunkDescriptor(Span<const OutputDescription> outputs,
                                                                              uint32_t first_output_index);
[[nodiscard]] std::optional<V2RebalanceBuildResult> BuildDeterministicV2RebalanceBundle(
    const V2RebalanceBuildInput& input,
    std::string& reject_reason,
    const Consensus::Params* consensus = nullptr,
    int32_t validation_height = std::numeric_limits<int32_t>::max());
[[nodiscard]] bool OutputChunkMatchesOutputs(const OutputChunkDescriptor& descriptor,
                                             Span<const OutputDescription> outputs);
[[nodiscard]] bool ProofShardCoverageIsCanonical(Span<const ProofShardDescriptor> proof_shards, size_t leaf_count, size_t proof_payload_size);
[[nodiscard]] bool OutputChunkCoverageIsCanonical(Span<const OutputChunkDescriptor> output_chunks, size_t output_count);
[[nodiscard]] bool TransactionBundleOutputChunksAreCanonical(const TransactionBundle& bundle);

} // namespace shielded::v2

#endif // BTX_SHIELDED_V2_BUNDLE_H
