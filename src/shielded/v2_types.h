// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_V2_TYPES_H
#define BTX_SHIELDED_V2_TYPES_H

#include <consensus/amount.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <vector>

namespace shielded::v2 {

static constexpr uint8_t WIRE_VERSION{1};
static constexpr uint8_t SCAN_HINT_VERSION{1};
static constexpr size_t SCAN_HINT_BYTES{4};
static constexpr size_t MAX_NOTE_MEMO_BYTES{512};
static constexpr size_t MAX_NOTE_CIPHERTEXT_BYTES{4096};
static constexpr uint64_t MAX_PROOF_METADATA_BYTES{256};
static constexpr uint64_t MAX_NETTING_DOMAINS{64};

enum class TransactionFamily : uint8_t {
    V2_SEND = 1,
    V2_INGRESS_BATCH = 2,
    V2_EGRESS_BATCH = 3,
    V2_REBALANCE = 4,
    V2_SETTLEMENT_ANCHOR = 5,
    V2_GENERIC = 6,
    V2_LIFECYCLE = 7,
};

// Reserved scaffolding id for a future spend-path recovery semantic family.
// Payload and consensus acceptance are intentionally not implemented in this
// step; this constant only reserves the identifier and lets tests cover the
// current rejected behavior.
static constexpr TransactionFamily V2_SPEND_PATH_RECOVERY{static_cast<TransactionFamily>(8)};

enum class NoteClass : uint8_t {
    USER = 1,
    RESERVE = 2,
    OPERATOR = 3,
    SETTLEMENT = 4,
};

#ifdef OPAQUE
#undef OPAQUE
#endif

enum class ScanDomain : uint8_t {
    OPAQUE = 0,
    USER = 1,
    RESERVE = 2,
    OPERATOR = 3,
    BATCH = 4,
};

enum class ProofKind : uint8_t {
    NONE = 0,
    DIRECT_MATRICT = 1,
    BATCH_MATRICT = 2,
    IMPORTED_RECEIPT = 3,
    IMPORTED_CLAIM = 4,
    DIRECT_SMILE = 5,
    BATCH_SMILE = 6,
    GENERIC_SMILE = 7,
    GENERIC_BRIDGE = 8,
    GENERIC_OPAQUE = 9,
};

enum class ProofComponentKind : uint8_t {
    NONE = 0,
    MATRICT = 1,
    RANGE = 2,
    BALANCE = 3,
    RECEIPT = 4,
    SMILE_MEMBERSHIP = 5,
    SMILE_BALANCE = 6,
    GENERIC_OPAQUE = 7,
};

enum class SettlementBindingKind : uint8_t {
    NONE = 0,
    NATIVE_BATCH = 1,
    BRIDGE_RECEIPT = 2,
    BRIDGE_CLAIM = 3,
    NETTING_MANIFEST = 4,
    GENERIC_SHIELDED = 5,
    GENERIC_BRIDGE = 6,
    GENERIC_POSTFORK = 7,
};

[[nodiscard]] bool IsValidTransactionFamily(TransactionFamily family);
[[nodiscard]] bool IsValidNoteClass(NoteClass note_class);
[[nodiscard]] bool IsValidScanDomain(ScanDomain domain);
[[nodiscard]] bool IsValidProofKind(ProofKind kind);
[[nodiscard]] bool IsValidProofComponentKind(ProofComponentKind kind);
[[nodiscard]] bool IsValidSettlementBindingKind(SettlementBindingKind kind);
[[nodiscard]] uint256 ComputeLegacyPayloadEphemeralKey(Span<const uint8_t> ciphertext);

[[nodiscard]] const char* GetTransactionFamilyName(TransactionFamily family);
[[nodiscard]] const char* GetNoteClassName(NoteClass note_class);
[[nodiscard]] const char* GetScanDomainName(ScanDomain domain);
[[nodiscard]] const char* GetProofKindName(ProofKind kind);
[[nodiscard]] const char* GetProofComponentKindName(ProofComponentKind kind);
[[nodiscard]] const char* GetSettlementBindingKindName(SettlementBindingKind kind);

namespace detail {

template <typename Stream>
void SerializeEnum(Stream& s, uint8_t value)
{
    ::Serialize(s, value);
}

template <typename Stream, typename Enum, typename Validator>
void UnserializeEnum(Stream& s, Enum& out, Validator&& validator, const char* error)
{
    uint8_t raw{0};
    ::Unserialize(s, raw);
    out = static_cast<Enum>(raw);
    if (!validator(out)) {
        throw std::ios_base::failure(error);
    }
}

template <typename Stream>
void SerializeVersion(Stream& s, uint8_t version, const char* error)
{
    if (version != WIRE_VERSION) {
        throw std::ios_base::failure(error);
    }
    ::Serialize(s, version);
}

template <typename Stream>
void UnserializeVersion(Stream& s, uint8_t& version, const char* error)
{
    ::Unserialize(s, version);
    if (version != WIRE_VERSION) {
        throw std::ios_base::failure(error);
    }
}

template <typename Stream>
void SerializeBoundedCompactSize(Stream& s, uint64_t size, uint64_t max_size, const char* error)
{
    if (size > max_size) {
        throw std::ios_base::failure(error);
    }
    ::Serialize(s, COMPACTSIZE(size));
}

template <typename Stream>
uint64_t UnserializeBoundedCompactSize(Stream& s, uint64_t max_size, const char* error)
{
    uint64_t size{0};
    ::Unserialize(s, COMPACTSIZE(size));
    if (size > max_size) {
        throw std::ios_base::failure(error);
    }
    return size;
}

template <typename Stream>
void SerializeBytes(Stream& s, const std::vector<uint8_t>& bytes, uint64_t max_size, const char* error)
{
    SerializeBoundedCompactSize(s, bytes.size(), max_size, error);
    if (!bytes.empty()) {
        s.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    }
}

template <typename Stream>
void UnserializeBytes(Stream& s, std::vector<uint8_t>& bytes, uint64_t max_size, const char* error)
{
    const uint64_t size = UnserializeBoundedCompactSize(s, max_size, error);
    bytes.resize(size);
    if (size > 0) {
        s.read(AsWritableBytes(Span<uint8_t>{bytes.data(), bytes.size()}));
    }
}

} // namespace detail

struct EncryptedNotePayload
{
    uint8_t version{WIRE_VERSION};
    uint8_t scan_hint_version{SCAN_HINT_VERSION};
    ScanDomain scan_domain{ScanDomain::USER};
    std::array<uint8_t, SCAN_HINT_BYTES> scan_hint{};
    uint256 ephemeral_key;
    std::vector<uint8_t> ciphertext;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("EncryptedNotePayload::Serialize invalid version");
        }
        if (scan_hint_version != SCAN_HINT_VERSION) {
            throw std::ios_base::failure("EncryptedNotePayload::Serialize invalid scan_hint_version");
        }
        detail::SerializeEnum(s, static_cast<uint8_t>(scan_domain));
        ::Serialize(s, scan_hint);
        detail::SerializeBytes(s, ciphertext, MAX_NOTE_CIPHERTEXT_BYTES, "EncryptedNotePayload::Serialize oversized ciphertext");
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        version = WIRE_VERSION;
        scan_hint_version = SCAN_HINT_VERSION;
        detail::UnserializeEnum(s, scan_domain, IsValidScanDomain, "EncryptedNotePayload::Unserialize invalid scan_domain");
        ::Unserialize(s, scan_hint);
        detail::UnserializeBytes(s, ciphertext, MAX_NOTE_CIPHERTEXT_BYTES, "EncryptedNotePayload::Unserialize oversized ciphertext");
        ephemeral_key = ComputeLegacyPayloadEphemeralKey(ciphertext);
    }

    template <typename Stream>
    void SerializeWithSharedScanDomain(Stream& s, ScanDomain shared_scan_domain) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("EncryptedNotePayload::SerializeWithSharedScanDomain invalid version");
        }
        if (scan_hint_version != SCAN_HINT_VERSION) {
            throw std::ios_base::failure("EncryptedNotePayload::SerializeWithSharedScanDomain invalid scan_hint_version");
        }
        if (scan_domain != shared_scan_domain) {
            throw std::ios_base::failure("EncryptedNotePayload::SerializeWithSharedScanDomain mismatched scan_domain");
        }
        ::Serialize(s, scan_hint);
        detail::SerializeBytes(s, ciphertext, MAX_NOTE_CIPHERTEXT_BYTES,
                               "EncryptedNotePayload::SerializeWithSharedScanDomain oversized ciphertext");
    }

    template <typename Stream>
    void UnserializeWithSharedScanDomain(Stream& s, ScanDomain shared_scan_domain)
    {
        version = WIRE_VERSION;
        scan_hint_version = SCAN_HINT_VERSION;
        scan_domain = shared_scan_domain;
        ::Unserialize(s, scan_hint);
        detail::UnserializeBytes(s, ciphertext, MAX_NOTE_CIPHERTEXT_BYTES,
                                 "EncryptedNotePayload::UnserializeWithSharedScanDomain oversized ciphertext");
        ephemeral_key = ComputeLegacyPayloadEphemeralKey(ciphertext);
    }
};

struct Note
{
    uint8_t version{WIRE_VERSION};
    NoteClass note_class{NoteClass::USER};
    CAmount value{0};
    uint256 owner_commitment;
    uint256 rho;
    uint256 rseed;
    uint256 source_binding;
    std::vector<uint8_t> memo;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "Note::Serialize invalid version");
        detail::SerializeEnum(s, static_cast<uint8_t>(note_class));
        ::Serialize(s, value);
        ::Serialize(s, owner_commitment);
        ::Serialize(s, rho);
        ::Serialize(s, rseed);
        ::Serialize(s, source_binding);
        detail::SerializeBytes(s, memo, MAX_NOTE_MEMO_BYTES, "Note::Serialize oversized memo");
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "Note::Unserialize invalid version");
        detail::UnserializeEnum(s, note_class, IsValidNoteClass, "Note::Unserialize invalid note_class");
        ::Unserialize(s, value);
        ::Unserialize(s, owner_commitment);
        ::Unserialize(s, rho);
        ::Unserialize(s, rseed);
        ::Unserialize(s, source_binding);
        detail::UnserializeBytes(s, memo, MAX_NOTE_MEMO_BYTES, "Note::Unserialize oversized memo");
    }
};

struct ProofEnvelope
{
    uint8_t version{WIRE_VERSION};
    ProofKind proof_kind{ProofKind::NONE};
    ProofComponentKind membership_proof_kind{ProofComponentKind::NONE};
    ProofComponentKind amount_proof_kind{ProofComponentKind::NONE};
    ProofComponentKind balance_proof_kind{ProofComponentKind::NONE};
    SettlementBindingKind settlement_binding_kind{SettlementBindingKind::NONE};
    uint256 statement_digest;
    uint256 extension_digest;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "ProofEnvelope::Serialize invalid version");
        detail::SerializeEnum(s, static_cast<uint8_t>(proof_kind));
        detail::SerializeEnum(s, static_cast<uint8_t>(membership_proof_kind));
        detail::SerializeEnum(s, static_cast<uint8_t>(amount_proof_kind));
        detail::SerializeEnum(s, static_cast<uint8_t>(balance_proof_kind));
        detail::SerializeEnum(s, static_cast<uint8_t>(settlement_binding_kind));
        ::Serialize(s, statement_digest);
        ::Serialize(s, extension_digest);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "ProofEnvelope::Unserialize invalid version");
        detail::UnserializeEnum(s, proof_kind, IsValidProofKind, "ProofEnvelope::Unserialize invalid proof_kind");
        detail::UnserializeEnum(s, membership_proof_kind, IsValidProofComponentKind, "ProofEnvelope::Unserialize invalid membership_proof_kind");
        detail::UnserializeEnum(s, amount_proof_kind, IsValidProofComponentKind, "ProofEnvelope::Unserialize invalid amount_proof_kind");
        detail::UnserializeEnum(s, balance_proof_kind, IsValidProofComponentKind, "ProofEnvelope::Unserialize invalid balance_proof_kind");
        detail::UnserializeEnum(s, settlement_binding_kind, IsValidSettlementBindingKind, "ProofEnvelope::Unserialize invalid settlement_binding_kind");
        ::Unserialize(s, statement_digest);
        ::Unserialize(s, extension_digest);
    }
};

struct BatchLeaf
{
    uint8_t version{WIRE_VERSION};
    TransactionFamily family_id{TransactionFamily::V2_INGRESS_BATCH};
    uint256 l2_id;
    uint256 destination_commitment;
    uint256 amount_commitment;
    uint256 fee_commitment;
    uint32_t position{0};
    uint256 nonce;
    uint256 settlement_domain;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "BatchLeaf::Serialize invalid version");
        detail::SerializeEnum(s, static_cast<uint8_t>(family_id));
        ::Serialize(s, l2_id);
        ::Serialize(s, destination_commitment);
        ::Serialize(s, amount_commitment);
        ::Serialize(s, fee_commitment);
        ::Serialize(s, position);
        ::Serialize(s, nonce);
        ::Serialize(s, settlement_domain);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "BatchLeaf::Unserialize invalid version");
        detail::UnserializeEnum(s, family_id, IsValidTransactionFamily, "BatchLeaf::Unserialize invalid family_id");
        ::Unserialize(s, l2_id);
        ::Unserialize(s, destination_commitment);
        ::Unserialize(s, amount_commitment);
        ::Unserialize(s, fee_commitment);
        ::Unserialize(s, position);
        ::Unserialize(s, nonce);
        ::Unserialize(s, settlement_domain);
    }
};

struct ProofShardDescriptor
{
    uint8_t version{WIRE_VERSION};
    uint256 settlement_domain;
    uint32_t first_leaf_index{0};
    uint32_t leaf_count{0};
    uint256 leaf_subroot;
    uint256 nullifier_commitment;
    uint256 value_commitment;
    uint256 statement_digest;
    std::vector<uint8_t> proof_metadata;
    uint32_t proof_payload_offset{0};
    uint32_t proof_payload_size{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "ProofShardDescriptor::Serialize invalid version");
        ::Serialize(s, settlement_domain);
        ::Serialize(s, first_leaf_index);
        ::Serialize(s, leaf_count);
        ::Serialize(s, leaf_subroot);
        ::Serialize(s, nullifier_commitment);
        ::Serialize(s, value_commitment);
        ::Serialize(s, statement_digest);
        detail::SerializeBytes(s, proof_metadata, MAX_PROOF_METADATA_BYTES, "ProofShardDescriptor::Serialize oversized proof_metadata");
        ::Serialize(s, proof_payload_offset);
        ::Serialize(s, proof_payload_size);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "ProofShardDescriptor::Unserialize invalid version");
        ::Unserialize(s, settlement_domain);
        ::Unserialize(s, first_leaf_index);
        ::Unserialize(s, leaf_count);
        ::Unserialize(s, leaf_subroot);
        ::Unserialize(s, nullifier_commitment);
        ::Unserialize(s, value_commitment);
        ::Unserialize(s, statement_digest);
        detail::UnserializeBytes(s, proof_metadata, MAX_PROOF_METADATA_BYTES, "ProofShardDescriptor::Unserialize oversized proof_metadata");
        ::Unserialize(s, proof_payload_offset);
        ::Unserialize(s, proof_payload_size);
    }
};

struct OutputChunkDescriptor
{
    uint8_t version{WIRE_VERSION};
    ScanDomain scan_domain{ScanDomain::USER};
    uint32_t first_output_index{0};
    uint32_t output_count{0};
    uint32_t ciphertext_bytes{0};
    uint256 scan_hint_commitment;
    uint256 ciphertext_commitment;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "OutputChunkDescriptor::Serialize invalid version");
        detail::SerializeEnum(s, static_cast<uint8_t>(scan_domain));
        ::Serialize(s, first_output_index);
        ::Serialize(s, output_count);
        ::Serialize(s, ciphertext_bytes);
        ::Serialize(s, scan_hint_commitment);
        ::Serialize(s, ciphertext_commitment);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "OutputChunkDescriptor::Unserialize invalid version");
        detail::UnserializeEnum(s, scan_domain, IsValidScanDomain, "OutputChunkDescriptor::Unserialize invalid scan_domain");
        ::Unserialize(s, first_output_index);
        ::Unserialize(s, output_count);
        ::Unserialize(s, ciphertext_bytes);
        ::Unserialize(s, scan_hint_commitment);
        ::Unserialize(s, ciphertext_commitment);
    }
};

struct NettingManifestEntry
{
    uint256 l2_id;
    CAmount net_reserve_delta{0};

    [[nodiscard]] bool IsValid() const;

    SERIALIZE_METHODS(NettingManifestEntry, obj)
    {
        READWRITE(obj.l2_id, obj.net_reserve_delta);
    }
};

struct NettingManifest
{
    uint8_t version{WIRE_VERSION};
    uint64_t settlement_window{0};
    std::vector<NettingManifestEntry> domains;
    CAmount aggregate_net_delta{0};
    uint256 gross_flow_commitment;
    SettlementBindingKind binding_kind{SettlementBindingKind::NONE};
    uint256 authorization_digest;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "NettingManifest::Serialize invalid version");
        ::Serialize(s, settlement_window);
        detail::SerializeBoundedCompactSize(s, domains.size(), MAX_NETTING_DOMAINS, "NettingManifest::Serialize oversized domains");
        for (const NettingManifestEntry& entry : domains) {
            ::Serialize(s, entry);
        }
        ::Serialize(s, aggregate_net_delta);
        ::Serialize(s, gross_flow_commitment);
        detail::SerializeEnum(s, static_cast<uint8_t>(binding_kind));
        ::Serialize(s, authorization_digest);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "NettingManifest::Unserialize invalid version");
        ::Unserialize(s, settlement_window);
        const uint64_t domain_count = detail::UnserializeBoundedCompactSize(s, MAX_NETTING_DOMAINS, "NettingManifest::Unserialize oversized domains");
        domains.assign(domain_count, {});
        for (NettingManifestEntry& entry : domains) {
            ::Unserialize(s, entry);
        }
        ::Unserialize(s, aggregate_net_delta);
        ::Unserialize(s, gross_flow_commitment);
        detail::UnserializeEnum(s, binding_kind, IsValidSettlementBindingKind, "NettingManifest::Unserialize invalid binding_kind");
        ::Unserialize(s, authorization_digest);
    }
};

struct TransactionHeader
{
    uint8_t version{WIRE_VERSION};
    TransactionFamily family_id{TransactionFamily::V2_SEND};
    ProofEnvelope proof_envelope;
    uint256 payload_digest;
    uint256 proof_shard_root;
    uint32_t proof_shard_count{0};
    uint256 output_chunk_root;
    uint32_t output_chunk_count{0};
    uint8_t netting_manifest_version{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        detail::SerializeVersion(s, version, "TransactionHeader::Serialize invalid version");
        detail::SerializeEnum(s, static_cast<uint8_t>(family_id));
        ::Serialize(s, proof_envelope);
        ::Serialize(s, payload_digest);
        ::Serialize(s, proof_shard_root);
        ::Serialize(s, proof_shard_count);
        ::Serialize(s, output_chunk_root);
        ::Serialize(s, output_chunk_count);
        if (netting_manifest_version != 0 && netting_manifest_version != WIRE_VERSION) {
            throw std::ios_base::failure("TransactionHeader::Serialize invalid netting_manifest_version");
        }
        ::Serialize(s, netting_manifest_version);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        detail::UnserializeVersion(s, version, "TransactionHeader::Unserialize invalid version");
        detail::UnserializeEnum(s, family_id, IsValidTransactionFamily, "TransactionHeader::Unserialize invalid family_id");
        ::Unserialize(s, proof_envelope);
        ::Unserialize(s, payload_digest);
        ::Unserialize(s, proof_shard_root);
        ::Unserialize(s, proof_shard_count);
        ::Unserialize(s, output_chunk_root);
        ::Unserialize(s, output_chunk_count);
        ::Unserialize(s, netting_manifest_version);
        if (netting_manifest_version != 0 && netting_manifest_version != WIRE_VERSION) {
            throw std::ios_base::failure("TransactionHeader::Unserialize invalid netting_manifest_version");
        }
    }
};

[[nodiscard]] bool IsAmountDeltaInRange(CAmount amount);

[[nodiscard]] uint256 ComputeNoteCommitment(const Note& note);
[[nodiscard]] uint256 ComputeNullifier(const Note& note, Span<const uint8_t> spending_key);
[[nodiscard]] uint256 ComputeTreeEmptyLeaf();
[[nodiscard]] uint256 ComputeTreeNode(const uint256& left, const uint256& right);
[[nodiscard]] uint256 ComputeBatchLeafHash(const BatchLeaf& leaf);
[[nodiscard]] uint256 ComputeBatchLeafRoot(Span<const BatchLeaf> leaves);
[[nodiscard]] uint256 ComputeProofShardDescriptorHash(const ProofShardDescriptor& descriptor);
[[nodiscard]] uint256 ComputeProofShardRoot(Span<const ProofShardDescriptor> descriptors);
[[nodiscard]] uint256 ComputeOutputChunkDescriptorHash(const OutputChunkDescriptor& descriptor);
[[nodiscard]] uint256 ComputeOutputChunkRoot(Span<const OutputChunkDescriptor> descriptors);
[[nodiscard]] uint256 ComputeNettingManifestId(const NettingManifest& manifest);
[[nodiscard]] uint256 ComputeTransactionHeaderId(const TransactionHeader& header);

} // namespace shielded::v2

#endif // BTX_SHIELDED_V2_TYPES_H
