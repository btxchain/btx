// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_ACCOUNT_REGISTRY_H
#define BTX_SHIELDED_ACCOUNT_REGISTRY_H

#include <dbwrapper.h>
#include <shielded/account_registry_proof.h>
#include <serialize.h>
#include <shielded/note.h>
#include <shielded/smile2/public_account.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_types.h>
#include <span.h>
#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <ios>
#include <memory>
#include <map>
#include <optional>
#include <vector>

struct CShieldedBundle;

namespace shielded::registry {

enum class AccountDomain : uint8_t {
    DIRECT_SEND = 1,
    INGRESS = 2,
    EGRESS = 3,
    REBALANCE = 4,
};

[[nodiscard]] bool IsValidAccountDomain(AccountDomain domain);
[[nodiscard]] const char* GetAccountDomainName(AccountDomain domain);

struct ShieldedAccountLeaf;
struct PayloadStore;

struct AccountLeafHint
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    AccountDomain domain{AccountDomain::DIRECT_SEND};
    uint256 settlement_binding_digest;
    uint256 output_binding_digest;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure("AccountLeafHint::Serialize invalid hint");
        }
        ::Serialize(s, version);
        shielded::v2::detail::SerializeEnum(s, static_cast<uint8_t>(domain));
        ::Serialize(s, settlement_binding_digest);
        ::Serialize(s, output_binding_digest);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure("AccountLeafHint::Unserialize invalid version");
        }
        shielded::v2::detail::UnserializeEnum(s,
                                              domain,
                                              IsValidAccountDomain,
                                              "AccountLeafHint::Unserialize invalid domain");
        ::Unserialize(s, settlement_binding_digest);
        ::Unserialize(s, output_binding_digest);
        if (!IsValid()) {
            throw std::ios_base::failure("AccountLeafHint::Unserialize invalid hint");
        }
    }
};

[[nodiscard]] AccountLeafHint MakeDirectSendAccountLeafHint();
[[nodiscard]] std::optional<AccountLeafHint> MakeIngressAccountLeafHint(
    const uint256& settlement_binding_digest);
[[nodiscard]] std::optional<AccountLeafHint> MakeEgressAccountLeafHint(
    const uint256& settlement_binding_digest,
    const uint256& output_binding_digest);
[[nodiscard]] std::optional<AccountLeafHint> MakeRebalanceAccountLeafHint(
    const uint256& settlement_binding_digest);

[[nodiscard]] std::optional<ShieldedAccountLeaf> BuildAccountLeafFromNote(
    const ShieldedNote& note,
    const uint256& note_commitment,
    const AccountLeafHint& hint,
    bool use_nonced_bridge_tag = false);
[[nodiscard]] std::optional<uint256> ComputeAccountLeafCommitmentFromNote(
    const ShieldedNote& note,
    const uint256& note_commitment,
    const AccountLeafHint& hint,
    bool use_nonced_bridge_tag = false);
[[nodiscard]] std::vector<uint256> CollectAccountLeafCommitmentCandidatesFromNote(
    const ShieldedNote& note,
    const uint256& note_commitment,
    const AccountLeafHint& hint);

[[nodiscard]] uint256 ComputeCompactPublicKeyCommitment(const smile2::CompactPublicAccount& account);
[[nodiscard]] uint256 ComputeCompactPublicCoinT0Commitment(const smile2::CompactPublicAccount& account);
[[nodiscard]] uint256 ComputeCompactPublicCoinMessageCommitment(const smile2::CompactPublicAccount& account);
[[nodiscard]] uint256 ComputeAccountPayloadCommitment(const smile2::CompactPublicAccount& account);
[[nodiscard]] uint256 ComputeSpendTagCommitment(const smile2::CompactPublicAccount& account,
                                                const uint256& note_commitment);
[[nodiscard]] std::optional<smile2::CompactPublicAccount> BuildCompactPublicAccountFromAccountLeaf(
    const struct ShieldedAccountLeaf& leaf);

[[nodiscard]] uint256 ComputeIngressBridgeTag(const uint256& settlement_binding_digest);
[[nodiscard]] uint256 ComputeEgressBridgeTag(const uint256& settlement_binding_digest,
                                             const uint256& output_binding_digest);
[[nodiscard]] uint256 ComputeRebalanceBridgeTag(const uint256& settlement_binding_digest);
[[nodiscard]] uint256 ComputeIngressBridgeTag(const uint256& settlement_binding_digest,
                                              const uint256& note_commitment);
[[nodiscard]] uint256 ComputeEgressBridgeTag(const uint256& settlement_binding_digest,
                                             const uint256& output_binding_digest,
                                             const uint256& note_commitment);
[[nodiscard]] uint256 ComputeRebalanceBridgeTag(const uint256& settlement_binding_digest,
                                                const uint256& note_commitment);

struct ShieldedAccountLeaf
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    uint256 note_commitment;
    AccountDomain domain{AccountDomain::DIRECT_SEND};
    uint256 account_payload_commitment;
    uint256 spend_tag_commitment;
    smile2::CompactPublicKeyData compact_public_key;
    smile2::BDLOPCommitment compact_public_coin;
    std::optional<uint256> bridge_tag;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedAccountLeaf::Serialize invalid leaf");
        }
        ::Serialize(s, version);
        ::Serialize(s, note_commitment);
        shielded::v2::detail::SerializeEnum(s, static_cast<uint8_t>(domain));
        ::Serialize(s, account_payload_commitment);
        ::Serialize(s, spend_tag_commitment);
        ::Serialize(s, compact_public_key);
        smile2::SerializeCompactPublicCoin(s, compact_public_coin);
        const bool has_bridge_tag = bridge_tag.has_value();
        ::Serialize(s, has_bridge_tag);
        if (has_bridge_tag) {
            ::Serialize(s, *bridge_tag);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure("ShieldedAccountLeaf::Unserialize invalid version");
        }
        ::Unserialize(s, note_commitment);
        shielded::v2::detail::UnserializeEnum(s,
                                              domain,
                                              IsValidAccountDomain,
                                              "ShieldedAccountLeaf::Unserialize invalid domain");
        ::Unserialize(s, account_payload_commitment);
        ::Unserialize(s, spend_tag_commitment);
        ::Unserialize(s, compact_public_key);
        smile2::UnserializeCompactPublicCoin(s, compact_public_coin);
        bool has_bridge_tag{false};
        ::Unserialize(s, has_bridge_tag);
        if (has_bridge_tag) {
            uint256 tag;
            ::Unserialize(s, tag);
            bridge_tag = tag;
        } else {
            bridge_tag.reset();
        }
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedAccountLeaf::Unserialize invalid leaf");
        }
    }
};

[[nodiscard]] uint256 ComputeShieldedAccountLeafCommitment(const ShieldedAccountLeaf& leaf);
[[nodiscard]] std::vector<uint8_t> SerializeShieldedAccountLeafPayload(const ShieldedAccountLeaf& leaf);
[[nodiscard]] std::optional<ShieldedAccountLeaf> DeserializeShieldedAccountLeafPayload(
    Span<const uint8_t> bytes);

[[nodiscard]] std::optional<ShieldedAccountLeaf> BuildShieldedAccountLeaf(
    const smile2::CompactPublicAccount& account,
    const uint256& note_commitment,
    AccountDomain domain,
    std::optional<uint256> bridge_tag = std::nullopt);

[[nodiscard]] std::optional<ShieldedAccountLeaf> BuildDirectSendAccountLeaf(
    const shielded::v2::OutputDescription& output);
[[nodiscard]] std::optional<ShieldedAccountLeaf> BuildIngressAccountLeaf(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest,
    bool use_nonced_bridge_tag = false);
[[nodiscard]] std::optional<ShieldedAccountLeaf> BuildEgressAccountLeaf(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest,
    const uint256& output_binding_digest,
    bool use_nonced_bridge_tag = false);
[[nodiscard]] std::optional<ShieldedAccountLeaf> BuildRebalanceAccountLeaf(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest,
    bool use_nonced_bridge_tag = false);
[[nodiscard]] std::optional<std::vector<ShieldedAccountLeaf>> CollectShieldedOutputAccountLeaves(
    const CShieldedBundle& bundle,
    bool use_nonced_bridge_tag = false);

struct MinimalOutputRecord
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    uint256 note_commitment;
    uint256 account_leaf_commitment;
    AccountDomain account_domain{AccountDomain::DIRECT_SEND};
    shielded::v2::EncryptedNotePayload encrypted_note;

    [[nodiscard]] bool IsValid() const;
};

[[nodiscard]] std::vector<uint8_t> SerializeMinimalOutputRecord(
    const MinimalOutputRecord& output,
    std::optional<AccountDomain> implied_account_domain,
    std::optional<shielded::v2::ScanDomain> implied_scan_domain);

[[nodiscard]] std::optional<MinimalOutputRecord> DeserializeMinimalOutputRecord(
    Span<const uint8_t> bytes,
    std::optional<AccountDomain> implied_account_domain,
    std::optional<shielded::v2::ScanDomain> implied_scan_domain);

[[nodiscard]] std::optional<MinimalOutputRecord> BuildDirectSendMinimalOutput(
    const shielded::v2::OutputDescription& output);
[[nodiscard]] std::optional<MinimalOutputRecord> BuildIngressMinimalOutput(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest);
[[nodiscard]] std::optional<MinimalOutputRecord> BuildEgressMinimalOutput(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest,
    const uint256& output_binding_digest);
[[nodiscard]] std::optional<MinimalOutputRecord> BuildRebalanceMinimalOutput(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest);

[[nodiscard]] bool MinimalOutputRecordMatchesOutput(
    const MinimalOutputRecord& minimal_output,
    const shielded::v2::OutputDescription& output,
    const ShieldedAccountLeaf& account_leaf);

struct ShieldedAccountRegistrySnapshot
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    std::vector<ShieldedAccountRegistryEntry> entries;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedAccountRegistrySnapshot::Serialize invalid snapshot");
        }
        ::Serialize(s, version);
        shielded::v2::detail::SerializeBoundedCompactSize(
            s,
            entries.size(),
            MAX_REGISTRY_ENTRIES,
            "ShieldedAccountRegistrySnapshot::Serialize oversized entries");
        for (const auto& entry : entries) {
            ::Serialize(s, entry);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure("ShieldedAccountRegistrySnapshot::Unserialize invalid version");
        }
        const uint64_t entry_count = shielded::v2::detail::UnserializeBoundedCompactSize(
            s,
            MAX_REGISTRY_ENTRIES,
            "ShieldedAccountRegistrySnapshot::Unserialize oversized entries");
        entries.assign(entry_count, {});
        for (auto& entry : entries) {
            ::Unserialize(s, entry);
        }
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedAccountRegistrySnapshot::Unserialize invalid snapshot");
        }
    }
};

struct ShieldedAccountRegistryPersistedEntry
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    uint64_t leaf_index{0};
    uint256 account_leaf_commitment;
    uint256 entry_commitment;
    bool spent{false};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistryPersistedEntry::Serialize invalid entry");
        }
        ::Serialize(s, version);
        ::Serialize(s, leaf_index);
        ::Serialize(s, account_leaf_commitment);
        ::Serialize(s, entry_commitment);
        ::Serialize(s, spent);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistryPersistedEntry::Unserialize invalid version");
        }
        ::Unserialize(s, leaf_index);
        ::Unserialize(s, account_leaf_commitment);
        ::Unserialize(s, entry_commitment);
        ::Unserialize(s, spent);
        if (!IsValid()) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistryPersistedEntry::Unserialize invalid entry");
        }
    }
};

struct ShieldedAccountRegistryPersistedSnapshot
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    std::vector<ShieldedAccountRegistryPersistedEntry> entries;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistryPersistedSnapshot::Serialize invalid snapshot");
        }
        ::Serialize(s, version);
        shielded::v2::detail::SerializeBoundedCompactSize(
            s,
            entries.size(),
            MAX_REGISTRY_ENTRIES,
            "ShieldedAccountRegistryPersistedSnapshot::Serialize oversized entries");
        for (const auto& entry : entries) {
            ::Serialize(s, entry);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistryPersistedSnapshot::Unserialize invalid version");
        }
        const uint64_t entry_count = shielded::v2::detail::UnserializeBoundedCompactSize(
            s,
            MAX_REGISTRY_ENTRIES,
            "ShieldedAccountRegistryPersistedSnapshot::Unserialize oversized entries");
        entries.assign(entry_count, {});
        for (auto& entry : entries) {
            ::Unserialize(s, entry);
        }
        if (!IsValid()) {
            throw std::ios_base::failure(
                "ShieldedAccountRegistryPersistedSnapshot::Unserialize invalid snapshot");
        }
    }
};

class ShieldedAccountRegistryState
{
public:
    enum class PayloadPruneMode {
        PRUNE,
        KEEP,
    };

    ShieldedAccountRegistryState();
    [[nodiscard]] static ShieldedAccountRegistryState WithConfiguredPayloadStore();

    [[nodiscard]] static bool ConfigurePayloadStore(const fs::path& db_path,
                                                    size_t cache_bytes = 8 << 20,
                                                    bool memory_only = false,
                                                    bool wipe_data = false,
                                                    DBOptions options = {});
    static void ResetPayloadStore();
    [[nodiscard]] static bool HasPayloadStore();
    [[nodiscard]] bool HasAttachedPayloadStore() const { return m_payload_store != nullptr; }

    [[nodiscard]] size_t Size() const { return m_entries.size(); }
    [[nodiscard]] bool Empty() const { return m_entries.empty(); }

    [[nodiscard]] bool Append(Span<const ShieldedAccountLeaf> account_leaves,
                              std::vector<uint64_t>* inserted_indices = nullptr);
    [[nodiscard]] bool Truncate(size_t size,
                                PayloadPruneMode prune_mode = PayloadPruneMode::PRUNE);
    [[nodiscard]] std::optional<uint64_t> FindLeafIndexByCommitment(
        const uint256& account_leaf_commitment) const;
    [[nodiscard]] std::optional<ShieldedAccountRegistryProof> BuildProof(uint64_t leaf_index) const;
    [[nodiscard]] std::optional<ShieldedAccountRegistrySpendWitness> BuildSpendWitness(
        uint64_t leaf_index) const;
    [[nodiscard]] std::optional<ShieldedAccountRegistryProof> BuildProofByCommitment(
        const uint256& account_leaf_commitment) const;
    [[nodiscard]] std::optional<ShieldedAccountRegistrySpendWitness> BuildSpendWitnessByCommitment(
        const uint256& account_leaf_commitment) const;
    [[nodiscard]] std::optional<ShieldedAccountRegistryEntry> MaterializeEntry(
        uint64_t leaf_index) const;
    [[nodiscard]] bool CanMaterializeAllEntries() const;
    [[nodiscard]] uint256 Root() const;

    template <typename Fn>
    bool ForEachEntry(Fn&& fn) const
    {
        for (uint64_t leaf_index = 0; leaf_index < m_entries.size(); ++leaf_index) {
            const auto entry = MaterializeEntry(leaf_index);
            if (!entry.has_value() || !fn(*entry)) return false;
        }
        return true;
    }

    [[nodiscard]] ShieldedAccountRegistrySnapshot ExportSnapshot() const;
    [[nodiscard]] ShieldedAccountRegistryPersistedSnapshot ExportPersistedSnapshot() const;
    [[nodiscard]] static std::optional<ShieldedAccountRegistryState> Restore(
        const ShieldedAccountRegistrySnapshot& snapshot);
    [[nodiscard]] static std::optional<ShieldedAccountRegistryState> RestorePersisted(
        const ShieldedAccountRegistryPersistedSnapshot& snapshot);

private:
    struct StoredEntry {
        uint64_t leaf_index{0};
        uint256 account_leaf_commitment;
        uint256 entry_commitment;
        bool spent{false};
        std::vector<uint8_t> inline_payload;
    };

    [[nodiscard]] bool LoadFromSnapshot(const ShieldedAccountRegistrySnapshot& snapshot);
    [[nodiscard]] bool LoadFromPersistedSnapshot(
        const ShieldedAccountRegistryPersistedSnapshot& snapshot);
    [[nodiscard]] std::optional<std::vector<uint8_t>> LoadPayloadBytes(uint64_t leaf_index) const;
    void AttachConfiguredPayloadStore();

    std::vector<StoredEntry> m_entries;
    std::shared_ptr<PayloadStore> m_payload_store;

    friend bool VerifyShieldedAccountRegistrySpendWitness(
        const ShieldedAccountRegistrySpendWitness& witness,
        const ShieldedAccountRegistryState& registry,
        const uint256& expected_root);
};

[[nodiscard]] bool BuildRegistryAccountState(
    const ShieldedAccountRegistryState& registry,
    std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
    std::map<uint256, uint256>& account_leaf_commitments);
[[nodiscard]] bool VerifyShieldedAccountRegistrySpendWitness(
    const ShieldedAccountRegistrySpendWitness& witness,
    const ShieldedAccountRegistryState& registry,
    const uint256& expected_root);

[[nodiscard]] uint256 ComputeNullifierSetCommitment(Span<const uint256> nullifiers);

struct ShieldedStateCommitment
{
    uint8_t version{REGISTRY_WIRE_VERSION};
    uint256 note_commitment_root;
    uint256 account_registry_root;
    uint256 nullifier_root;
    uint256 bridge_settlement_root;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedStateCommitment::Serialize invalid commitment");
        }
        ::Serialize(s, version);
        ::Serialize(s, note_commitment_root);
        ::Serialize(s, account_registry_root);
        ::Serialize(s, nullifier_root);
        ::Serialize(s, bridge_settlement_root);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        if (version != REGISTRY_WIRE_VERSION) {
            throw std::ios_base::failure("ShieldedStateCommitment::Unserialize invalid version");
        }
        ::Unserialize(s, note_commitment_root);
        ::Unserialize(s, account_registry_root);
        ::Unserialize(s, nullifier_root);
        ::Unserialize(s, bridge_settlement_root);
        if (!IsValid()) {
            throw std::ios_base::failure("ShieldedStateCommitment::Unserialize invalid commitment");
        }
    }
};

[[nodiscard]] uint256 ComputeShieldedStateCommitmentHash(const ShieldedStateCommitment& commitment);
[[nodiscard]] bool VerifyShieldedStateInclusion(const ShieldedStateCommitment& commitment,
                                                const ShieldedAccountRegistryProof& proof);

} // namespace shielded::registry

#endif // BTX_SHIELDED_ACCOUNT_REGISTRY_H
