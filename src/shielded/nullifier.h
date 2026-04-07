// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_NULLIFIER_H
#define BTX_SHIELDED_NULLIFIER_H

#include <consensus/amount.h>
#include <crypto/common.h>
#include <crypto/siphash.h>
#include <dbwrapper.h>
#include <serialize.h>
#include <shielded/account_registry.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <uint256.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <unordered_set>
#include <vector>

/** Maximum nullifiers in in-memory cache before disk-only behavior. */
static constexpr size_t NULLIFIER_CACHE_MAX_ENTRIES{2'000'000};

/** Salted SipHash hasher for uint256 nullifiers (defense-in-depth). */
struct NullifierHasher {
private:
    const uint64_t k0, k1;
public:
    NullifierHasher();
    size_t operator()(const Nullifier& nf) const { return SipHashUint256(k0, k1, nf); }
};

struct ConfirmedNettingManifestState
{
    uint256 manifest_id;
    int32_t created_height{-1};
    uint64_t settlement_window{0};

    [[nodiscard]] bool HasMetadata() const
    {
        return created_height >= 0 && settlement_window > 0;
    }

    [[nodiscard]] bool IsValid() const
    {
        return !manifest_id.IsNull() && HasMetadata();
    }

    friend bool operator==(const ConfirmedNettingManifestState& lhs,
                           const ConfirmedNettingManifestState& rhs)
    {
        return lhs.manifest_id == rhs.manifest_id &&
               lhs.created_height == rhs.created_height &&
               lhs.settlement_window == rhs.settlement_window;
    }

    SERIALIZE_METHODS(ConfirmedNettingManifestState, obj)
    {
        READWRITE(obj.manifest_id, obj.created_height, obj.settlement_window);
    }
};

struct ConfirmedSettlementAnchorState
{
    uint256 anchor;
    int32_t created_height{-1};

    [[nodiscard]] bool HasMetadata() const
    {
        return created_height >= 0;
    }

    [[nodiscard]] bool IsValid() const
    {
        return !anchor.IsNull() && HasMetadata();
    }

    friend bool operator==(const ConfirmedSettlementAnchorState& lhs,
                           const ConfirmedSettlementAnchorState& rhs)
    {
        return lhs.anchor == rhs.anchor && lhs.created_height == rhs.created_height;
    }

    SERIALIZE_METHODS(ConfirmedSettlementAnchorState, obj)
    {
        READWRITE(obj.anchor, obj.created_height);
    }
};

struct ShieldedStateMutationMarker
{
    struct PreparedSnapshot
    {
        shielded::ShieldedMerkleTree tree{};
        CAmount pool_balance{0};
        uint256 commitment_index_digest;
        shielded::registry::ShieldedAccountRegistryPersistedSnapshot account_registry_snapshot;

        [[nodiscard]] bool IsValid() const
        {
            const auto actual_commitment_index_digest = tree.CommitmentIndexDigest();
            return MoneyRange(pool_balance) &&
                   pool_balance >= 0 &&
                   actual_commitment_index_digest.has_value() &&
                   commitment_index_digest == *actual_commitment_index_digest &&
                   account_registry_snapshot.IsValid();
        }

        SERIALIZE_METHODS(PreparedSnapshot, obj)
        {
            READWRITE(obj.tree,
                      obj.pool_balance,
                      obj.commitment_index_digest,
                      obj.account_registry_snapshot);
        }
    };

    static constexpr uint8_t LEGACY_VERSION{1};
    static constexpr uint8_t PREPARED_TRANSITION_VERSION{2};
    static constexpr uint8_t PREPARED_STAGE{1};

    uint8_t version{LEGACY_VERSION};
    uint256 target_tip_hash;
    int32_t target_tip_height{-1};
    uint8_t stage{PREPARED_STAGE};
    uint256 source_tip_hash;
    int32_t source_tip_height{-1};
    PreparedSnapshot prepared_target_snapshot;

    [[nodiscard]] static bool IsValidTip(int32_t height, const uint256& hash)
    {
        return (height == -1 && hash.IsNull()) || (height >= 0 && !hash.IsNull());
    }

    [[nodiscard]] bool IsValid() const
    {
        if (version == LEGACY_VERSION) {
            return IsValidTip(target_tip_height, target_tip_hash);
        }
        if (version != PREPARED_TRANSITION_VERSION) {
            return false;
        }
        return stage == PREPARED_STAGE &&
               IsValidTip(source_tip_height, source_tip_hash) &&
               IsValidTip(target_tip_height, target_tip_hash) &&
               prepared_target_snapshot.IsValid();
    }

    [[nodiscard]] bool IsPreparedTransitionJournal() const
    {
        return version == PREPARED_TRANSITION_VERSION &&
               stage == PREPARED_STAGE &&
               prepared_target_snapshot.IsValid();
    }

    SERIALIZE_METHODS(ShieldedStateMutationMarker, obj)
    {
        READWRITE(obj.version);
        if (obj.version == LEGACY_VERSION) {
            READWRITE(obj.target_tip_hash, obj.target_tip_height);
            if constexpr (ser_action.ForRead()) {
                obj.stage = PREPARED_STAGE;
                obj.source_tip_hash.SetNull();
                obj.source_tip_height = -1;
                obj.prepared_target_snapshot = PreparedSnapshot{};
            }
            return;
        }
        READWRITE(obj.target_tip_hash,
                  obj.target_tip_height,
                  obj.stage,
                  obj.source_tip_hash,
                  obj.source_tip_height,
                  obj.prepared_target_snapshot);
    }
};

/**
 * Persistent set of spent nullifiers, backed by LevelDB.
 *
 * Thread safety:
 * - Contains()/AnyExist(): shared lock
 * - Insert()/Remove(): exclusive lock
 */
class NullifierSet
{
public:
    explicit NullifierSet(const fs::path& db_path,
                          size_t cache_bytes = 8 << 20,
                          bool memory_only = false,
                          bool wipe_data = false);
    ~NullifierSet();

    NullifierSet(const NullifierSet&) = delete;
    NullifierSet& operator=(const NullifierSet&) = delete;

    /** Check if a nullifier has already been spent. Null nullifier is always false. */
    [[nodiscard]] bool Contains(const Nullifier& nf) const;

    /** Check if any nullifier in the vector exists in cache or DB. */
    [[nodiscard]] bool AnyExist(const std::vector<Nullifier>& nullifiers) const;

    /** Insert nullifiers from a connected block. */
    [[nodiscard]] bool Insert(const std::vector<Nullifier>& nullifiers);

    /** Remove nullifiers on block disconnect. */
    [[nodiscard]] bool Remove(const std::vector<Nullifier>& nullifiers);

    /** Check if a settlement-anchor digest exists in the confirmed chain. */
    [[nodiscard]] bool ContainsSettlementAnchor(const uint256& anchor) const;

    /** Return persisted metadata for a confirmed settlement anchor, if available. */
    [[nodiscard]] std::optional<ConfirmedSettlementAnchorState> GetSettlementAnchorState(
        const uint256& anchor) const;

    /** Insert settlement-anchor digests from a connected block. */
    [[nodiscard]] bool InsertSettlementAnchors(const std::vector<uint256>& anchors);

    /** Insert settlement-anchor state from a connected block. */
    [[nodiscard]] bool InsertSettlementAnchors(const std::vector<ConfirmedSettlementAnchorState>& anchors);

    /** Remove settlement-anchor digests on block disconnect. */
    [[nodiscard]] bool RemoveSettlementAnchors(const std::vector<uint256>& anchors);

    /** Check if a netting-manifest id exists in the confirmed chain. */
    [[nodiscard]] bool ContainsNettingManifest(const uint256& manifest_id) const;

    /** Return the persisted metadata for a confirmed netting manifest, if available. */
    [[nodiscard]] std::optional<ConfirmedNettingManifestState> GetNettingManifestState(
        const uint256& manifest_id) const;

    /** Insert confirmed netting-manifest state from a connected block. */
    [[nodiscard]] bool InsertNettingManifests(const std::vector<ConfirmedNettingManifestState>& manifests);

    /** Remove netting-manifest ids on block disconnect. */
    [[nodiscard]] bool RemoveNettingManifests(const std::vector<uint256>& manifest_ids);

    /** In-memory cache size (diagnostic). */
    [[nodiscard]] size_t CacheSize() const;

    /** Estimated total memory usage. */
    [[nodiscard]] size_t DynamicMemoryUsage() const;

    /** Return the maintained nullifier count (O(1), no DB scan). */
    [[nodiscard]] uint64_t CountNullifiers() const;

    /** Count persisted nullifiers via full LevelDB scan (slow, diagnostic only). */
    [[nodiscard]] uint64_t CountNullifiersSlow() const;

    /** Persist database state (best-effort fsync barrier). */
    [[nodiscard]] bool Flush();

    /** Read the persisted shielded pool balance. Missing value defaults to zero. */
    [[nodiscard]] bool ReadPoolBalance(CAmount& balance) const;

    /** Persist the shielded pool balance. */
    [[nodiscard]] bool WritePoolBalance(CAmount balance);

    /** Return the in-flight shielded mutation marker, if any. */
    [[nodiscard]] std::optional<ShieldedStateMutationMarker> ReadMutationMarker() const;

    /** Persist an in-flight shielded mutation marker before multi-store writes. */
    [[nodiscard]] bool WriteMutationMarker(const ShieldedStateMutationMarker& marker);

    /** Clear the in-flight shielded mutation marker after persisted state commits. */
    [[nodiscard]] bool ClearMutationMarker();

    /** Read whether persisted bridge metadata came from a snapshot section. */
    [[nodiscard]] bool ReadSnapshotBridgeMetadataHint() const;

    /** Persist whether restart should preserve snapshot-seeded bridge metadata extras. */
    [[nodiscard]] bool WriteSnapshotBridgeMetadataHint(bool preserve_snapshot_extras);

    /** Read the persisted active shielded frontier state for the current tip. */
    [[nodiscard]] bool ReadPersistedState(shielded::ShieldedMerkleTree& tree,
                                          std::vector<uint256>& anchor_roots,
                                          uint256& tip_hash,
                                          int32_t& tip_height,
                                          CAmount& balance,
                                          std::optional<uint256>& commitment_index_digest,
                                          std::optional<
                                              shielded::registry::ShieldedAccountRegistryPersistedSnapshot>&
                                              account_registry_snapshot) const;

    /** Persist the active shielded frontier state for restart recovery. */
    [[nodiscard]] bool WritePersistedState(const shielded::ShieldedMerkleTree& tree,
                                           const std::vector<uint256>& anchor_roots,
                                           const uint256& tip_hash,
                                           int32_t tip_height,
                                           CAmount balance,
                                           std::optional<uint256> commitment_index_digest,
                                           std::optional<
                                               shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
                                               account_registry_snapshot);

    /** Iterate over persisted nullifiers in on-disk order. */
    template <typename Fn>
    bool ForEachPersistedNullifier(Fn&& fn) const
    {
        std::shared_lock lock(m_rwlock);
        std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
        cursor->Seek(std::make_pair(DB_NULLIFIER, uint256{}));

        while (cursor->Valid()) {
            std::pair<uint8_t, Nullifier> key;
            if (!cursor->GetKey(key) || key.first != DB_NULLIFIER) break;
            if (!fn(key.second)) return false;
            cursor->Next();
        }
        return true;
    }

    /** Iterate over persisted settlement-anchor digests in on-disk order. */
    template <typename Fn>
    bool ForEachPersistedSettlementAnchor(Fn&& fn) const
    {
        return ForEachPersistedSettlementAnchorState([&](const ConfirmedSettlementAnchorState& state) {
            return fn(state.anchor);
        });
    }

    /** Iterate over persisted settlement-anchor state in on-disk order. */
    template <typename Fn>
    bool ForEachPersistedSettlementAnchorState(Fn&& fn) const
    {
        std::shared_lock lock(m_rwlock);
        std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
        cursor->Seek(std::make_pair(DB_SETTLEMENT_ANCHOR, uint256{}));

        while (cursor->Valid()) {
            std::pair<uint8_t, uint256> key;
            if (!cursor->GetKey(key) || key.first != DB_SETTLEMENT_ANCHOR) break;
            ConfirmedSettlementAnchorState anchor_state;
            if (!cursor->GetValue(anchor_state)) {
                uint8_t legacy_marker{0};
                if (!cursor->GetValue(legacy_marker)) {
                    return false;
                }
                anchor_state.anchor = key.second;
            } else if (anchor_state.anchor.IsNull()) {
                anchor_state.anchor = key.second;
            } else if (anchor_state.anchor != key.second) {
                return false;
            }
            if (!fn(anchor_state)) return false;
            cursor->Next();
        }
        return true;
    }

    /** Iterate over persisted netting-manifest ids in on-disk order. */
    template <typename Fn>
    bool ForEachPersistedNettingManifest(Fn&& fn) const
    {
        return ForEachPersistedNettingManifestState([&](const ConfirmedNettingManifestState& manifest_state) {
            return fn(manifest_state.manifest_id);
        });
    }

    /** Iterate over persisted netting-manifest state in on-disk order. */
    template <typename Fn>
    bool ForEachPersistedNettingManifestState(Fn&& fn) const
    {
        std::shared_lock lock(m_rwlock);
        std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
        cursor->Seek(std::make_pair(DB_NETTING_MANIFEST, uint256{}));

        while (cursor->Valid()) {
            std::pair<uint8_t, uint256> key;
            if (!cursor->GetKey(key) || key.first != DB_NETTING_MANIFEST) break;
            ConfirmedNettingManifestState manifest_state;
            if (!cursor->GetValue(manifest_state)) {
                uint8_t legacy_marker{0};
                if (!cursor->GetValue(legacy_marker)) {
                    return false;
                }
                manifest_state.manifest_id = key.second;
            } else if (manifest_state.manifest_id.IsNull()) {
                manifest_state.manifest_id = key.second;
            } else if (manifest_state.manifest_id != key.second) {
                return false;
            }
            if (!fn(manifest_state)) return false;
            cursor->Next();
        }
        return true;
    }

private:
    [[nodiscard]] bool ExistsInDB(const Nullifier& nf) const;
    [[nodiscard]] bool SettlementAnchorExistsInDB(const uint256& anchor) const;
    [[nodiscard]] bool NettingManifestExistsInDB(const uint256& manifest_id) const;
    using NullifierCache = std::unordered_set<Nullifier, NullifierHasher>;
    using SettlementAnchorCache = std::unordered_set<uint256, NullifierHasher>;
    using NettingManifestCache = std::unordered_set<uint256, NullifierHasher>;

    std::unique_ptr<CDBWrapper> m_db;
    std::shared_ptr<NullifierCache> m_cache_current;
    std::shared_ptr<NullifierCache> m_cache_previous;
    mutable std::shared_ptr<NullifierCache> m_miss_cache_current;
    mutable std::shared_ptr<NullifierCache> m_miss_cache_previous;
    std::shared_ptr<SettlementAnchorCache> m_settlement_anchor_cache_current;
    std::shared_ptr<SettlementAnchorCache> m_settlement_anchor_cache_previous;
    mutable std::shared_ptr<SettlementAnchorCache> m_settlement_anchor_miss_cache_current;
    mutable std::shared_ptr<SettlementAnchorCache> m_settlement_anchor_miss_cache_previous;
    std::shared_ptr<NettingManifestCache> m_netting_manifest_cache_current;
    std::shared_ptr<NettingManifestCache> m_netting_manifest_cache_previous;
    mutable std::shared_ptr<NettingManifestCache> m_netting_manifest_miss_cache_current;
    mutable std::shared_ptr<NettingManifestCache> m_netting_manifest_miss_cache_previous;
    mutable std::shared_mutex m_rwlock;
    std::atomic<uint64_t> m_count{0};  //!< Maintained count to avoid O(n) DB scans.

    static constexpr uint8_t DB_NULLIFIER{'N'};
    static constexpr uint8_t DB_NULLIFIER_COUNT{'C'};
    static constexpr uint8_t DB_STATE_MUTATION_MARKER{'J'};
    static constexpr uint8_t DB_SETTLEMENT_ANCHOR{'A'};
    static constexpr uint8_t DB_NETTING_MANIFEST{'M'};
    static constexpr uint8_t DB_POOL_BALANCE{'B'};
    static constexpr uint8_t DB_PERSISTED_STATE{'S'};
    static constexpr uint8_t DB_SNAPSHOT_BRIDGE_METADATA_HINT{'G'};
};

#endif // BTX_SHIELDED_NULLIFIER_H
