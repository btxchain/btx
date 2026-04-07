// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/nullifier.h>

#include <consensus/amount.h>
#include <logging.h>
#include <random.h>

#include <mutex>
#include <limits>
#include <set>
#include <shared_mutex>
#include <utility>

namespace {
constexpr uint32_t SHIELDED_STATE_DISK_MAGIC{0x31534453}; // "SDS1"
constexpr uint8_t SHIELDED_STATE_DISK_VERSION{2};
constexpr uint8_t SHIELDED_STATE_HAS_COMMITMENT_INDEX_DIGEST{1U << 0};
constexpr uint8_t SHIELDED_STATE_HAS_ACCOUNT_REGISTRY_SNAPSHOT{1U << 1};

[[nodiscard]] std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
BuildPersistedRegistrySnapshot(
    const shielded::registry::ShieldedAccountRegistrySnapshot& snapshot)
{
    if (!snapshot.IsValid()) {
        return std::nullopt;
    }

    shielded::registry::ShieldedAccountRegistryPersistedSnapshot persisted_snapshot;
    persisted_snapshot.entries.reserve(snapshot.entries.size());
    for (const auto& entry : snapshot.entries) {
        if (!entry.IsValid()) {
            return std::nullopt;
        }
        persisted_snapshot.entries.push_back(
            shielded::registry::ShieldedAccountRegistryPersistedEntry{
                .leaf_index = entry.leaf_index,
                .account_leaf_commitment = entry.account_leaf_commitment,
                .entry_commitment =
                    shielded::registry::ComputeShieldedAccountRegistryEntryCommitment(entry),
                .spent = entry.spent,
            });
    }
    if (!persisted_snapshot.IsValid()) {
        return std::nullopt;
    }
    return persisted_snapshot;
}

struct ShieldedStateDisk
{
    shielded::ShieldedMerkleTree tree;
    std::vector<uint256> anchor_roots;
    uint256 tip_hash;
    int32_t tip_height{-1};
    CAmount pool_balance{0};
    std::optional<uint256> commitment_index_digest;
    std::optional<shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
        account_registry_snapshot;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t flags =
            (commitment_index_digest.has_value() ? SHIELDED_STATE_HAS_COMMITMENT_INDEX_DIGEST : 0) |
            (account_registry_snapshot.has_value() ? SHIELDED_STATE_HAS_ACCOUNT_REGISTRY_SNAPSHOT : 0);

        ::Serialize(s, SHIELDED_STATE_DISK_MAGIC);
        ::Serialize(s, SHIELDED_STATE_DISK_VERSION);
        ::Serialize(s, flags);
        ::Serialize(s, tree);
        ::Serialize(s, anchor_roots);
        ::Serialize(s, tip_hash);
        ::Serialize(s, tip_height);
        ::Serialize(s, pool_balance);
        if ((flags & SHIELDED_STATE_HAS_COMMITMENT_INDEX_DIGEST) != 0) {
            ::Serialize(s, *commitment_index_digest);
        }
        if ((flags & SHIELDED_STATE_HAS_ACCOUNT_REGISTRY_SNAPSHOT) != 0) {
            ::Serialize(s, *account_registry_snapshot);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        if (!TryUnserializeVersioned(s) && !TryUnserializePositional(s)) {
            throw std::ios_base::failure("ShieldedStateDisk unsupported persisted-state format");
        }
    }

private:
    template <typename Stream>
    bool TryUnserializeVersioned(Stream& s)
    {
        const auto start_size = s.size();
        uint32_t magic{0};
        ::Unserialize(s, magic);
        if (magic != SHIELDED_STATE_DISK_MAGIC) {
            s.Rewind(start_size - s.size());
            return false;
        }

        uint8_t version{0};
        uint8_t flags{0};
        ::Unserialize(s, version);
        ::Unserialize(s, flags);
        if ((version != 1 && version != SHIELDED_STATE_DISK_VERSION) ||
            (flags & ~(SHIELDED_STATE_HAS_COMMITMENT_INDEX_DIGEST |
                       SHIELDED_STATE_HAS_ACCOUNT_REGISTRY_SNAPSHOT)) != 0) {
            throw std::ios_base::failure("ShieldedStateDisk invalid persisted-state header");
        }

        ::Unserialize(s, tree);
        ::Unserialize(s, anchor_roots);
        ::Unserialize(s, tip_hash);
        ::Unserialize(s, tip_height);
        ::Unserialize(s, pool_balance);

        if ((flags & SHIELDED_STATE_HAS_COMMITMENT_INDEX_DIGEST) != 0) {
            uint256 digest;
            ::Unserialize(s, digest);
            commitment_index_digest = digest;
        } else {
            commitment_index_digest.reset();
        }
        if ((flags & SHIELDED_STATE_HAS_ACCOUNT_REGISTRY_SNAPSHOT) != 0) {
            if (version == 1) {
                shielded::registry::ShieldedAccountRegistrySnapshot snapshot;
                ::Unserialize(s, snapshot);
                auto persisted_snapshot = BuildPersistedRegistrySnapshot(snapshot);
                if (!persisted_snapshot.has_value()) {
                    throw std::ios_base::failure(
                        "ShieldedStateDisk invalid legacy account registry snapshot");
                }
                account_registry_snapshot = std::move(*persisted_snapshot);
            } else {
                shielded::registry::ShieldedAccountRegistryPersistedSnapshot snapshot;
                ::Unserialize(s, snapshot);
                account_registry_snapshot = std::move(snapshot);
            }
        } else {
            account_registry_snapshot.reset();
        }
        if (!s.empty()) {
            throw std::ios_base::failure("ShieldedStateDisk trailing bytes in versioned state");
        }
        return true;
    }

    template <typename Stream>
    bool TryUnserializePositional(Stream& s)
    {
        commitment_index_digest.reset();
        account_registry_snapshot.reset();

        ::Unserialize(s, tree);
        ::Unserialize(s, anchor_roots);
        ::Unserialize(s, tip_hash);
        ::Unserialize(s, tip_height);
        ::Unserialize(s, pool_balance);
        if (s.empty()) {
            return true;
        }

        if (TryConsumePositionalOptionalFields(s)) {
            return true;
        }
        throw std::ios_base::failure("ShieldedStateDisk invalid positional optional fields");
    }

    template <typename Stream>
    bool TryConsumePositionalOptionalFields(Stream& s)
    {
        const auto optional_start = s.size();

        if (optional_start == uint64_t{sizeof(uint256)}) {
            uint256 digest;
            ::Unserialize(s, digest);
            if (s.empty()) {
                commitment_index_digest = digest;
                account_registry_snapshot.reset();
                return true;
            }
            s.Rewind(optional_start - s.size());
        }

        if (optional_start > uint64_t{sizeof(uint256)}) {
            try {
                uint256 digest;
                bool has_account_registry_snapshot{false};
                ::Unserialize(s, digest);
                ::Unserialize(s, has_account_registry_snapshot);
                commitment_index_digest = digest;
                if (has_account_registry_snapshot) {
                    shielded::registry::ShieldedAccountRegistrySnapshot snapshot;
                    ::Unserialize(s, snapshot);
                    auto persisted_snapshot = BuildPersistedRegistrySnapshot(snapshot);
                    if (!persisted_snapshot.has_value()) {
                        throw std::ios_base::failure(
                            "ShieldedStateDisk invalid positional account registry snapshot");
                    }
                    account_registry_snapshot = std::move(*persisted_snapshot);
                } else {
                    account_registry_snapshot.reset();
                }
                if (s.empty()) {
                    return true;
                }
            } catch (const std::exception&) {
            }
            s.Rewind(optional_start - s.size());
            commitment_index_digest.reset();
            account_registry_snapshot.reset();
        }

        try {
            bool has_account_registry_snapshot{false};
            ::Unserialize(s, has_account_registry_snapshot);
            if (has_account_registry_snapshot) {
                shielded::registry::ShieldedAccountRegistrySnapshot snapshot;
                ::Unserialize(s, snapshot);
                auto persisted_snapshot = BuildPersistedRegistrySnapshot(snapshot);
                if (!persisted_snapshot.has_value()) {
                    throw std::ios_base::failure(
                        "ShieldedStateDisk invalid positional account registry snapshot");
                }
                account_registry_snapshot = std::move(*persisted_snapshot);
            }
            if (s.empty()) {
                commitment_index_digest.reset();
                return true;
            }
        } catch (const std::exception&) {
        }
        s.Rewind(optional_start - s.size());
        commitment_index_digest.reset();
        account_registry_snapshot.reset();
        return false;
    }
};

template <typename Cache>
[[nodiscard]] bool CacheContains(const std::shared_ptr<Cache>& current,
                                 const std::shared_ptr<Cache>& previous,
                                 const typename Cache::value_type& value)
{
    return (current && current->count(value) != 0) ||
           (previous && previous->count(value) != 0);
}

template <typename Cache>
void RotateCacheGeneration(std::shared_ptr<Cache>& current,
                           std::shared_ptr<Cache>& previous,
                           std::shared_ptr<Cache>& release_out,
                           size_t incoming_size)
{
    if (current == nullptr) {
        current = std::make_shared<Cache>();
    }
    if (current->size() + incoming_size >= NULLIFIER_CACHE_MAX_ENTRIES) {
        release_out = std::move(previous);
        previous = std::move(current);
        current = std::make_shared<Cache>();
        if (incoming_size >= NULLIFIER_CACHE_MAX_ENTRIES) {
            current->reserve(incoming_size);
        }
    }
}

template <typename Cache>
void RememberMissInCache(std::shared_ptr<Cache>& current,
                         std::shared_ptr<Cache>& previous,
                         std::shared_ptr<Cache>& release_out,
                         const typename Cache::value_type& value)
{
    RotateCacheGeneration(current, previous, release_out, /*incoming_size=*/1);
    current->insert(value);
}
} // namespace

NullifierHasher::NullifierHasher() :
    k0{FastRandomContext().rand64()},
    k1{FastRandomContext().rand64()} {}

NullifierSet::NullifierSet(const fs::path& db_path, size_t cache_bytes, bool memory_only, bool wipe_data)
    : m_db(std::make_unique<CDBWrapper>(DBParams{
          .path = db_path,
          .cache_bytes = cache_bytes,
          .memory_only = memory_only,
          .wipe_data = wipe_data,
          .obfuscate = true})),
      m_cache_current(std::make_shared<NullifierCache>()),
      m_miss_cache_current(std::make_shared<NullifierCache>()),
      m_settlement_anchor_cache_current(std::make_shared<SettlementAnchorCache>()),
      m_settlement_anchor_miss_cache_current(std::make_shared<SettlementAnchorCache>()),
      m_netting_manifest_cache_current(std::make_shared<NettingManifestCache>()),
      m_netting_manifest_miss_cache_current(std::make_shared<NettingManifestCache>())
{
    uint64_t persisted_count{0};
    if (!m_db->Read(std::make_pair(DB_NULLIFIER_COUNT, uint8_t{0}), persisted_count)) {
        persisted_count = CountNullifiersSlow();
        m_db->Write(std::make_pair(DB_NULLIFIER_COUNT, uint8_t{0}), persisted_count, /*fSync=*/true);
    }
    m_count.store(persisted_count, std::memory_order_relaxed);
}

NullifierSet::~NullifierSet() = default;

bool NullifierSet::Contains(const Nullifier& nf) const
{
    if (nf.IsNull()) return false;

    {
        std::shared_lock lock(m_rwlock);
        if (CacheContains(m_cache_current, m_cache_previous, nf)) return true;
        if (CacheContains(m_miss_cache_current, m_miss_cache_previous, nf)) return false;
    }
    if (ExistsInDB(nf)) return true;

    std::shared_ptr<NullifierCache> old_generation_release;
    {
        std::unique_lock lock(m_rwlock);
        if (CacheContains(m_cache_current, m_cache_previous, nf)) return true;
        if (!CacheContains(m_miss_cache_current, m_miss_cache_previous, nf)) {
            RememberMissInCache(m_miss_cache_current, m_miss_cache_previous, old_generation_release, nf);
        }
    }
    old_generation_release.reset();
    return false;
}

bool NullifierSet::AnyExist(const std::vector<Nullifier>& nullifiers) const
{
    std::vector<Nullifier> misses;
    misses.reserve(nullifiers.size());
    {
        std::shared_lock lock(m_rwlock);
        for (const auto& nf : nullifiers) {
            if (nf.IsNull()) return true;
            if (CacheContains(m_cache_current, m_cache_previous, nf)) return true;
            if (!CacheContains(m_miss_cache_current, m_miss_cache_previous, nf)) {
                misses.push_back(nf);
            }
        }
    }
    for (const auto& nf : misses) {
        if (ExistsInDB(nf)) return true;
    }

    std::shared_ptr<NullifierCache> old_generation_release;
    std::unique_lock lock(m_rwlock);
    for (const auto& nf : nullifiers) {
        if (CacheContains(m_cache_current, m_cache_previous, nf)) return true;
        if (!CacheContains(m_miss_cache_current, m_miss_cache_previous, nf)) {
            RememberMissInCache(m_miss_cache_current, m_miss_cache_previous, old_generation_release, nf);
        }
    }
    old_generation_release.reset();
    return false;
}

bool NullifierSet::Insert(const std::vector<Nullifier>& nullifiers)
{
    for (const auto& nf : nullifiers) {
        if (nf.IsNull()) {
            LogPrintf("NullifierSet::Insert rejected null nullifier\n");
            return false;
        }
    }

    std::shared_ptr<NullifierCache> old_generation_release;
    size_t actually_new{0};
    {
        std::unique_lock lock(m_rwlock);

        // Performance fix: count only truly new nullifiers for the atomic counter.
        for (const auto& nf : nullifiers) {
            bool in_current = m_cache_current && m_cache_current->count(nf);
            bool in_previous = m_cache_previous && m_cache_previous->count(nf);
            if (!in_current && !in_previous && !ExistsInDB(nf)) {
                ++actually_new;
            }
        }

        CDBBatch batch(*m_db);
        const uint64_t updated_count = m_count.load(std::memory_order_relaxed) + actually_new;
        for (const auto& nf : nullifiers) {
            batch.Write(std::make_pair(DB_NULLIFIER, nf), uint8_t{1});
        }
        batch.Write(std::make_pair(DB_NULLIFIER_COUNT, uint8_t{0}), updated_count);
        if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
            LogPrintf("NullifierSet::Insert failed DB batch write\n");
            return false;
        }

        // R6-604: generation-based cache rotation avoids O(n) erase loops while
        // holding the exclusive lock. Keep two generations hot/current+previous.
        RotateCacheGeneration(m_cache_current, m_cache_previous, old_generation_release, nullifiers.size());
        for (const auto& nf : nullifiers) {
            m_cache_current->insert(nf);
            if (m_miss_cache_current) m_miss_cache_current->erase(nf);
            if (m_miss_cache_previous) m_miss_cache_previous->erase(nf);
        }
    }
    // Performance fix: maintain atomic count for O(1) CountNullifiers().
    m_count.fetch_add(actually_new, std::memory_order_relaxed);
    // Release the oldest cache generation outside the lock.
    old_generation_release.reset();
    return true;
}

bool NullifierSet::Remove(const std::vector<Nullifier>& nullifiers)
{
    for (const auto& nf : nullifiers) {
        if (nf.IsNull()) {
            LogPrintf("NullifierSet::Remove rejected null nullifier\n");
            return false;
        }
    }

    std::unique_lock lock(m_rwlock);
    std::shared_ptr<NullifierCache> old_miss_generation_release;
    uint64_t actually_removed{0};
    std::set<Nullifier> unique_nullifiers;
    for (const auto& nf : nullifiers) {
        if (!unique_nullifiers.insert(nf).second) continue;
        const bool cached =
            (m_cache_current && m_cache_current->find(nf) != m_cache_current->end()) ||
            (m_cache_previous && m_cache_previous->find(nf) != m_cache_previous->end());
        if (cached || ExistsInDB(nf)) {
            ++actually_removed;
        }
    }

    CDBBatch batch(*m_db);
    const uint64_t current_count = m_count.load(std::memory_order_relaxed);
    const uint64_t updated_count = actually_removed > current_count ? 0 : current_count - actually_removed;
    for (const auto& nf : nullifiers) {
        batch.Erase(std::make_pair(DB_NULLIFIER, nf));
    }
    batch.Write(std::make_pair(DB_NULLIFIER_COUNT, uint8_t{0}), updated_count);
    if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
        LogPrintf("NullifierSet::Remove failed DB batch erase\n");
        return false;
    }

    for (const auto& nf : nullifiers) {
        if (m_cache_current) m_cache_current->erase(nf);
        if (m_cache_previous) m_cache_previous->erase(nf);
        if (!CacheContains(m_miss_cache_current, m_miss_cache_previous, nf)) {
            RememberMissInCache(m_miss_cache_current, m_miss_cache_previous, old_miss_generation_release, nf);
        }
    }
    m_count.fetch_sub(actually_removed, std::memory_order_relaxed);
    old_miss_generation_release.reset();
    return true;
}

bool NullifierSet::ContainsSettlementAnchor(const uint256& anchor) const
{
    if (anchor.IsNull()) return false;

    {
        std::shared_lock lock(m_rwlock);
        if (CacheContains(m_settlement_anchor_cache_current, m_settlement_anchor_cache_previous, anchor)) {
            return true;
        }
        if (CacheContains(m_settlement_anchor_miss_cache_current,
                          m_settlement_anchor_miss_cache_previous,
                          anchor)) {
            return false;
        }
    }
    if (SettlementAnchorExistsInDB(anchor)) return true;

    std::shared_ptr<SettlementAnchorCache> old_generation_release;
    {
        std::unique_lock lock(m_rwlock);
        if (CacheContains(m_settlement_anchor_cache_current, m_settlement_anchor_cache_previous, anchor)) {
            return true;
        }
        if (!CacheContains(m_settlement_anchor_miss_cache_current,
                           m_settlement_anchor_miss_cache_previous,
                           anchor)) {
            RememberMissInCache(m_settlement_anchor_miss_cache_current,
                                m_settlement_anchor_miss_cache_previous,
                                old_generation_release,
                                anchor);
        }
    }
    old_generation_release.reset();
    return false;
}

std::optional<ConfirmedSettlementAnchorState> NullifierSet::GetSettlementAnchorState(
    const uint256& anchor) const
{
    if (anchor.IsNull()) return std::nullopt;

    std::shared_lock lock(m_rwlock);
    ConfirmedSettlementAnchorState anchor_state;
    if (m_db->Read(std::make_pair(DB_SETTLEMENT_ANCHOR, anchor), anchor_state)) {
        if (anchor_state.anchor.IsNull()) {
            anchor_state.anchor = anchor;
        }
        if (anchor_state.anchor != anchor) {
            return std::nullopt;
        }
        return anchor_state;
    }

    uint8_t legacy_marker{0};
    if (!m_db->Read(std::make_pair(DB_SETTLEMENT_ANCHOR, anchor), legacy_marker)) {
        return std::nullopt;
    }
    return ConfirmedSettlementAnchorState{anchor, /*created_height=*/-1};
}

bool NullifierSet::InsertSettlementAnchors(const std::vector<uint256>& anchors)
{
    for (const auto& anchor : anchors) {
        if (anchor.IsNull()) {
            LogPrintf("NullifierSet::InsertSettlementAnchors rejected null anchor\n");
            return false;
        }
    }

    std::shared_ptr<SettlementAnchorCache> old_generation_release;
    {
        std::unique_lock lock(m_rwlock);

        CDBBatch batch(*m_db);
        for (const auto& anchor : anchors) {
            batch.Write(std::make_pair(DB_SETTLEMENT_ANCHOR, anchor), uint8_t{1});
        }
        if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
            LogPrintf("NullifierSet::InsertSettlementAnchors failed DB batch write\n");
            return false;
        }

        RotateCacheGeneration(m_settlement_anchor_cache_current,
                              m_settlement_anchor_cache_previous,
                              old_generation_release,
                              anchors.size());
        for (const auto& anchor : anchors) {
            m_settlement_anchor_cache_current->insert(anchor);
            if (m_settlement_anchor_miss_cache_current) m_settlement_anchor_miss_cache_current->erase(anchor);
            if (m_settlement_anchor_miss_cache_previous) m_settlement_anchor_miss_cache_previous->erase(anchor);
        }
    }

    old_generation_release.reset();
    return true;
}

bool NullifierSet::InsertSettlementAnchors(const std::vector<ConfirmedSettlementAnchorState>& anchors)
{
    for (const auto& anchor_state : anchors) {
        if (!anchor_state.IsValid()) {
            LogPrintf("NullifierSet::InsertSettlementAnchors rejected invalid anchor state\n");
            return false;
        }
    }

    std::shared_ptr<SettlementAnchorCache> old_generation_release;
    {
        std::unique_lock lock(m_rwlock);

        CDBBatch batch(*m_db);
        for (const auto& anchor_state : anchors) {
            batch.Write(std::make_pair(DB_SETTLEMENT_ANCHOR, anchor_state.anchor), anchor_state);
        }
        if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
            LogPrintf("NullifierSet::InsertSettlementAnchors failed DB batch write\n");
            return false;
        }

        RotateCacheGeneration(m_settlement_anchor_cache_current,
                              m_settlement_anchor_cache_previous,
                              old_generation_release,
                              anchors.size());
        for (const auto& anchor_state : anchors) {
            m_settlement_anchor_cache_current->insert(anchor_state.anchor);
            if (m_settlement_anchor_miss_cache_current) {
                m_settlement_anchor_miss_cache_current->erase(anchor_state.anchor);
            }
            if (m_settlement_anchor_miss_cache_previous) {
                m_settlement_anchor_miss_cache_previous->erase(anchor_state.anchor);
            }
        }
    }

    old_generation_release.reset();
    return true;
}

bool NullifierSet::RemoveSettlementAnchors(const std::vector<uint256>& anchors)
{
    for (const auto& anchor : anchors) {
        if (anchor.IsNull()) {
            LogPrintf("NullifierSet::RemoveSettlementAnchors rejected null anchor\n");
            return false;
        }
    }

    std::unique_lock lock(m_rwlock);
    std::shared_ptr<SettlementAnchorCache> old_miss_generation_release;
    CDBBatch batch(*m_db);
    for (const auto& anchor : anchors) {
        batch.Erase(std::make_pair(DB_SETTLEMENT_ANCHOR, anchor));
    }
    if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
        LogPrintf("NullifierSet::RemoveSettlementAnchors failed DB batch erase\n");
        return false;
    }

    for (const auto& anchor : anchors) {
        if (m_settlement_anchor_cache_current) m_settlement_anchor_cache_current->erase(anchor);
        if (m_settlement_anchor_cache_previous) m_settlement_anchor_cache_previous->erase(anchor);
        if (!CacheContains(m_settlement_anchor_miss_cache_current,
                           m_settlement_anchor_miss_cache_previous,
                           anchor)) {
            RememberMissInCache(m_settlement_anchor_miss_cache_current,
                                m_settlement_anchor_miss_cache_previous,
                                old_miss_generation_release,
                                anchor);
        }
    }
    old_miss_generation_release.reset();
    return true;
}

bool NullifierSet::ContainsNettingManifest(const uint256& manifest_id) const
{
    if (manifest_id.IsNull()) return false;

    {
        std::shared_lock lock(m_rwlock);
        if (CacheContains(m_netting_manifest_cache_current, m_netting_manifest_cache_previous, manifest_id)) {
            return true;
        }
        if (CacheContains(m_netting_manifest_miss_cache_current,
                          m_netting_manifest_miss_cache_previous,
                          manifest_id)) {
            return false;
        }
    }
    if (NettingManifestExistsInDB(manifest_id)) return true;

    std::shared_ptr<NettingManifestCache> old_generation_release;
    {
        std::unique_lock lock(m_rwlock);
        if (CacheContains(m_netting_manifest_cache_current, m_netting_manifest_cache_previous, manifest_id)) {
            return true;
        }
        if (!CacheContains(m_netting_manifest_miss_cache_current,
                           m_netting_manifest_miss_cache_previous,
                           manifest_id)) {
            RememberMissInCache(m_netting_manifest_miss_cache_current,
                                m_netting_manifest_miss_cache_previous,
                                old_generation_release,
                                manifest_id);
        }
    }
    old_generation_release.reset();
    return false;
}

std::optional<ConfirmedNettingManifestState> NullifierSet::GetNettingManifestState(
    const uint256& manifest_id) const
{
    if (manifest_id.IsNull()) return std::nullopt;

    {
        std::shared_lock lock(m_rwlock);
        if (CacheContains(m_netting_manifest_miss_cache_current,
                          m_netting_manifest_miss_cache_previous,
                          manifest_id)) {
            return std::nullopt;
        }
    }

    ConfirmedNettingManifestState manifest_state;
    {
        std::shared_lock lock(m_rwlock);
        if (!m_db->Read(std::make_pair(DB_NETTING_MANIFEST, manifest_id), manifest_state)) {
            lock.unlock();
            std::shared_ptr<NettingManifestCache> old_generation_release;
            std::unique_lock miss_lock(m_rwlock);
            if (!CacheContains(m_netting_manifest_miss_cache_current,
                               m_netting_manifest_miss_cache_previous,
                               manifest_id)) {
                RememberMissInCache(m_netting_manifest_miss_cache_current,
                                    m_netting_manifest_miss_cache_previous,
                                    old_generation_release,
                                    manifest_id);
            }
            miss_lock.unlock();
            old_generation_release.reset();
            return std::nullopt;
        }
    }
    if (manifest_state.manifest_id.IsNull()) {
        manifest_state.manifest_id = manifest_id;
    }
    if (manifest_state.manifest_id != manifest_id || !manifest_state.IsValid()) {
        std::shared_ptr<NettingManifestCache> old_generation_release;
        std::unique_lock lock(m_rwlock);
        if (!CacheContains(m_netting_manifest_miss_cache_current,
                           m_netting_manifest_miss_cache_previous,
                           manifest_id)) {
            RememberMissInCache(m_netting_manifest_miss_cache_current,
                                m_netting_manifest_miss_cache_previous,
                                old_generation_release,
                                manifest_id);
        }
        lock.unlock();
        old_generation_release.reset();
        return std::nullopt;
    }
    return manifest_state;
}

bool NullifierSet::InsertNettingManifests(const std::vector<ConfirmedNettingManifestState>& manifests)
{
    for (const auto& manifest_state : manifests) {
        if (!manifest_state.IsValid()) {
            LogPrintf("NullifierSet::InsertNettingManifests rejected invalid manifest state\n");
            return false;
        }
    }

    std::shared_ptr<NettingManifestCache> old_generation_release;
    {
        std::unique_lock lock(m_rwlock);

        CDBBatch batch(*m_db);
        for (const auto& manifest_state : manifests) {
            batch.Write(std::make_pair(DB_NETTING_MANIFEST, manifest_state.manifest_id), manifest_state);
        }
        if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
            LogPrintf("NullifierSet::InsertNettingManifests failed DB batch write\n");
            return false;
        }

        RotateCacheGeneration(m_netting_manifest_cache_current,
                              m_netting_manifest_cache_previous,
                              old_generation_release,
                              manifests.size());
        for (const auto& manifest_state : manifests) {
            m_netting_manifest_cache_current->insert(manifest_state.manifest_id);
            if (m_netting_manifest_miss_cache_current) {
                m_netting_manifest_miss_cache_current->erase(manifest_state.manifest_id);
            }
            if (m_netting_manifest_miss_cache_previous) {
                m_netting_manifest_miss_cache_previous->erase(manifest_state.manifest_id);
            }
        }
    }

    old_generation_release.reset();
    return true;
}

bool NullifierSet::RemoveNettingManifests(const std::vector<uint256>& manifest_ids)
{
    for (const auto& manifest_id : manifest_ids) {
        if (manifest_id.IsNull()) {
            LogPrintf("NullifierSet::RemoveNettingManifests rejected null manifest id\n");
            return false;
        }
    }

    std::unique_lock lock(m_rwlock);
    std::shared_ptr<NettingManifestCache> old_miss_generation_release;
    CDBBatch batch(*m_db);
    for (const auto& manifest_id : manifest_ids) {
        batch.Erase(std::make_pair(DB_NETTING_MANIFEST, manifest_id));
    }
    if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
        LogPrintf("NullifierSet::RemoveNettingManifests failed DB batch erase\n");
        return false;
    }

    for (const auto& manifest_id : manifest_ids) {
        if (m_netting_manifest_cache_current) m_netting_manifest_cache_current->erase(manifest_id);
        if (m_netting_manifest_cache_previous) m_netting_manifest_cache_previous->erase(manifest_id);
        if (!CacheContains(m_netting_manifest_miss_cache_current,
                           m_netting_manifest_miss_cache_previous,
                           manifest_id)) {
            RememberMissInCache(m_netting_manifest_miss_cache_current,
                                m_netting_manifest_miss_cache_previous,
                                old_miss_generation_release,
                                manifest_id);
        }
    }
    old_miss_generation_release.reset();
    return true;
}

size_t NullifierSet::CacheSize() const
{
    std::shared_lock lock(m_rwlock);
    size_t total{0};
    if (m_cache_current) total += m_cache_current->size();
    if (m_cache_previous) total += m_cache_previous->size();
    return total;
}

size_t NullifierSet::DynamicMemoryUsage() const
{
    constexpr size_t per_entry_overhead{64};
    std::shared_lock lock(m_rwlock);
    size_t cache_entries{0};
    if (m_cache_current) cache_entries += m_cache_current->size();
    if (m_cache_previous) cache_entries += m_cache_previous->size();
    if (m_miss_cache_current) cache_entries += m_miss_cache_current->size();
    if (m_miss_cache_previous) cache_entries += m_miss_cache_previous->size();
    size_t settlement_anchor_cache_entries{0};
    if (m_settlement_anchor_cache_current) settlement_anchor_cache_entries += m_settlement_anchor_cache_current->size();
    if (m_settlement_anchor_cache_previous) settlement_anchor_cache_entries += m_settlement_anchor_cache_previous->size();
    if (m_settlement_anchor_miss_cache_current) settlement_anchor_cache_entries += m_settlement_anchor_miss_cache_current->size();
    if (m_settlement_anchor_miss_cache_previous) settlement_anchor_cache_entries += m_settlement_anchor_miss_cache_previous->size();
    size_t netting_manifest_cache_entries{0};
    if (m_netting_manifest_cache_current) netting_manifest_cache_entries += m_netting_manifest_cache_current->size();
    if (m_netting_manifest_cache_previous) netting_manifest_cache_entries += m_netting_manifest_cache_previous->size();
    if (m_netting_manifest_miss_cache_current) netting_manifest_cache_entries += m_netting_manifest_miss_cache_current->size();
    if (m_netting_manifest_miss_cache_previous) netting_manifest_cache_entries += m_netting_manifest_miss_cache_previous->size();
    return m_db->DynamicMemoryUsage() +
           (cache_entries * (sizeof(Nullifier) + per_entry_overhead)) +
           (settlement_anchor_cache_entries * (sizeof(uint256) + per_entry_overhead)) +
           (netting_manifest_cache_entries * (sizeof(uint256) + per_entry_overhead));
}

uint64_t NullifierSet::CountNullifiers() const
{
    // Performance fix: return the maintained counter instead of doing an
    // O(n) full LevelDB scan which blocks all insert/remove operations
    // for the entire duration. The counter is maintained atomically by
    // Insert() and Remove().
    return m_count.load(std::memory_order_relaxed);
}

uint64_t NullifierSet::CountNullifiersSlow() const
{
    std::shared_lock lock(m_rwlock);
    std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
    cursor->Seek(std::make_pair(DB_NULLIFIER, uint256{}));

    uint64_t count{0};
    while (cursor->Valid()) {
        std::pair<uint8_t, Nullifier> key;
        if (!cursor->GetKey(key) || key.first != DB_NULLIFIER) break;
        if (count == std::numeric_limits<uint64_t>::max()) break;
        ++count;
        cursor->Next();
    }
    return count;
}

bool NullifierSet::Flush()
{
    std::unique_lock lock(m_rwlock);
    CDBBatch batch(*m_db);
    return m_db->WriteBatch(batch, /*fSync=*/true);
}

bool NullifierSet::ReadPoolBalance(CAmount& balance) const
{
    std::shared_lock lock(m_rwlock);
    const auto key = std::make_pair(DB_POOL_BALANCE, uint8_t{0});
    if (!m_db->Read(key, balance)) {
        balance = 0;
    }
    if (!MoneyRange(balance)) {
        LogPrintf("NullifierSet::ReadPoolBalance read out-of-range balance\n");
        return false;
    }
    return true;
}

bool NullifierSet::WritePoolBalance(CAmount balance)
{
    if (!MoneyRange(balance)) {
        LogPrintf("NullifierSet::WritePoolBalance rejected out-of-range balance\n");
        return false;
    }

    std::unique_lock lock(m_rwlock);
    return m_db->Write(std::make_pair(DB_POOL_BALANCE, uint8_t{0}), balance, /*fSync=*/true);
}

std::optional<ShieldedStateMutationMarker> NullifierSet::ReadMutationMarker() const
{
    std::shared_lock lock(m_rwlock);
    const auto key = std::make_pair(DB_STATE_MUTATION_MARKER, uint8_t{0});
    if (!m_db->Exists(key)) {
        return std::nullopt;
    }

    ShieldedStateMutationMarker marker;
    if (!m_db->Read(key, marker) || !marker.IsValid()) {
        LogPrintf("NullifierSet::ReadMutationMarker read invalid shielded mutation marker\n");
        return ShieldedStateMutationMarker{};
    }
    return marker;
}

bool NullifierSet::WriteMutationMarker(const ShieldedStateMutationMarker& marker)
{
    if (!marker.IsValid()) {
        LogPrintf("NullifierSet::WriteMutationMarker rejected invalid marker\n");
        return false;
    }

    std::unique_lock lock(m_rwlock);
    return m_db->Write(std::make_pair(DB_STATE_MUTATION_MARKER, uint8_t{0}), marker, /*fSync=*/true);
}

bool NullifierSet::ClearMutationMarker()
{
    std::unique_lock lock(m_rwlock);
    return m_db->Erase(std::make_pair(DB_STATE_MUTATION_MARKER, uint8_t{0}));
}

bool NullifierSet::ReadSnapshotBridgeMetadataHint() const
{
    std::shared_lock lock(m_rwlock);
    uint8_t preserve_snapshot_extras{0};
    if (!m_db->Read(std::make_pair(DB_SNAPSHOT_BRIDGE_METADATA_HINT, uint8_t{0}),
                    preserve_snapshot_extras)) {
        return false;
    }
    return preserve_snapshot_extras != 0;
}

bool NullifierSet::WriteSnapshotBridgeMetadataHint(bool preserve_snapshot_extras)
{
    std::unique_lock lock(m_rwlock);
    return m_db->Write(std::make_pair(DB_SNAPSHOT_BRIDGE_METADATA_HINT, uint8_t{0}),
                       static_cast<uint8_t>(preserve_snapshot_extras ? 1 : 0),
                       /*fSync=*/true);
}

bool NullifierSet::ReadPersistedState(shielded::ShieldedMerkleTree& tree,
                                      std::vector<uint256>& anchor_roots,
                                      uint256& tip_hash,
                                      int32_t& tip_height,
                                      CAmount& balance,
                                      std::optional<uint256>& commitment_index_digest,
                                      std::optional<
                                          shielded::registry::ShieldedAccountRegistryPersistedSnapshot>&
                                          account_registry_snapshot) const
{
    std::shared_lock lock(m_rwlock);
    ShieldedStateDisk state;
    if (!m_db->Read(std::make_pair(DB_PERSISTED_STATE, uint8_t{0}), state)) {
        return false;
    }
    if (!MoneyRange(state.pool_balance) || state.pool_balance < 0) {
        LogPrintf("NullifierSet::ReadPersistedState rejected out-of-range balance\n");
        return false;
    }
    tree = std::move(state.tree);
    anchor_roots = std::move(state.anchor_roots);
    tip_hash = state.tip_hash;
    tip_height = state.tip_height;
    balance = state.pool_balance;
    commitment_index_digest = state.commitment_index_digest;
    account_registry_snapshot = state.account_registry_snapshot;
    return true;
}

bool NullifierSet::WritePersistedState(const shielded::ShieldedMerkleTree& tree,
                                       const std::vector<uint256>& anchor_roots,
                                       const uint256& tip_hash,
                                       int32_t tip_height,
                                       CAmount balance,
                                       std::optional<uint256> commitment_index_digest,
                                       std::optional<
                                           shielded::registry::ShieldedAccountRegistryPersistedSnapshot>
                                           account_registry_snapshot)
{
    if (!MoneyRange(balance) || balance < 0) {
        LogPrintf("NullifierSet::WritePersistedState rejected out-of-range balance\n");
        return false;
    }

    ShieldedStateDisk state;
    state.tree = tree;
    state.anchor_roots = anchor_roots;
    state.tip_hash = tip_hash;
    state.tip_height = tip_height;
    state.pool_balance = balance;
    state.commitment_index_digest = std::move(commitment_index_digest);
    state.account_registry_snapshot = std::move(account_registry_snapshot);

    std::unique_lock lock(m_rwlock);
    return m_db->Write(std::make_pair(DB_PERSISTED_STATE, uint8_t{0}), state, /*fSync=*/true);
}

bool NullifierSet::ExistsInDB(const Nullifier& nf) const
{
    return m_db->Exists(std::make_pair(DB_NULLIFIER, nf));
}

bool NullifierSet::SettlementAnchorExistsInDB(const uint256& anchor) const
{
    return m_db->Exists(std::make_pair(DB_SETTLEMENT_ANCHOR, anchor));
}

bool NullifierSet::NettingManifestExistsInDB(const uint256& manifest_id) const
{
    return m_db->Exists(std::make_pair(DB_NETTING_MANIFEST, manifest_id));
}
