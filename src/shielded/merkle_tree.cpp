// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/merkle_tree.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <leveldb/cache.h>
#include <leveldb/db.h>
#include <logging.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <deque>
#include <list>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace shielded {

namespace {
constexpr uint8_t DB_COMMITMENT_POS{'C'};
constexpr size_t DEFAULT_COMMITMENT_INDEX_LRU_CAPACITY{262144};
constexpr std::string_view COMMITMENT_INDEX_DIGEST_TAG{"BTX_Shielded_Commitment_Index_V1"};

struct CommitmentLruEntry {
    uint256 commitment;
    std::list<uint64_t>::iterator lru_it;
};

} // namespace

struct ShieldedMerkleTree::CommitmentIndexStore
{
    CommitmentIndexStore(const fs::path& db_path,
                         size_t db_cache_bytes,
                         size_t lru_capacity,
                         bool memory_only,
                         bool wipe_data) :
        max_lru_entries(std::max<size_t>(1, lru_capacity))
    {
        if (memory_only) {
            throw std::runtime_error("Shielded commitment index memory_only mode unsupported");
        }

        leveldb::Options options;
        options.create_if_missing = true;
        options.paranoid_checks = true;
        block_cache.reset(leveldb::NewLRUCache(db_cache_bytes));
        options.block_cache = block_cache.get();

        if (wipe_data) {
            leveldb::DestroyDB(fs::PathToString(db_path), options);
        }
        fs::create_directories(db_path);

        leveldb::DB* raw_db{nullptr};
        const leveldb::Status status = leveldb::DB::Open(options, fs::PathToString(db_path), &raw_db);
        if (!status.ok() || raw_db == nullptr) {
            throw std::runtime_error("failed to open commitment index DB: " + status.ToString());
        }
        db.reset(raw_db);
    }

    [[nodiscard]] bool Write(uint64_t position, const uint256& commitment)
    {
        const auto key = MakeKey(position);
        const std::string value{
            reinterpret_cast<const char*>(commitment.begin()),
            reinterpret_cast<const char*>(commitment.end())};
        leveldb::WriteOptions write_opts;
        // L6/P4-H durability hardening: persist the commitment-index leaf
        // synchronously before the in-memory frontier advances so a process
        // crash cannot strand the retained index behind the accepted tree.
        write_opts.sync = true;
        if (!db->Put(write_opts, key, value).ok()) return false;
        std::unique_lock<std::shared_mutex> lock(cache_mutex);
        TouchCache(position, commitment);
        return true;
    }

    [[nodiscard]] std::optional<uint256> Read(uint64_t position) const
    {
        // Fast path: shared lock for cache lookup.  If hit, try to promote
        // the entry in the LRU order under an exclusive lock to prevent
        // frequently-accessed entries from being evicted (Finding 3 fix).
        {
            std::shared_lock<std::shared_mutex> shared(cache_mutex);
            auto it = lru_cache.find(position);
            if (it != lru_cache.end()) {
                uint256 result = it->second.commitment;
                shared.unlock();
                // Best-effort LRU promotion — skip if contended to avoid
                // blocking concurrent readers on the hot path.
                std::unique_lock<std::shared_mutex> exclusive(cache_mutex, std::try_to_lock);
                if (exclusive.owns_lock()) {
                    auto it2 = lru_cache.find(position);
                    if (it2 != lru_cache.end()) {
                        lru_order.splice(lru_order.begin(), lru_order, it2->second.lru_it);
                    }
                }
                return result;
            }
        }

        std::string value;
        const leveldb::Status status = db->Get(leveldb::ReadOptions{}, MakeKey(position), &value);
        if (!status.ok()) return std::nullopt;
        if (value.size() != 32) return std::nullopt;

        uint256 commitment;
        std::memcpy(commitment.begin(), value.data(), 32);
        // Exclusive lock only on cache miss to insert the new entry.
        std::unique_lock<std::shared_mutex> exclusive(cache_mutex);
        TouchCache(position, commitment);
        return commitment;
    }

    [[nodiscard]] bool Exists(uint64_t position) const
    {
        std::string value;
        const leveldb::Status status = db->Get(leveldb::ReadOptions{}, MakeKey(position), &value);
        return status.ok();
    }

    /**
     * Finding 6 fix: Sequential range read using LevelDB iterator instead of
     * individual Get() calls. Reduces Truncate() I/O from O(n) random reads
     * to a single sequential scan, which is significantly faster for deep reorgs.
     */
    [[nodiscard]] std::vector<uint256> ReadRange(uint64_t start, uint64_t end) const
    {
        std::vector<uint256> result;
        if (start >= end) return result;
        result.reserve(static_cast<size_t>(end - start));

        leveldb::ReadOptions read_opts;
        read_opts.fill_cache = true;
        std::unique_ptr<leveldb::Iterator> iter(db->NewIterator(read_opts));

        uint64_t pos = start;
        iter->Seek(MakeKey(start));
        for (; iter->Valid() && pos < end; iter->Next(), ++pos) {
            // Verify we're reading the expected sequential position.
            const auto expected_key = MakeKey(pos);
            if (iter->key().ToString() != expected_key) {
                // Gap in sequential data — fall back to point reads.
                break;
            }
            if (iter->value().size() != 32) break;
            uint256 commitment;
            std::memcpy(commitment.begin(), iter->value().data(), 32);
            result.push_back(commitment);
        }

        // Fall back to point reads for any remaining positions.
        for (; pos < end; ++pos) {
            std::string value;
            if (!db->Get(leveldb::ReadOptions{}, MakeKey(pos), &value).ok()) break;
            if (value.size() != 32) break;
            uint256 commitment;
            std::memcpy(commitment.begin(), value.data(), 32);
            result.push_back(commitment);
        }

        return result;
    }

private:
    [[nodiscard]] static std::string MakeKey(uint64_t position)
    {
        std::array<unsigned char, 1 + sizeof(uint64_t)> key{};
        key[0] = DB_COMMITMENT_POS;
        // Big-endian encoding so that lexicographic key order matches numeric
        // position order, enabling efficient sequential iterator scans in
        // ReadRange().  (Previously used WriteLE64 which broke iterator ordering.)
        WriteBE64(key.data() + 1, position);
        return std::string(reinterpret_cast<const char*>(key.data()), key.size());
    }

    void TouchCache(uint64_t position, const uint256& commitment) const
    {
        auto it = lru_cache.find(position);
        if (it != lru_cache.end()) {
            it->second.commitment = commitment;
            lru_order.splice(lru_order.begin(), lru_order, it->second.lru_it);
            return;
        }

        lru_order.push_front(position);
        lru_cache.emplace(position, CommitmentLruEntry{commitment, lru_order.begin()});
        if (lru_cache.size() > max_lru_entries) {
            const uint64_t evict = lru_order.back();
            lru_order.pop_back();
            lru_cache.erase(evict);
        }
    }

public:
    std::unique_ptr<leveldb::DB> db;
    std::unique_ptr<leveldb::Cache> block_cache;
    const size_t max_lru_entries;
    mutable std::shared_mutex cache_mutex;
    mutable std::list<uint64_t> lru_order;
    mutable std::unordered_map<uint64_t, CommitmentLruEntry> lru_cache;
};

std::mutex ShieldedMerkleTree::s_commitment_store_mutex;
std::shared_ptr<ShieldedMerkleTree::CommitmentIndexStore> ShieldedMerkleTree::s_commitment_store;

// ===================================================================
// Domain-separated hash primitives
// ===================================================================

uint256 EmptyLeafHash()
{
    // Computed once and cached.
    static const uint256 cached = []() {
        const std::string tag{"BTX_Shielded_Empty_Leaf_V1"};
        uint256 result;
        CSHA256()
            .Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size())
            .Finalize(result.begin());
        return result;
    }();
    return cached;
}

uint256 BranchHash(const uint256& left, const uint256& right)
{
    // Domain-separated: SHA256("BTX_Shielded_Branch_V1" || left || right).
    // Performance fix: precompute the SHA-256 midstate after hashing the tag
    // prefix, so each invocation only needs to hash the two 32-byte children.
    // This saves one SHA-256 block per call on the hot path during Merkle
    // tree operations (~6400 calls per block with 200 shielded outputs).
    static const CSHA256 tag_midstate = []() {
        const std::string tag{"BTX_Shielded_Branch_V1"};
        CSHA256 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size());
        return hasher;
    }();
    uint256 result;
    CSHA256(tag_midstate)
        .Write(left.begin(), 32)
        .Write(right.begin(), 32)
        .Finalize(result.begin());
    return result;
}

const uint256& EmptyRoot(size_t depth)
{
    static const auto table = []() {
        std::array<uint256, MERKLE_DEPTH + 1> t;
        t[0] = EmptyLeafHash();
        for (size_t d = 1; d <= MERKLE_DEPTH; ++d) {
            t[d] = BranchHash(t[d - 1], t[d - 1]);
        }
        return t;
    }();

    // R6-414: Defensive bounds check — depth could come from deserialized data.
    if (depth > MERKLE_DEPTH) {
        throw std::out_of_range("EmptyRoot: depth exceeds MERKLE_DEPTH");
    }
    return table[depth];
}

// ===================================================================
// ShieldedMerkleTree
// ===================================================================

ShieldedMerkleTree::ShieldedMerkleTree(IndexStorageMode mode)
    : m_index_storage_mode_(mode)
{
    if (mode == IndexStorageMode::MEMORY_ONLY) {
        return;
    }
    std::lock_guard<std::mutex> lock(s_commitment_store_mutex);
    commitment_index_store_ = s_commitment_store;
    if (commitment_index_store_) {
        commitment_index_mem_.reset();
    }
}

bool ShieldedMerkleTree::ConfigureCommitmentIndexStore(const fs::path& db_path,
                                                       size_t db_cache_bytes,
                                                       size_t lru_capacity,
                                                       bool memory_only,
                                                       bool wipe_data)
{
    try {
        auto configured = std::make_shared<CommitmentIndexStore>(
            db_path,
            db_cache_bytes,
            lru_capacity == 0 ? DEFAULT_COMMITMENT_INDEX_LRU_CAPACITY : lru_capacity,
            memory_only,
            wipe_data);
        std::lock_guard<std::mutex> lock(s_commitment_store_mutex);
        s_commitment_store = std::move(configured);
    } catch (const std::exception& e) {
        LogPrintf("ShieldedMerkleTree::ConfigureCommitmentIndexStore failed: %s\n", e.what());
        return false;
    }
    return true;
}

void ShieldedMerkleTree::ResetCommitmentIndexStore()
{
    std::lock_guard<std::mutex> lock(s_commitment_store_mutex);
    s_commitment_store.reset();
}

bool ShieldedMerkleTree::WriteCommitmentAt(uint64_t position, const uint256& commitment)
{
    if (!commitment_index_enabled_) return true;

    if (commitment_index_store_) {
        return commitment_index_store_->Write(position, commitment);
    }

    if (!commitment_index_mem_) return false;
    // Hard cap: refuse to grow the in-memory index beyond MEM_INDEX_HARD_CAP
    // to prevent unbounded memory consumption on nodes without a LevelDB store.
    static constexpr size_t MEM_INDEX_HARD_CAP{10'000'000};
    static constexpr size_t MEM_INDEX_WARN_THRESHOLD{1'000'000};
    if (commitment_index_mem_->size() == MEM_INDEX_WARN_THRESHOLD) {
        LogPrintf("WARNING: ShieldedMerkleTree in-memory commitment index reached %u entries "
                  "(~%u MB). Configure a LevelDB commitment index store for production use.\n",
                  static_cast<unsigned>(MEM_INDEX_WARN_THRESHOLD),
                  static_cast<unsigned>(MEM_INDEX_WARN_THRESHOLD * 32 / (1024 * 1024)));
    }
    if (commitment_index_mem_->size() >= MEM_INDEX_HARD_CAP && position >= commitment_index_mem_->size()) {
        LogPrintf("ERROR: ShieldedMerkleTree in-memory commitment index reached hard cap of %u entries "
                  "(~%u MB). Configure a LevelDB commitment index store to continue.\n",
                  static_cast<unsigned>(MEM_INDEX_HARD_CAP),
                  static_cast<unsigned>(MEM_INDEX_HARD_CAP * 32 / (1024 * 1024)));
        return false;
    }
    EnsureCommitmentIndexWritable();
    if (position < commitment_index_mem_->size()) {
        (*commitment_index_mem_)[position] = commitment;
        return true;
    }
    if (position != commitment_index_mem_->size()) return false;
    commitment_index_mem_->push_back(commitment);
    return true;
}

std::optional<uint256> ShieldedMerkleTree::ReadCommitmentAt(uint64_t position) const
{
    if (!commitment_index_enabled_) return std::nullopt;
    if (position >= size_) return std::nullopt;

    if (commitment_index_store_) {
        return commitment_index_store_->Read(position);
    }

    if (!commitment_index_mem_) return std::nullopt;
    if (position >= commitment_index_mem_->size()) return std::nullopt;
    return (*commitment_index_mem_)[position];
}

bool ShieldedMerkleTree::HasCommitmentAt(uint64_t position) const
{
    if (!commitment_index_enabled_) return false;
    if (position >= size_) return false;
    if (commitment_index_store_) return commitment_index_store_->Exists(position);
    return commitment_index_mem_ && position < commitment_index_mem_->size();
}

void ShieldedMerkleTree::Append(const uint256& commitment)
{
    if (size_ >= MERKLE_MAX_LEAVES) {
        throw std::runtime_error("ShieldedMerkleTree: tree is full (2^32 leaves)");
    }

    // Finding 5 fix: persist commitment index BEFORE mutating frontier state.
    // This ensures that if the DB write fails, the tree remains in a consistent
    // state (size_ and frontier are unchanged).
    if (!WriteCommitmentAt(size_, commitment)) {
        throw std::runtime_error("ShieldedMerkleTree: failed to persist commitment index");
    }

    if (!left_.has_value()) {
        // Empty pair: place in left slot.
        left_ = commitment;
    } else if (!right_.has_value()) {
        // Left occupied, right empty: place in right slot.
        right_ = commitment;
    } else {
        // Both left and right occupied.
        // 1. Combine them into a depth-1 hash.
        // 2. Propagate upward through parents.
        // 3. Start a new pair with the new commitment on the left.
        uint256 combined = BranchHash(*left_, *right_);
        left_ = commitment;
        right_ = std::nullopt;

        bool propagating = true;
        for (size_t i = 0; i < parents_.size() && propagating; ++i) {
            if (parents_[i].has_value()) {
                combined = BranchHash(*parents_[i], combined);
                parents_[i] = std::nullopt;
            } else {
                parents_[i] = combined;
                propagating = false;
            }
        }
        if (propagating) {
            parents_.push_back(combined);
        }
    }

    ++size_;
    MaybeRecordFrontierCheckpoint();
}

uint256 ShieldedMerkleTree::Root() const
{
    PathFiller filler;
    return Root(MERKLE_DEPTH, std::move(filler));
}

uint256 ShieldedMerkleTree::Root(size_t depth, PathFiller filler) const
{
    if (size_ == 0) {
        return EmptyRoot(depth);
    }

    // Depth 0: leaf pair.
    uint256 current;
    if (right_.has_value()) {
        current = BranchHash(*left_, *right_);
    } else {
        current = BranchHash(*left_, filler.Next(0));
    }

    // Depths 1..parents_.size(): walk up the frontier.
    size_t d = 1;
    for (size_t i = 0; i < parents_.size(); ++i, ++d) {
        if (parents_[i].has_value()) {
            current = BranchHash(*parents_[i], current);
        } else {
            current = BranchHash(current, filler.Next(d));
        }
    }

    // Fill remaining levels to reach the target depth.
    for (; d < depth; ++d) {
        current = BranchHash(current, filler.Next(d));
    }

    return current;
}

uint256 ShieldedMerkleTree::LastLeaf() const
{
    if (size_ == 0) {
        throw std::runtime_error("ShieldedMerkleTree: tree is empty");
    }
    return right_.has_value() ? *right_ : *left_;
}

std::optional<uint256> ShieldedMerkleTree::CommitmentAt(uint64_t position) const
{
    return ReadCommitmentAt(position);
}

std::optional<uint256> ShieldedMerkleTree::CommitmentIndexDigest() const
{
    if (!commitment_index_enabled_) return std::nullopt;

    HashWriter hw;
    hw.write(MakeByteSpan(COMMITMENT_INDEX_DIGEST_TAG));
    hw << size_;

    if (commitment_index_store_) {
        const auto commitments = commitment_index_store_->ReadRange(0, size_);
        if (commitments.size() != size_) return std::nullopt;
        for (const auto& commitment : commitments) {
            hw << commitment;
        }
        return hw.GetSHA256();
    }

    if (!commitment_index_mem_) return std::nullopt;
    if (commitment_index_mem_->size() < size_) return std::nullopt;
    for (uint64_t i = 0; i < size_; ++i) {
        hw << (*commitment_index_mem_)[i];
    }
    return hw.GetSHA256();
}

bool ShieldedMerkleTree::HasCommitmentIndex() const
{
    if (!commitment_index_enabled_) return false;
    if (size_ == 0) return true;
    return HasCommitmentAt(size_ - 1);
}

bool ShieldedMerkleTree::Truncate(uint64_t new_size)
{
    if (new_size > size_) return false;
    if (new_size == size_) return true;
    if (!HasCommitmentIndex()) return false;

    // Rebuild from the nearest frontier checkpoint, then append the remainder.
    // This reduces truncation cost for deep reorgs from O(n) full replay.
    ShieldedMerkleTree rebuilt{m_index_storage_mode_};
    uint64_t resume_from{0};
    if (new_size >= FRONTIER_CHECKPOINT_INTERVAL &&
        frontier_checkpoints_ &&
        !frontier_checkpoints_->empty()) {
        auto it = std::upper_bound(
            frontier_checkpoints_->begin(),
            frontier_checkpoints_->end(),
            new_size,
            [](const uint64_t needle, const FrontierCheckpoint& cp) { return needle < cp.size; });
        if (it != frontier_checkpoints_->begin()) {
            --it;
            const FrontierCheckpoint& cp = *it;
            rebuilt.size_ = cp.size;
            rebuilt.left_ = cp.left;
            rebuilt.right_ = cp.right;
            rebuilt.parents_ = cp.parents;
            if (rebuilt.commitment_index_mem_) {
                // Finding 6 fix: use batch range read when LevelDB store available.
                if (commitment_index_store_ && cp.size > 0) {
                    auto range = commitment_index_store_->ReadRange(0, cp.size);
                    if (range.size() != static_cast<size_t>(cp.size)) return false;
                    *rebuilt.commitment_index_mem_ = std::move(range);
                } else {
                    rebuilt.commitment_index_mem_->reserve(static_cast<size_t>(new_size));
                    for (uint64_t i = 0; i < cp.size; ++i) {
                        const auto commitment = ReadCommitmentAt(i);
                        if (!commitment.has_value()) return false;
                        rebuilt.commitment_index_mem_->push_back(*commitment);
                    }
                }
            }
            rebuilt.frontier_checkpoints_->assign(frontier_checkpoints_->begin(), it + 1);
            resume_from = cp.size;
        }
    }

    // Finding 6 fix: use batch range read for the remaining positions.
    if (commitment_index_store_ && resume_from < new_size) {
        auto range = commitment_index_store_->ReadRange(resume_from, new_size);
        if (range.size() != static_cast<size_t>(new_size - resume_from)) return false;
        if (resume_from == 0 && rebuilt.commitment_index_mem_) {
            rebuilt.commitment_index_mem_->reserve(static_cast<size_t>(new_size));
        }
        for (auto& commitment : range) {
            rebuilt.Append(commitment);
        }
    } else {
        if (resume_from == 0 && rebuilt.commitment_index_mem_) {
            rebuilt.commitment_index_mem_->reserve(static_cast<size_t>(new_size));
        }
        for (uint64_t i = resume_from; i < new_size; ++i) {
            auto commitment = ReadCommitmentAt(i);
            if (!commitment.has_value()) return false;
            rebuilt.Append(*commitment);
        }
    }

    *this = std::move(rebuilt);
    return true;
}

bool ShieldedMerkleTree::RemoveLast(uint64_t count)
{
    if (count > size_) return false;
    return Truncate(size_ - count);
}

ShieldedMerkleWitness ShieldedMerkleTree::Witness() const
{
    return ShieldedMerkleWitness(*this);
}

void ShieldedMerkleTree::EnsureCommitmentIndexWritable()
{
    if (!commitment_index_mem_) return;
    if (commitment_index_mem_.use_count() > 1) {
        commitment_index_mem_ = std::make_shared<std::vector<uint256>>(*commitment_index_mem_);
    }
}

void ShieldedMerkleTree::EnsureCheckpointsWritable()
{
    if (!frontier_checkpoints_) return;
    if (frontier_checkpoints_.use_count() > 1) {
        frontier_checkpoints_ = std::make_shared<std::vector<FrontierCheckpoint>>(*frontier_checkpoints_);
    }
}

void ShieldedMerkleTree::MaybeRecordFrontierCheckpoint()
{
    if (!frontier_checkpoints_) return;
    if (size_ == 0 || (size_ % FRONTIER_CHECKPOINT_INTERVAL) != 0) return;
    EnsureCheckpointsWritable();
    if (!frontier_checkpoints_->empty() && frontier_checkpoints_->back().size == size_) {
        return;
    }
    frontier_checkpoints_->push_back(FrontierCheckpoint{
        .size = size_,
        .left = left_,
        .right = right_,
        .parents = parents_,
    });
}

// ===================================================================
// ShieldedMerkleWitness
// ===================================================================

ShieldedMerkleWitness::ShieldedMerkleWitness(const ShieldedMerkleTree& tree)
    : tree_(tree)
{
    if (tree.IsEmpty()) {
        throw std::runtime_error("ShieldedMerkleWitness: cannot witness empty tree");
    }
}

uint64_t ShieldedMerkleWitness::Position() const
{
    return tree_.Size() - 1;
}

std::deque<uint256> ShieldedMerkleWitness::PartialPath() const
{
    std::deque<uint256> uncles;
    for (const auto& h : filled_) {
        uncles.push_back(h);
    }
    if (cursor_.has_value()) {
        uncles.push_back(
            cursor_->Root(cursor_depth_, PathFiller()));
    }
    return uncles;
}

uint256 ShieldedMerkleWitness::Root() const
{
    return tree_.Root(MERKLE_DEPTH, PathFiller(PartialPath()));
}

void ShieldedMerkleWitness::ComputePath(
    std::array<uint256, MERKLE_DEPTH>& auth_path, uint64_t& pos) const
{
    // The authentication path is derived from the snapshot tree + the
    // partial path filler, using the same walk as Root() but recording
    // siblings instead of combining them.
    //
    // At each depth the "current" node is on the path from the witnessed
    // leaf to the root.  The *sibling* at that depth goes into auth_path.
    // The position bit at that depth tells whether the current node is
    // left (0) or right (1).

    PathFiller filler(PartialPath());
    pos = Position();

    const auto& left = tree_.Left();
    const auto& right = tree_.Right();
    const auto& parents = tree_.Parents();

    // Depth 0.
    if (right.has_value()) {
        // Last leaf was right child; sibling = left.
        auth_path[0] = *left;
    } else {
        // Last leaf was left child; sibling = filler (empty or first uncle).
        auth_path[0] = filler.Next(0);
    }

    // Depths 1..parents.size().
    size_t d = 1;
    for (size_t i = 0; i < parents.size(); ++i, ++d) {
        if (parents[i].has_value()) {
            auth_path[d] = *parents[i];
        } else {
            auth_path[d] = filler.Next(d);
        }
    }

    // Remaining depths.
    for (; d < MERKLE_DEPTH; ++d) {
        auth_path[d] = filler.Next(d);
    }
}

bool ShieldedMerkleWitness::Verify(const uint256& leaf, const uint256& root) const
{
    std::array<uint256, MERKLE_DEPTH> auth_path;
    uint64_t pos;
    ComputePath(auth_path, pos);

    uint256 current = leaf;
    for (size_t d = 0; d < MERKLE_DEPTH; ++d) {
        if (pos & 1) {
            current = BranchHash(auth_path[d], current);
        } else {
            current = BranchHash(current, auth_path[d]);
        }
        pos >>= 1;
    }
    return current == root;
}

// -----------------------------------------------------------------------
// NextDepth -- determine the depth of the next subtree that will complete
// when a new leaf is appended.
//
// This mirrors Zcash's approach: the number of trailing 1-bits in
// (tree_.Size() + filled_.size()) gives us the depth.  But more precisely,
// the depth is determined by how many of the "unfilled uncle" positions
// have been filled so far.
//
// In the Zcash design the next depth is computed as follows:
//   Let skip = number of filled entries so far.
//   Walk the witness-position bits from LSB upward.
//   At each depth where the position bit is 0 (meaning we are left child
//   and need a right sibling), if skip > 0, decrement skip and continue.
//   Otherwise, the current depth is the "next depth".
// -----------------------------------------------------------------------

size_t ShieldedMerkleWitness::NextDepth(size_t skip) const
{
    // Mirror Zcash's next_depth: walk the snapshot tree's frontier slots.
    // Each empty (nullopt) slot is a position where the witness needs a
    // right-sibling uncle hash.  We skip past `skip` such positions
    // (already in filled_) and return the depth of the next one.

    if (!tree_.Left()) {
        if (skip) {
            --skip;
        } else {
            return 0;
        }
    }

    if (!tree_.Right()) {
        if (skip) {
            --skip;
        } else {
            return 0;
        }
    }

    size_t d = 1;
    for (const auto& parent : tree_.Parents()) {
        if (!parent) {
            if (skip) {
                --skip;
            } else {
                return d;
            }
        }
        ++d;
    }

    return d + skip;
}

void ShieldedMerkleWitness::IncrementalUpdate(const uint256& new_leaf)
{
    // Determine the depth of the subtree that this new leaf will contribute
    // to (from the witness's perspective).
    size_t depth = NextDepth(filled_.size());

    if (cursor_.has_value()) {
        // We are in the middle of building a subtree of size 2^cursor_depth_.
        // Append the new leaf to the cursor.
        cursor_->Append(new_leaf);

        // Check if the cursor subtree is now complete.
        // A subtree of depth d is complete when it has 2^d leaves.
        if (cursor_->Size() == (static_cast<uint64_t>(1) << cursor_depth_)) {
            // Promote the completed cursor root to the filled list.
            filled_.push_back(cursor_->Root(cursor_depth_, PathFiller()));
            cursor_ = std::nullopt;
            cursor_depth_ = 0;
        }
    } else {
        // No cursor active.
        if (depth == 0) {
            // The uncle is a single leaf -- just record it directly.
            filled_.push_back(new_leaf);
        } else {
            // Start a new cursor subtree at the required depth.
            cursor_ = ShieldedMerkleTree(tree_.GetIndexStorageMode());
            cursor_depth_ = depth;
            cursor_->Append(new_leaf);
        }
    }
}

} // namespace shielded
