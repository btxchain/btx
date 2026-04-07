// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_MERKLE_TREE_H
#define BTX_SHIELDED_MERKLE_TREE_H

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <vector>

#include <crypto/sha256.h>
#include <serialize.h>
#include <uint256.h>
#include <util/fs.h>

namespace shielded {

/** Tree depth -- supports up to 2^MERKLE_DEPTH leaves. */
static constexpr size_t MERKLE_DEPTH = 32;

/** Maximum number of leaves: 2^32. */
static constexpr uint64_t MERKLE_MAX_LEAVES = static_cast<uint64_t>(1) << MERKLE_DEPTH;

// ---------------------------------------------------------------------------
// Domain-separated hash primitives
// ---------------------------------------------------------------------------

/** SHA256("BTX_Shielded_Empty_Leaf_V1") -- the hash of an unfilled leaf. */
uint256 EmptyLeafHash();

/** SHA256("BTX_Shielded_Branch_V1" || left || right) -- domain-separated internal node hash. */
uint256 BranchHash(const uint256& left, const uint256& right);

/**
 * Precomputed empty-subtree root at the given depth (0 = leaf level).
 *
 *   EmptyRoot(0) = EmptyLeafHash()
 *   EmptyRoot(d) = BranchHash(EmptyRoot(d-1), EmptyRoot(d-1))
 *
 * Cached in a static table on first access.
 */
const uint256& EmptyRoot(size_t depth);

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
class ShieldedMerkleTree;
class ShieldedMerkleWitness;

// ---------------------------------------------------------------------------
// PathFiller -- internal helper consumed by Root(), Witness(), and
// witness partial_path().
// ---------------------------------------------------------------------------

/**
 * Supplies hashes for positions that have not yet been filled.
 * Consumes a deque of precomputed hashes left-to-right; once exhausted
 * returns EmptyRoot(depth).
 */
class PathFiller
{
public:
    PathFiller() = default;
    explicit PathFiller(std::deque<uint256> hashes) : queue_(std::move(hashes)) {}

    uint256 Next(size_t depth)
    {
        if (!queue_.empty()) {
            uint256 h = queue_.front();
            queue_.pop_front();
            return h;
        }
        return EmptyRoot(depth);
    }

private:
    std::deque<uint256> queue_;
};

// ---------------------------------------------------------------------------
// ShieldedMerkleTree -- incremental Merkle commitment tree (frontier-based)
// ---------------------------------------------------------------------------

/**
 * An append-only incremental Merkle tree that stores only the *frontier* --
 * the minimal set of intermediate hashes needed to compute the root and to
 * append the next leaf.  Memory usage is O(depth) regardless of tree size.
 *
 * Design reference: Zcash's IncrementalMerkleTree (ZIP 32 / Sapling spec),
 * adapted to use SHA-256 with domain separation for post-quantum security.
 *
 * Internal representation:
 *
 *   left_     : most-recently completed left child at the leaf level.
 *   right_    : most-recently completed right child at the leaf level.
 *   parents_[i] : collapsed left child at depth (i+1).
 *
 * Append() is NOT thread-safe.  Root() is a pure computation on immutable
 * frontier data and is safe to call concurrently on a snapshot.
 */
class ShieldedMerkleTree
{
public:
    enum class IndexStorageMode : uint8_t {
        AUTO = 0,
        MEMORY_ONLY = 1,
    };

    explicit ShieldedMerkleTree(IndexStorageMode mode = IndexStorageMode::AUTO);

    /**
     * Configure a persistent LevelDB-backed commitment index with bounded LRU
     * cache. Must be called before creating trees that should use persistent
     * position lookups.
     */
    static bool ConfigureCommitmentIndexStore(const fs::path& db_path,
                                              size_t db_cache_bytes = 8 << 20,
                                              size_t lru_capacity = 262144,
                                              bool memory_only = false,
                                              bool wipe_data = false);

    /** Disable and release the shared commitment index store. */
    static void ResetCommitmentIndexStore();

    /**
     * Append a note commitment as the next leaf.
     * @throws std::runtime_error if the tree has reached 2^MERKLE_DEPTH leaves.
     * Complexity: O(depth) SHA-256 worst-case, O(1) amortized.
     */
    void Append(const uint256& commitment);

    /**
     * Compute the current Merkle root from the frontier.
     * Returns EmptyRoot(MERKLE_DEPTH) for an empty tree.
     * Complexity: O(depth) SHA-256.
     */
    uint256 Root() const;

    /** Compute root using the given filler for missing positions. */
    uint256 Root(size_t depth, PathFiller filler) const;

    /** Number of leaves appended. */
    uint64_t Size() const { return size_; }

    /** True if no leaves have been appended. */
    bool IsEmpty() const { return size_ == 0; }

    /**
     * Produce a witness (authentication path) for the most recently appended
     * leaf.  The witness can later be updated incrementally.
     * @throws std::runtime_error if the tree is empty.
     */
    ShieldedMerkleWitness Witness() const;

    /**
     * Return the most recently appended leaf hash.
     * @throws std::runtime_error if the tree is empty.
     */
    uint256 LastLeaf() const;

    /**
     * Lookup a leaf commitment by absolute position (0-based).
     * Returns std::nullopt when position is out of range or no index is available.
     */
    [[nodiscard]] std::optional<uint256> CommitmentAt(uint64_t position) const;

    /**
     * Compute a stable digest over the commitment-position index contents.
     * Returns std::nullopt when the tree cannot read every indexed commitment.
     */
    [[nodiscard]] std::optional<uint256> CommitmentIndexDigest() const;

    /** True when position lookups are available for all appended commitments. */
    [[nodiscard]] bool HasCommitmentIndex() const;

    /**
     * Truncate the tree to @p new_size leaves.
     * Requires a commitment index (LevelDB-backed or in-memory fallback).
     * Returns false if new_size > Size() or if truncation cannot be performed.
     */
    [[nodiscard]] bool Truncate(uint64_t new_size);

    /**
     * Remove the most recent @p count leaves.
     * Equivalent to Truncate(Size() - count).
     */
    [[nodiscard]] bool RemoveLast(uint64_t count);

    [[nodiscard]] IndexStorageMode GetIndexStorageMode() const { return m_index_storage_mode_; }

    // --- Accessors for witness internals ------------------------------------
    const std::optional<uint256>& Left() const { return left_; }
    const std::optional<uint256>& Right() const { return right_; }
    const std::vector<std::optional<uint256>>& Parents() const { return parents_; }

    // --- Serialization -------------------------------------------------------
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, size_);
        SerializeOptHash(s, left_);
        SerializeOptHash(s, right_);
        uint64_t pc = parents_.size();
        ::Serialize(s, COMPACTSIZE(pc));
        for (const auto& p : parents_) {
            SerializeOptHash(s, p);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, size_);
        if (size_ > MERKLE_MAX_LEAVES) {
            throw std::ios_base::failure("ShieldedMerkleTree: size overflow");
        }
        left_ = DeserializeOptHash(s);
        right_ = DeserializeOptHash(s);
        uint64_t pc{0};
        ::Unserialize(s, COMPACTSIZE(pc));
        if (pc > MERKLE_DEPTH) {
            throw std::ios_base::failure("ShieldedMerkleTree: parent_count > MERKLE_DEPTH");
        }
        parents_.resize(pc);
        for (auto& p : parents_) {
            p = DeserializeOptHash(s);
        }

        commitment_index_store_.reset();
        if (m_index_storage_mode_ != IndexStorageMode::MEMORY_ONLY) {
            std::lock_guard<std::mutex> lock(s_commitment_store_mutex);
            commitment_index_store_ = s_commitment_store;
        }

        // Serialized tree frontiers do not embed the leaf-position index.
        // Reattach the shared persistent index when one is configured; otherwise
        // preserve the legacy behavior and disable lookups for non-empty trees.
        if (size_ == 0) {
            commitment_index_enabled_ = true;
            if (commitment_index_store_) {
                commitment_index_mem_.reset();
            } else {
                commitment_index_mem_ = std::make_shared<std::vector<uint256>>();
            }
        } else if (commitment_index_store_) {
            commitment_index_enabled_ = true;
            commitment_index_mem_.reset();
        } else {
            commitment_index_enabled_ = false;
            commitment_index_mem_.reset();
        }
        frontier_checkpoints_ = std::make_shared<std::vector<FrontierCheckpoint>>();
    }

private:
    struct CommitmentIndexStore;
    static std::mutex s_commitment_store_mutex;
    static std::shared_ptr<CommitmentIndexStore> s_commitment_store;

    struct FrontierCheckpoint {
        uint64_t size{0};
        std::optional<uint256> left;
        std::optional<uint256> right;
        std::vector<std::optional<uint256>> parents;
    };

    static constexpr uint64_t FRONTIER_CHECKPOINT_INTERVAL{1024};

    uint64_t size_{0};
    std::optional<uint256> left_;
    std::optional<uint256> right_;
    std::vector<std::optional<uint256>> parents_;

    template <typename Stream>
    static void SerializeOptHash(Stream& s, const std::optional<uint256>& opt)
    {
        uint8_t f = opt.has_value() ? 1 : 0;
        ::Serialize(s, f);
        if (f) ::Serialize(s, *opt);
    }

    template <typename Stream>
    static std::optional<uint256> DeserializeOptHash(Stream& s)
    {
        uint8_t f{0};
        ::Unserialize(s, f);
        if (f) {
            uint256 v;
            ::Unserialize(s, v);
            return v;
        }
        return std::nullopt;
    }

    void EnsureCommitmentIndexWritable();
    void EnsureCheckpointsWritable();
    void MaybeRecordFrontierCheckpoint();
    [[nodiscard]] std::optional<uint256> ReadCommitmentAt(uint64_t position) const;
    [[nodiscard]] bool WriteCommitmentAt(uint64_t position, const uint256& commitment);
    [[nodiscard]] bool HasCommitmentAt(uint64_t position) const;

    // Position index used for ring-member lookup. The in-memory vector is a
    // fallback for tests/unconfigured nodes; production nodes should configure
    // the shared LevelDB-backed store.
    std::shared_ptr<std::vector<uint256>> commitment_index_mem_{std::make_shared<std::vector<uint256>>()};
    std::shared_ptr<CommitmentIndexStore> commitment_index_store_;
    bool commitment_index_enabled_{true};
    IndexStorageMode m_index_storage_mode_{IndexStorageMode::AUTO};
    std::shared_ptr<std::vector<FrontierCheckpoint>> frontier_checkpoints_{std::make_shared<std::vector<FrontierCheckpoint>>()};
};

// ---------------------------------------------------------------------------
// ShieldedMerkleWitness -- authentication path + incremental update
// ---------------------------------------------------------------------------

/**
 * A witness proving inclusion of a specific leaf in a ShieldedMerkleTree.
 *
 * Internally the witness stores:
 *   - tree_       : snapshot of the tree at the time the witness was created.
 *   - filled_     : hashes of completed subtrees appended after creation.
 *   - cursor_     : partial subtree currently being filled.
 *   - cursor_depth_ : depth of the cursor subtree.
 *
 * This mirrors the Zcash IncrementalWitness design, which allows O(depth)
 * incremental updates per appended leaf without recomputing from scratch.
 *
 * The external interface exposes:
 *   - path/position  for verification (computed on demand).
 *   - Verify()       to check inclusion against a root.
 *   - IncrementalUpdate() to absorb a newly appended leaf.
 */
class ShieldedMerkleWitness
{
public:
    ShieldedMerkleWitness() = default;

    /** Construct from a tree snapshot (taken at the time the note was committed). */
    explicit ShieldedMerkleWitness(const ShieldedMerkleTree& tree);

    /** Leaf position (0-based index). */
    uint64_t Position() const;

    /**
     * Compute the authentication path (array of 32 sibling hashes,
     * from leaf level to root level) and the leaf position.
     */
    void ComputePath(std::array<uint256, MERKLE_DEPTH>& auth_path, uint64_t& pos) const;

    /**
     * Compute the current root as seen by this witness (should match the
     * tree root at the time of the most recent IncrementalUpdate).
     */
    uint256 Root() const;

    /**
     * Verify that @p leaf at the witness position hashes to @p root via
     * the authentication path.
     */
    bool Verify(const uint256& leaf, const uint256& root) const;

    /**
     * Absorb a newly appended leaf into this witness.  Must be called
     * once per Append() in order, after each append.
     */
    void IncrementalUpdate(const uint256& new_leaf);

    // --- Serialization -------------------------------------------------------
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, tree_);
        // filled_
        uint64_t fc = filled_.size();
        ::Serialize(s, COMPACTSIZE(fc));
        for (const auto& h : filled_) {
            ::Serialize(s, h);
        }
        // cursor
        uint8_t has_cursor = cursor_.has_value() ? 1 : 0;
        ::Serialize(s, has_cursor);
        if (has_cursor) {
            ::Serialize(s, *cursor_);
            uint64_t cd = cursor_depth_;
            ::Serialize(s, COMPACTSIZE(cd));
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, tree_);
        uint64_t fc{0};
        ::Unserialize(s, COMPACTSIZE(fc));
        if (fc > MERKLE_DEPTH) {
            throw std::ios_base::failure("ShieldedMerkleWitness: filled count overflow");
        }
        filled_.resize(fc);
        for (auto& h : filled_) {
            ::Unserialize(s, h);
        }
        uint8_t has_cursor{0};
        ::Unserialize(s, has_cursor);
        if (has_cursor > 1) {
            throw std::ios_base::failure("ShieldedMerkleWitness: invalid cursor flag");
        }
        if (has_cursor) {
            cursor_.emplace();
            ::Unserialize(s, *cursor_);
            uint64_t cd{0};
            ::Unserialize(s, COMPACTSIZE(cd));
            if (cd > MERKLE_DEPTH) {
                throw std::ios_base::failure("ShieldedMerkleWitness: cursor depth overflow");
            }
            cursor_depth_ = static_cast<size_t>(cd);
        } else {
            cursor_ = std::nullopt;
            cursor_depth_ = 0;
        }
    }

private:
    /** Snapshot of the tree at the time the witnessed leaf was appended. */
    ShieldedMerkleTree tree_;

    /** Completed subtree hashes accumulated since the snapshot. */
    std::vector<uint256> filled_;

    /** Partial subtree currently being built. */
    std::optional<ShieldedMerkleTree> cursor_;

    /** Depth of the cursor subtree (0 = full tree, but in practice small). */
    size_t cursor_depth_{0};

    /**
     * Return the partial path (deque of hashes from filled_ + cursor)
     * that acts as filler when computing root or authentication path
     * from the snapshot tree.
     */
    std::deque<uint256> PartialPath() const;

    /**
     * Compute the next depth at which a new completed subtree will be needed
     * based on the current number of filled subtrees and the snapshot tree.
     */
    size_t NextDepth(size_t skip) const;
};

} // namespace shielded

#endif // BTX_SHIELDED_MERKLE_TREE_H
