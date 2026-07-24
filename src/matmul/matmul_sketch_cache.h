// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_SKETCH_CACHE_H
#define BTX_MATMUL_MATMUL_SKETCH_CACHE_H

#include <sync.h>
#include <uint256.h>

#include <cstddef>
#include <deque>
#include <map>
#include <vector>

// ---------------------------------------------------------------------------
// v4.4 ENC-DR UNTRUSTED SKETCH CACHE (doc/btx-matmul-v4.4-tension-resolution.md
// §2.3/§4.3). STRICTLY NON-CONSENSUS, best-effort, in-memory.
//
// Under ENC-DR the block carries ZERO proof bytes: the header's
// matmul_digest = H(sigma || Chat) is the whole commitment, and any node can
// re-derive the 8·m² sketch bytes from the header alone (ComputeSketchOptimal).
// The cache exists only to let a validator run the cheap v4.3 Freivalds
// verifier (~O(n^2)) instead of the full recompute when SOMEONE — the winning
// miner, a peer, or this node's own earlier recompute — already materialized
// the bytes. Every entry is SELF-AUTHENTICATING: one hash
// (H(sigma||bytes) == matmul_digest) proves the bytes are exactly the preimage
// the miner committed, so the cache may be fed by ANY untrusted source and
// dropped by anyone at any time.
//
// Structural properties (what makes this a fraction of the deleted Stage-2
// segregated-proof store, §4.4):
//   * no consensus edge: validation NEVER requires an entry (fallback =
//     recompute); absence can never render a block INCOMPLETE or stall sync;
//   * no durability role: memory-only, bounded FIFO, lost on restart —
//     everything in it is regenerable from headers by anyone;
//   * no archive role, no trust role (never NODE_*-service-bit-advertised).
//
// Populated by: (a) the winning miner's own materialized sketch
// (OffloadMatMulV4SketchToCache), (b) authenticated `mmsketch` P2P deliveries
// (net_processing), (c) this node's own ENC-DR recompute-verify results.
// Served via `getmmsketch` under the net_processing anti-amplification limits.
// ---------------------------------------------------------------------------

namespace matmul {

class MatMulSketchCache
{
public:
    //! Store (or refresh) the raw serialized sketch bytes for `block_hash`.
    //! Evicts the oldest entries beyond the capacity bound (FIFO). A capacity
    //! of 0 disables the cache (Put becomes a no-op).
    void Put(const uint256& block_hash, std::vector<unsigned char> sketch_bytes);

    //! Fetch the raw sketch bytes for `block_hash`. Returns false (leaving
    //! `out` untouched) when absent — the caller falls back to recompute;
    //! absence is NEVER a validation outcome.
    [[nodiscard]] bool Get(const uint256& block_hash, std::vector<unsigned char>& out) const;

    //! True iff an entry is held for `block_hash`.
    [[nodiscard]] bool Have(const uint256& block_hash) const;

    //! Fetch the byte length of the held sketch WITHOUT copying it (sets
    //! `size_out`), or return false if absent. Lets the getmmsketch serve path
    //! apply its anti-amplification gates before the ~8 MiB Get() copy (E.1).
    [[nodiscard]] bool GetSize(const uint256& block_hash, size_t& size_out) const;

    //! Drop the entry for `block_hash` (no-op if absent). Used when an entry
    //! fails the H(sigma||bytes)==matmul_digest authentication (garbage cache).
    void Erase(const uint256& block_hash);

    //! Bound the cache to `max_entries` sketches (~8 MiB each at m = 1024).
    //! 0 disables the cache entirely (existing entries dropped).
    void SetCapacity(size_t max_entries);

    [[nodiscard]] size_t Capacity() const;

    //! Number of entries currently resident (diagnostics/tests).
    [[nodiscard]] size_t Size() const;

    //! Drop every held entry (tests/teardown).
    void Clear();

private:
    mutable Mutex m_mutex;
    std::map<uint256, std::vector<unsigned char>> m_entries GUARDED_BY(m_mutex);
    //! Insertion order for FIFO eviction.
    std::deque<uint256> m_order GUARDED_BY(m_mutex);
    //! Default bound: 8 sketches ≈ 64 MiB at the production m = 1024. Tuned via
    //! -mmsketchcache=<n>.
    size_t m_max_entries GUARDED_BY(m_mutex){8};
};

//! The single process-wide sketch cache.
MatMulSketchCache& GetMatMulSketchCache();

} // namespace matmul

#endif // BTX_MATMUL_MATMUL_SKETCH_CACHE_H
