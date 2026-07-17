// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_PROOF_STORE_H
#define BTX_MATMUL_MATMUL_PROOF_STORE_H

#include <sync.h>
#include <uint256.h>
#include <util/fs.h>

#include <cstddef>
#include <map>
#include <memory>
#include <set>
#include <vector>

class CDBWrapper;

// ---------------------------------------------------------------------------
// LOCAL MatMul segregated-proof store (solver-evolution Stage 2a/2b/2c; §3).
//
// At segregated-proof heights (GetMatMulProfileParams(height).proof_segregated)
// the ~32 MiB ENC-BMX4C-D sketch is NO LONGER carried in the block body. The
// block commits ONLY the 32-byte header field matmul_digest = H(sigma || Chat);
// the sketch travels out-of-band and is bound back to the block by that digest
// (design §3.1/§3.3). Stage 2b relays it over a getmatmulproof/matmulproof P2P
// exchange; Stage 2c (this file) adds DISK PERSISTENCE, the ARCHIVE-node role,
// and the rolling PRUNE window.
//
//   * the miner PUTS the solved sketch here keyed by the block hash, then emits
//     a block whose body sketch is empty (rpc/mining.cpp GenerateBlock);
//   * validation GETS it here to run the §3.3 binding + Freivalds cascade
//     (pow.cpp CheckMatMulV4SegregatedProof, called from ContextualCheckBlock);
//   * net_processing POPULATES it from peers and SERVES it to peers.
//
// The key is the block hash, which is the HEADER hash (uint256, header-only, so
// it is independent of the body / the presence of the sketch — clearing the
// inline sketch does not move the key). The value is the RAW serialized sketch
// bytes (exactly 8*m^2 bytes for a well-formed proof), i.e. the flat byte buffer
// matmul::v4::VerifySketch / ComputeSketchDigest operate on — NOT the word-packed
// matrix_c_data form.
//
// STORAGE MODES (Stage 2c):
//   * MEMORY mode (default, no OpenDiskBacking call): proofs live in an in-RAM
//     map. This is what the unit tests and the single-process regtest path use.
//   * DISK mode (OpenDiskBacking): proofs live in a leveldb table under the
//     datadir (proofs/), keyed by block hash, re-loaded on startup. RESIDENT RAM
//     holds only the KEY INDEX (32 bytes/proof), never the 32 MiB blobs, so
//     resident storage is bounded even on an archive node. Get() reads the blob
//     from disk on demand.
//
// The Put / Get / Have / Erase interface is byte-identical across modes and
// UNCHANGED from Stage 2a/2b, so validation and net_processing are untouched by
// the disk backing.
// ---------------------------------------------------------------------------

namespace matmul {

class MatMulProofStore
{
public:
    MatMulProofStore();
    ~MatMulProofStore();

    //! Open (or create) the on-disk leveldb backing at `dir`/proofs and load the
    //! resident key index from it. When `archive` is true the store retains ALL
    //! proofs (PruneToDepth is a no-op); otherwise it keeps only the rolling
    //! window (design §3.5). Idempotent replace of any prior backing. Must be
    //! called before the first Put on a node that wants persistence; the unit /
    //! single-process paths never call it and stay in MEMORY mode.
    void OpenDiskBacking(const fs::path& dir, size_t cache_bytes, bool archive, bool wipe);

    //! Close the on-disk backing (shutdown / teardown). Reverts to MEMORY mode
    //! and drops the resident key index. Does NOT delete the on-disk data.
    void CloseDiskBacking();

    //! True iff this node retains all proofs (an archive node — never prunes).
    [[nodiscard]] bool IsArchive() const;

    //! True iff a persistent (disk) backing is open.
    [[nodiscard]] bool IsDiskBacked() const;

    //! Store (or overwrite) the raw sketch bytes for `block_hash`.
    void Put(const uint256& block_hash, std::vector<unsigned char> sketch_bytes);

    //! Fetch the raw sketch bytes for `block_hash`. Returns false (leaving `out`
    //! untouched) when no proof is held — this is the PoW-INCOMPLETE state, a
    //! non-permanent "we don't have the proof yet", NOT a consensus failure.
    [[nodiscard]] bool Get(const uint256& block_hash, std::vector<unsigned char>& out) const;

    //! True iff a proof is held for `block_hash`.
    [[nodiscard]] bool Have(const uint256& block_hash) const;

    //! Drop the proof for `block_hash` (no-op if absent).
    void Erase(const uint256& block_hash);

    //! Durably flush every prior (fSync=false) Put/Erase to disk in ONE fsync.
    //! No-op in MEMORY mode. Called from FlushStateToDisk so a connected
    //! segregated block's proof reaches disk together with the chainstate that
    //! depends on it (durability parity) -- closing the crash window where the
    //! block body is persisted but its ~32 MiB proof is not. The hot Put path
    //! stays fSync=false (proofs are re-fetchable, never corruption); this is
    //! one fsync per flush checkpoint, not per proof.
    void Sync();

    //! Number of proofs currently resident (diagnostics/tests).
    [[nodiscard]] size_t Size() const;

    //! Drop every held proof (tests/teardown). Clears disk backing too if open.
    void Clear();

    //! Snapshot of every held proof's block hash (Stage 2c prune sweep driver).
    [[nodiscard]] std::vector<uint256> Keys() const;

private:
    mutable Mutex m_mutex;
    //! MEMORY-mode blobs (empty in DISK mode).
    std::map<uint256, std::vector<unsigned char>> m_mem GUARDED_BY(m_mutex);
    //! Resident key index — present in BOTH modes, so Have()/Size()/Keys() and the
    //! prune sweep never touch disk. In DISK mode this is the ONLY resident copy;
    //! the 32 MiB blobs stay on disk.
    std::set<uint256> m_keys GUARDED_BY(m_mutex);
    //! On-disk leveldb backing (null in MEMORY mode).
    std::unique_ptr<CDBWrapper> m_db GUARDED_BY(m_mutex);
    bool m_archive GUARDED_BY(m_mutex){false};
};

//! The single process-wide proof store.
MatMulProofStore& GetLocalMatMulProofStore();

// --- Free-function convenience wrappers over the process-local store ---------

void PutMatMulProof(const uint256& block_hash, std::vector<unsigned char> sketch_bytes);
[[nodiscard]] bool GetMatMulProof(const uint256& block_hash, std::vector<unsigned char>& out);
[[nodiscard]] bool HaveMatMulProof(const uint256& block_hash);

} // namespace matmul

#endif // BTX_MATMUL_MATMUL_PROOF_STORE_H
