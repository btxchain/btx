// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_PROOF_STORE_H
#define BTX_MATMUL_MATMUL_PROOF_STORE_H

#include <sync.h>
#include <uint256.h>

#include <cstddef>
#include <map>
#include <vector>

// ---------------------------------------------------------------------------
// LOCAL MatMul segregated-proof store (solver-evolution Stage 2a; design §3).
//
// At segregated-proof heights (GetMatMulProfileParams(height).proof_segregated)
// the ~32 MiB ENC-BMX4C-D sketch is NO LONGER carried in the block body. The
// block commits ONLY the 32-byte header field matmul_digest = H(sigma || Chat);
// the sketch travels out-of-band and is bound back to the block by that digest
// (design §3.1/§3.3). Stage 2b will relay it over a getmatmulproof/matmulproof
// P2P exchange; Stage 2c will prune/archive it.
//
// This Stage-2a store is the PROCESS-LOCAL stand-in for that relay so the whole
// segregated path is end-to-end testable on a SINGLE node (miner + validator in
// one process):
//   * the miner PUTS the solved sketch here keyed by the block hash, then emits
//     a block whose body sketch is empty (rpc/mining.cpp GenerateBlock);
//   * validation GETS it here to run the §3.3 binding + Freivalds cascade
//     (pow.cpp CheckMatMulV4SegregatedProof, called from ContextualCheckBlock).
//
// The key is the block hash, which is the HEADER hash (uint256, header-only, so
// it is independent of the body / the presence of the sketch — clearing the
// inline sketch does not move the key). The value is the RAW serialized sketch
// bytes (exactly 8*m^2 bytes for a well-formed proof), i.e. the flat byte buffer
// matmul::v4::VerifySketch / ComputeSketchDigest operate on — NOT the word-packed
// matrix_c_data form.
//
// The interface (Put / Get / Have / Erase) is deliberately the SAME surface a
// network-populated store would expose to validation, so Stage 2b can swap the
// population source (miner -> peer relay) without touching the validator: the
// validator only ever Get/Have-s.
// ---------------------------------------------------------------------------

namespace matmul {

class MatMulProofStore
{
public:
    //! Store (or overwrite) the raw sketch bytes for `block_hash`.
    void Put(const uint256& block_hash, std::vector<unsigned char> sketch_bytes);

    //! Fetch the raw sketch bytes for `block_hash`. Returns false (leaving `out`
    //! untouched) when no proof is held — this is the PoW-INCOMPLETE state, a
    //! non-permanent "we don't have the proof yet", NOT a consensus failure.
    [[nodiscard]] bool Get(const uint256& block_hash, std::vector<unsigned char>& out) const;

    //! True iff a proof is held for `block_hash`.
    [[nodiscard]] bool Have(const uint256& block_hash) const;

    //! Drop the proof for `block_hash` (no-op if absent). Stage 2c (prune) will
    //! drive this from the rolling depth; here it is exposed for tests/teardown.
    void Erase(const uint256& block_hash);

    //! Number of proofs currently resident (diagnostics/tests).
    [[nodiscard]] size_t Size() const;

    //! Drop every held proof (tests/teardown).
    void Clear();

private:
    mutable Mutex m_mutex;
    std::map<uint256, std::vector<unsigned char>> m_proofs GUARDED_BY(m_mutex);
};

//! The single process-local proof store. Stage 2b replaces the population path
//! (miner -> network) but keeps this accessor for the validator.
MatMulProofStore& GetLocalMatMulProofStore();

// --- Free-function convenience wrappers over the process-local store ---------
// (These are the names the design/Stage-2a task references directly.)

void PutMatMulProof(const uint256& block_hash, std::vector<unsigned char> sketch_bytes);
[[nodiscard]] bool GetMatMulProof(const uint256& block_hash, std::vector<unsigned char>& out);
[[nodiscard]] bool HaveMatMulProof(const uint256& block_hash);

} // namespace matmul

#endif // BTX_MATMUL_MATMUL_PROOF_STORE_H
