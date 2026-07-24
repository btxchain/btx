// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_ALG_H
#define BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_ALG_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ============================================================================
// ALGEBRAIC-HASH backend policy for the AIR constraint-quotient module — the
// RECURSION-side instantiation of the `Backend` parameter of
// AirQuotientProve / AirQuotientVerify / AirQuotientProof (spec §2.1/§4.2,
// scratchpad/stage-c-buildable-spec.md: an aggregation proof must have the
// SAME shape as the child proofs it verifies, both over the alg-hash
// proximity module — so the backend is threaded as an explicit policy, not
// inferred from the field type, which cannot distinguish the two Fp3
// substrates).
//
// This header is included ONLY by recursion-side callers (and the
// explicit-instantiation TU); matmul_v4_rc_air_quotient.h deliberately does
// not include it, so the episode/base SHA path never sees the alg module.
//
// SEMANTIC DIFFERENCES vs AirFriBackend<Fp3> (all forced by the ROW-WISE
// commitment layout of Fri3AlgBatch*, matmul_v4_rc_fri_ext3_alg.h §2.3):
//  • kRowWiseLayout = true — the batch commits ONE Poseidon2 row tree whose
//    leaf i is alg_hash::LeafHashRow over ALL column values at LDE row i;
//    there are NO per-column roots in the proof (Fri3AlgBatchProof carries
//    a single row_commit).
//  • ColumnRoot(col, n_coeffs) — the packed (uint256) root of a
//    SINGLE-column row tree (Fri3AlgBatchRowRoot({col}, n_coeffs)). This is
//    a deterministic, binding, per-column FS digest (two-epoch challenge
//    discipline / AirCommittedValuesRoot), but UNLIKE the SHA backend it is
//    NOT byte-identical to anything inside a multi-column batch proof — a
//    per-column root has no meaning in the row-wise layout.
//  • RowRoot(cols, n_coeffs) — the packed row root over a column SET; used
//    by AirQuotientProve as the trace-only commitment R_T that seeds the
//    constraint-batching challenge λ (the quotient depends on λ, so it
//    cannot ride the tree that seeds λ; R_T ships in
//    AirQuotientProof::trace_commit and is bound to the batch by per-query
//    cross-openings — see AirQuotientProof's layout note).
//  • MerklePath is AirAlgRowPath — a whole-ROW opening (values + one
//    sibling path of Fp^4 digests), not a single-value path.
//  • NumQueries() = kRCFri3AlgNumQueries = 148 (recursion soundness
//    parameterization, spec §5.2), not the SHA paths' 128.
// Everything else (BatchCommit/BatchVerify wiring, dual-OOD DEEP members
// z1/z2/evals_z1/evals_z2 consumed by the preprocessed OOD pin, n_coeffs,
// column_len degree bounds) matches AirFriBackend<Fp3> member-for-member in
// meaning.
// ============================================================================

namespace matmul::v4::rc::air_quotient {

/**
 * Row opening / authentication-path record for the row-wise backend (the
 * policy's MerklePath type). For the next-row openings `values` carries the
 * FULL row (all W+1 column values — required to recompute the row leaf);
 * for the trace-binding openings `values` is EMPTY (the leaf is recomputed
 * from the batch query's own opened trace values, which the row-wise batch
 * has already Merkle-verified).
 */
struct AirAlgRowPath {
    uint32_t index{0};
    std::vector<gkr_field::Fp3> values;
    std::vector<Fri3AlgDigest> siblings;
};

template <typename F>
struct AirFriBackendAlg;

template <>
struct AirFriBackendAlg<gkr_field::Fp3> {
    /** Row-wise commitment layout — see the header block for what changes. */
    static constexpr bool kRowWiseLayout = true;

    using BatchProof = Fri3AlgBatchProof;
    using BatchCommitResult = Fri3AlgBatchCommitResult;
    using MerklePath = AirAlgRowPath;
    /** Field-native Merkle digest (4 Goldilocks lanes). */
    using Digest = Fri3AlgDigest;

    static BatchCommitResult BatchCommit(const std::vector<std::vector<gkr_field::Fp3>>& cols,
                                         const uint256& fs_seed)
    {
        return Fri3AlgBatchCommit(cols, fs_seed);
    }
    static bool BatchVerify(const BatchProof& p, const uint256& fs_seed, std::string* why)
    {
        return Fri3AlgBatchVerify(p, fs_seed, why);
    }
    /** SINGLE-column row-tree root, packed — per-column FS digest ONLY (see
     *  the semantic notes above; not present in multi-column batch proofs). */
    static uint256 ColumnRoot(const std::vector<gkr_field::Fp3>& col, uint32_t n_coeffs)
    {
        return Fri3AlgDigestToUint256(Fri3AlgBatchRowRoot({col}, n_coeffs));
    }
    /** Row-tree root over a column SET, packed (the λ-seeding trace
     *  commitment R_T of AirQuotientProve). */
    static uint256 RowRoot(const std::vector<std::vector<gkr_field::Fp3>>& cols,
                           uint32_t n_coeffs)
    {
        return Fri3AlgDigestToUint256(Fri3AlgBatchRowRoot(cols, n_coeffs));
    }
    /** Leaf i of a row tree: LeafHashRow over the row's column values. */
    static Digest RowLeafHash(const std::vector<gkr_field::Fp3>& row, uint32_t index)
    {
        return alg_hash::LeafHashRow(row, index);
    }
    static Digest NodeHash(const Digest& l, const Digest& r) { return alg_hash::Compress(l, r); }
    static bool VerifyRowPath(const Digest& leaf, uint32_t index,
                              const std::vector<Digest>& siblings, const Digest& root,
                              uint32_t n_leaves)
    {
        return Fri3AlgVerifyPath(leaf, index, siblings, root, n_leaves);
    }
    /** Canonical Fp^4 ⇆ uint256 packing for FS/proof boundaries; Unpack
     *  REJECTS non-canonical limbs (nullopt). */
    static uint256 PackDigest(const Digest& d) { return Fri3AlgDigestToUint256(d); }
    static std::optional<Digest> UnpackDigest(const uint256& u)
    {
        return Fri3AlgDigestFromUint256(u);
    }
    static uint32_t NumQueries() { return kRCFri3AlgNumQueries; }
};

} // namespace matmul::v4::rc::air_quotient

#endif // BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_ALG_H
