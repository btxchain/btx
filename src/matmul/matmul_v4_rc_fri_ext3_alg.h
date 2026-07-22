// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_H
#define BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_H

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_fri.h> // FriNextPow2 / shared numeric caps
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ALGEBRAIC-HASH batched FRI over Fp3 — the RECURSION-side Merkle substrate
// (Stage-C spec §2, scratchpad/stage-c-buildable-spec.md). Same polynomial
// mathematics as the batched FRI in matmul_v4_rc_fri_ext3.{h,cpp} (LDE,
// degree-shift RLC, dual-OOD DEEP, v5 half-domain fold, terminal B-constant
// layer, FS replay) with EXACTLY the hash-touching surface swapped:
//
//   Fri3LeafHash / Fri3NodeHash (SHA256d, uint256 digests)
//     → alg_hash::LeafHash / alg_hash::LeafHashRow / alg_hash::Compress
//       (Poseidon2-Goldilocks, digests = 4 Fp lanes) — so every Merkle node
//       is a low-degree algebraic map over GF(p), arithmetizable in V_CS.
//
// APPROACH (spec §2.1 option (b), chosen deliberately): a PARALLEL file. The
// fold/DEEP/NTT helpers of matmul_v4_rc_fri_ext3.cpp live in an anonymous
// namespace (internal linkage), so approach (a) — a MerkleHashPolicy template
// — would have required restructuring the frozen SHA256d consensus file.
// Option (b) keeps matmul_v4_rc_fri_ext3.{h,cpp} byte-for-byte untouched
// (base / non-recursive proofs still use it verbatim); this file re-instates
// the field-arithmetic scaffolding verbatim in its own anonymous namespace and
// swaps only the digest type and the four hash entry points. The spec itself
// recommends (b) for the first cut (isolation; migrate to (a) later).
//
// DIGEST REPRESENTATION: nodes and leaves are std::array<Fp,4>
// (alg_hash::Digest) EVERYWHERE — in the tree, in the proof structs, and in
// the fold-step sibling lists. Conversion to uint256 happens ONLY at the two
// byte boundaries (the SHA256d Fiat–Shamir transcript and proof
// serialization) via the canonical little-endian-limb packing
//   uint256 bytes [8k, 8k+8) = LE64(Canonical(limb_k)),  k = 0..3,
// implemented by Fri3AlgDigestToUint256 / Fri3AlgDigestFromUint256 below.
// Unpacking REJECTS any limb ≥ p, so the packing is a bijection between
// canonical digests and its image (round-trip pinned by unit test).
//
// ROW-WISE BATCH COMMITMENT (spec §2.3, REQUIRED for the recursion cell
// budget): unlike Fri3BatchCommit (one Merkle tree PER column), this path
// commits ONE tree whose leaf i is alg_hash::LeafHashRow over ALL W column
// values at LDE row i (variable-length sponge over 3W+1 Fp lanes). A query
// therefore opens ONE authentication path carrying the whole row, not W
// paths. The RLC composition U, the per-column degree-shift bounds and the
// dual-OOD claims evals_z1/evals_z2 are UNCHANGED — only the Merkle layout
// differs. The SHA base FRI keeps its per-column layout.
//
// FIAT–SHAMIR stays SHA256d-based (spec §2.2): challenge derivation is NOT
// arithmetized in V_CS (the recursive verifier recomputes challenges
// natively), so only the Merkle commitment must be field-native. Distinct
// domain tag ⇒ no transcript collision with the SHA batch path.
//
// ============================================================================
// SOUNDNESS PARAMETERS (recursion path; spec §5.2 — code and statement MUST
// agree). This path ships Q = 148 (NOT the SHA path's 128), g = 40, blowup 16:
//   148·log2(32/17) − 40 = 135.11 − 40 = 95.11 ≥ 92 (per-node recursion
//   target incl. the 2^28-node union; margin +3.1 bits).
// The shared cap kRCFriMaxQueriesHard = 128 (matmul_v4_rc_fri.h:82) belongs to
// the SHA paths and is DELIBERATELY not edited; this path carries its own
// kRCFri3AlgNumQueries = 148 and kRCFri3AlgMaxQueriesHard, statically checked
// below. All other numeric parameters (blowup, grinding, fold caps, LDE
// guard) are shared unchanged from matmul_v4_rc_fri.h.
// ============================================================================

namespace matmul::v4::rc {

using gkr_field::Fp;
using gkr_field::Fp3;

/** Field-native Merkle digest: 4 Goldilocks lanes (alg_hash::Digest). */
using Fri3AlgDigest = alg_hash::Digest;

inline constexpr uint32_t kRCFri3AlgBatchProofMagic = 0x33414246u; // 'FBA3'
inline constexpr uint32_t kRCFri3AlgBatchProofVersion = 1;
inline constexpr char kRCFri3AlgBatchDomainTag[] = "BTX_RC_FRIB3ALG_V1";

/** Recursion-path query count (spec §5.2): Q = 148 ≥ ceil((92+40)/0.912928). */
inline constexpr uint32_t kRCFri3AlgNumQueries = 148;
/** Path-local hard cap (DoS bound for deserialization/verify) — the shared
 *  kRCFriMaxQueriesHard = 128 is a SHA-path cap and stays untouched. */
inline constexpr uint32_t kRCFri3AlgMaxQueriesHard = 256;
/** Per-node soundness target for the 2^28-node recursion union (spec §5). */
inline constexpr int kRCFri3AlgTargetSoundnessBits = 92;

static_assert(kRCFri3AlgNumQueries == 148, "recursion FRI ships Q=148 (spec §5.2)");
static_assert(kRCFriGrindingBits == 40, "recursion FRI ships g=40 (spec §5.2)");
static_assert(kRCFriBlowup == 16, "recursion FRI ships blowup=16 (spec §5.2)");
static_assert(kRCFri3AlgMaxQueriesHard >= kRCFri3AlgNumQueries,
              "path-local hard cap must admit Q=148");

[[nodiscard]] inline int Fri3AlgSoundnessBoundBits()
{
    // Query proximity term is FIELD-INDEPENDENT: floor(Q·log2(32/17)) − g.
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull; // log2(32/17) in Q32
    const uint64_t prod = static_cast<uint64_t>(kRCFri3AlgNumQueries) * kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32) - static_cast<int>(kRCFriGrindingBits);
}

inline constexpr char kRCFri3AlgBatchSoundnessStatement[] =
    "BATCHED FRI (Fp3 substrate, v5 fold, ALGEBRAIC Poseidon2-Goldilocks "
    "Merkle, ROW-WISE layout): ONE instance over ALL committed columns; ONE "
    "row tree (leaf i = LeafHashRow of all W column values at row i) => one "
    "opening path per query. Q=148, blowup=16, g=40, Fp3 (|F|=p^3~2^192), "
    "UNIQUE-DECODING alpha=17/32 => Fri3AlgSoundnessBoundBits()=95 (real "
    "95.11, >= 92 per-node recursion target incl. 2^28-node union). v5 "
    "half-domain fold × log2(n_coeffs) → terminal B-constant layer. DUAL-OOD "
    "DEEP (z1,z2) with extension part (c1,c2)!=(0,0); degree-shift RLC "
    "enforces per-column maximal degree — both unchanged from the SHA batch "
    "path. FS transcript SHA256d (not arithmetized); Merkle field-native. "
    "Collision resistance of the 4-lane capacity sponge: 2^-128 floor. "
    "COMPUTATIONAL — not eps=0.";

/**
 * Canonical 4×Fp ⇆ uint256 packing: byte [8k, 8k+8) = LE64(Canonical(d[k])).
 * Used ONLY at the FS-transcript and serialization boundaries.
 */
[[nodiscard]] uint256 Fri3AlgDigestToUint256(const Fri3AlgDigest& d);

/** Inverse packing; rejects (nullopt) any limb ≥ p — non-canonical encodings
 *  are invalid, so the packing is a bijection onto its image. */
[[nodiscard]] std::optional<Fri3AlgDigest> Fri3AlgDigestFromUint256(const uint256& u);

/** Layer commitment with a field-native root (FriLayerCommit analogue). */
struct Fri3AlgLayerCommit {
    Fri3AlgDigest root{};
    uint32_t n_leaves{0};
};

/** Fold-step opening (Fri3FoldStep with Fp^4 sibling digests). */
struct Fri3AlgFoldStep {
    /** Pair indices on domain size N: even_index = i, odd_index = i + N/2. */
    uint32_t even_index{0};
    uint32_t odd_index{0};
    Fp3 even{}; // f(x) at i
    Fp3 odd{};  // f(-x) at i+N/2
    std::vector<Fri3AlgDigest> even_siblings;
    std::vector<Fri3AlgDigest> odd_siblings;
};

/** Row opening at one query index: ALL W column values + ONE path (§2.3). */
struct Fri3AlgRowOpening {
    /** values[i] = column i's LDE value at the query index, column order. */
    std::vector<Fp3> values;
    std::vector<Fri3AlgDigest> siblings;
};

struct Fri3AlgBatchQuery {
    uint32_t index{0};
    /** One row opening against row_commit (replaces W per-column openings). */
    Fri3AlgRowOpening row;
    /** Fold-path openings of the DEEP composition G (same math as SHA path). */
    std::vector<Fri3AlgFoldStep> steps;
};

/** Fri3BatchProof analogue (spec §2.4): per-column FriLayerCommit roots →
 *  a SINGLE row-wise commitment; all digests Fp^4; everything else identical
 *  in meaning (lambda, z1, z2, evals_z1/z2, w1, w2, fold layers, final_value,
 *  fold_challenges, pow_grind_nonce, n_coeffs, blowup). */
struct Fri3AlgBatchProof {
    uint32_t version{kRCFri3AlgBatchProofVersion};
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    /** Common padded column length N (power of two); LDE domain = N·blowup. */
    uint32_t n_coeffs{0};
    /** SINGLE row-wise Merkle commitment over the common LDE domain (§2.3). */
    Fri3AlgLayerCommit row_commit{};
    /** Logical (pre-padding) length ℓ_i of each column = enforced degree bound. */
    std::vector<uint32_t> column_len;
    /** FS RLC challenge (recomputed and checked by the verifier). */
    Fp3 lambda{};
    /** Dual OOD points (FS, both ∉ D, z1 ≠ z2). */
    Fp3 z1{};
    Fp3 z2{};
    /** Claimed per-column evaluations at z1/z2 — THE bound opening primitive. */
    std::vector<Fp3> evals_z1;
    std::vector<Fp3> evals_z2;
    /** FS DEEP batching weights (recomputed and checked). */
    Fp3 w1{};
    Fp3 w2{};
    /** Fold-commit layers of the DEEP composition G (field-native roots). */
    std::vector<Fri3AlgLayerCommit> fold_layers;
    Fp3 final_value{};
    std::vector<Fp3> fold_challenges;
    std::vector<Fri3AlgBatchQuery> queries;
};

struct Fri3AlgBatchCommitResult {
    Fri3AlgBatchProof proof;
    /** Per-column LDE over the common domain (prover-side; NEVER shipped). */
    std::vector<std::vector<Fp3>> column_lde;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * Verify one field-native Merkle authentication path: fold leaf_digest up
 * with alg_hash::Compress against siblings. The caller computes leaf_digest
 * (alg_hash::LeafHash for fold layers, alg_hash::LeafHashRow for the row
 * tree) — leaf/node domain separation lives in the capacity seeds Le ≠ D.
 */
[[nodiscard]] bool Fri3AlgVerifyPath(const Fri3AlgDigest& leaf_digest, uint32_t index,
                                     const std::vector<Fri3AlgDigest>& siblings,
                                     const Fri3AlgDigest& root, uint32_t n_leaves);

/**
 * Commit-and-prove: ONE batched FRI instance over all columns, row-wise
 * algebraic Merkle layout. columns[i] = coefficient vector; size = logical
 * length ℓ_i ≥ 1. fs_seed MUST already bind everything the caller committed
 * to — commit-then-challenge.
 */
[[nodiscard]] Fri3AlgBatchCommitResult Fri3AlgBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);

[[nodiscard]] bool Fri3AlgBatchVerify(const Fri3AlgBatchProof& proof, const uint256& fs_seed,
                                      std::string* why = nullptr);

/**
 * Standalone row-root helper (two-epoch discipline; Fri3BatchColumnRoot
 * analogue for the ROW-WISE layout): the Merkle root of the row tree over the
 * common LDE domain of padded size n_coeffs, from the full column set.
 * Limb-identical to proof.row_commit.root produced by Fri3AlgBatchCommit for
 * the same (columns, n_coeffs). Returns the all-zero digest on invalid input.
 * NOTE: a PER-column root has no meaning in the row-wise layout — the row
 * tree is the unit of commitment (spec §2.3).
 */
[[nodiscard]] Fri3AlgDigest Fri3AlgBatchRowRoot(const std::vector<std::vector<Fp3>>& columns,
                                                uint32_t n_coeffs);

/**
 * Forge probe (Fri3ForgeFlippedEvalMustFail analogue): flip ONE LDE eval of
 * column flip_col at LDE index flip_index, recompute ONLY the row root, keep
 * the honest openings; returns true iff Fri3AlgBatchVerify correctly rejects.
 */
[[nodiscard]] bool Fri3AlgForgeFlippedEvalMustFail(const Fri3AlgBatchCommitResult& honest,
                                                   const uint256& fs_seed, uint32_t flip_col,
                                                   uint32_t flip_index,
                                                   std::string* why = nullptr);

[[nodiscard]] size_t SerializeFri3AlgBatchProof(const Fri3AlgBatchProof& proof,
                                                std::vector<unsigned char>& out);
[[nodiscard]] std::optional<Fri3AlgBatchProof> DeserializeFri3AlgBatchProof(
    const std::vector<unsigned char>& in);

[[nodiscard]] inline bool Fri3AlgClaimedBitsMeetTarget()
{
    return Fri3AlgSoundnessBoundBits() >= kRCFri3AlgTargetSoundnessBits &&
           kRCFri3AlgNumQueries == 148u && kRCFriBlowup == 16u &&
           kRCFriGrindingBits == 40u && !kRCFriConjecturedBoundEnabled;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_H
