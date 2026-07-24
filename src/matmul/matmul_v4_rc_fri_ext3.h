// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_H
#define BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_H

#include <matmul/matmul_v4_rc_fri.h> // field-agnostic FriLayerCommit / FriNextPow2 / shared caps
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// REAL FRI PCS over the DEGREE-3 Goldilocks extension Fp3 = Fp[x]/(x^3 − 2)
// (|F| = p^3 ≈ 2^192) — the Fp3 lift of the shipped Fp2 stack in
// matmul_v4_rc_fri.{h,cpp}. Structure-for-structure mirror; the Fp2 path is
// untouched (parallel implementation, distinct domain tags / proof magics).
//
// Pipeline: LDE (blowup) → Merkle commit → DEEP out-of-domain sample →
// log2(n_coeffs) half-domain folds → terminal B-constant layer → FS queries
// with per-layer fold-path openings + DEEP quotient openings at the same
// indices. Witness LDE is NEVER shipped.
//
// ============================================================================
// SOUNDNESS PARAMETERS (Fp3 substrate; code and statement MUST agree)
// ============================================================================
// Shipped: g=40, Fp3, blowup B=16 (ρ=1/16), Q=128 unique decoding.
//
// QUERY TERM (field-independent): 128·log2(32/17) = 116.80 bits pre-grinding,
// − 40 grinding = 76.80 bits post-grinding. Fri3SoundnessBoundBits() = 76
// (integer floor of the real 76.80).
//
// FIAT–SHAMIR / UNION TERMS (this is what the Fp3 substrate buys). Every FS
// collision term scales as (count)/|F|; moving |F| from p^2 ≈ 2^128 to
// p^3 ≈ 2^192 gains ≈ 64 bits per term. Exact per-term numbers at the shipped
// constants (post-grind = pre-grind + g = 40 bits of adversary grinding):
//   • RLC batching term (W+2)/|Fp3|, W ≤ kRCFriBatchMaxColumns = 2^12:
//       ≈ 2^-180.0 pre-grind → ≈ 2^-140.0 post-grind
//       (Fp2: ≈ 2^-116 pre-grind → ≈ 2^-76 post-grind).
//   • Dual-OOD DEEP (z1,z2), (2κ/(|Fp3|−2^32))² with κ = 2^28 (2κ = 2^29):
//       ≈ 2^-326.0 pre-grind → ≈ 2^-286.0 post-grind
//       (Fp2: ≈ 2^-196 pre-grind → ≈ 2^-156 post-grind).
//   • Fold-challenge union, ≤ kRCFriMaxFoldLayersHard·2^kRCFriMaxLdeLog2/|Fp3|
//     = 32·2^24/2^192 = 2^-163 pre-grind → ≈ 2^-123 post-grind
//       (Fp2: 2^-99 pre-grind → 2^-59-scale contributions in the wider union).
//   • DEEP quotient / per-challenge algebraic terms: deg/|Fp3| ≈ 2^24/2^192 =
//       2^-168 pre-grind → 2^-128 post-grind each.
// FS subtotal (union of the above) ≈ 2^-123 post-grind — more than 46 bits
// ABOVE the 2^-76.8 query floor. Over Fp2 the whole-protocol FS subtotal lands
// at ≈ 2^-72 post-grind and CAPS the composed bound below the query term; over
// Fp3 the composed separation bound is query-dominated at ≈ 76.8 bits, i.e.
// margin ≈ 12.8 bits (≥ 12) over the 2^-64 consensus target.
//
// DEEP/OOD (ePrint 2019/336; DEEP-ALI practice): after committing P, draw z∉D,
// claim v=P(z), commit quotient Q=(P−v)/(X−z), open Q at FRI query sites,
// check P(x)=Q(x)·(x−z)+v. Closes "proximity ≠ exact evaluation" for P(z).
// OOD z is resampled until its extension part (c1,c2) != (0,0) — the LDE
// domain D embeds on the c1=c2=0 base-field line, so a nonzero extension
// coordinate guarantees z ∉ D.
//
// Conjectured ρ^Q: -DBTX_RC_FRI_CONJECTURED_BOUND=1 (default OFF, never consensus).

namespace matmul::v4::rc {

using gkr_field::Fp3;

/** SHA256d of a byte buffer (defined in matmul_v4_rc_fri_ext3.cpp) — also the
 *  deterministic constant-generation XOF for matmul_v4_rc_alg_hash.cpp. */
[[nodiscard]] uint256 Sha256dBytes(const unsigned char* data, size_t len);

inline constexpr uint32_t kRCFri3ProofMagic = 0x33495246u; // 'FRI3'
inline constexpr uint32_t kRCFri3ProofVersion = 5;
inline constexpr char kRCFri3DomainTag[] = "BTX_RC_FRI3_V5";

// Blowup (16), grinding (40), query counts (128), hard caps and the CPU LDE
// guard are SHARED with the Fp2 stack (field-agnostic numeric parameters):
// kRCFriBlowup, kRCFriGrindingBits, kRCFriNumQueries, kRCFriBatchNumQueries,
// kRCFriMaxFoldLayersHard, kRCFriMaxQueriesHard, kRCFriMaxCoeffsHard,
// kRCFriMaxNestedDeepHard, kRCFriMaxProofBytesHard, kRCFriMaxLdeLog2,
// kRCFriMaxColumnLog2, kRCFriBatchMaxColumns, kRCFriTargetSoundnessBits.

[[nodiscard]] inline int Fri3SoundnessBoundBits()
{
    // Query proximity term is FIELD-INDEPENDENT: floor(Q·log2(32/17)) − g.
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull;
    const uint64_t prod = static_cast<uint64_t>(kRCFriNumQueries) * kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32) - static_cast<int>(kRCFriGrindingBits);
}

inline constexpr char kRCFri3SoundnessStatement[] =
    "FRI REAL (v5 Fp3 substrate + DEEP): blowup=16 (ρ=1/16), Q=128, g=40, Fp3 "
    "(|F|=p^3≈2^192); v5 half-domain fold (pair i with i+N/2) × log2(n_coeffs) "
    "→ terminal B-constant layer (Merkle of B identical leaves); "
    "UNIQUE-DECODING α=17/32 ⇒ Fri3SoundnessBoundBits()=76 (real 76.80, "
    "field-independent); DEEP/OOD binds P(z) via quotient openings at query "
    "sites (ePrint 2019/336); OOD z resampled until (c1,c2)!=(0,0); "
    "deep_quot_root≡nested FRI layer-0; deep_z_forced Haböck I(1) at z=1 uses "
    "layer-0 Merkle opening (not quotient). FS union terms ~2^-192-scale "
    "(≈2^-123 post-grind subtotal) ⇒ composed bound query-dominated at 76.80 "
    "bits. NOT conjectured ρ^Q. ROM, commit-then-challenge; fs_seed PoW-bound. "
    "COMPUTATIONAL — not ε=0.";

struct Fri3MerklePath {
    uint32_t index{0};
    Fp3 leaf{};
    std::vector<uint256> siblings;
};

struct Fri3FoldStep {
    /** Pair indices on domain size N: even_index = i, odd_index = i + N/2. */
    uint32_t even_index{0};
    uint32_t odd_index{0};
    Fp3 even{}; // f(x) at i
    Fp3 odd{};  // f(-x) at i+N/2
    std::vector<uint256> even_siblings;
    std::vector<uint256> odd_siblings;
};

struct Fri3QueryOpening {
    uint32_t index{0};
    std::vector<Fri3FoldStep> steps;
    /** DEEP: Q(x) leaf at the same index + Merkle siblings into deep_quot_root. */
    Fp3 deep_quot_leaf{};
    std::vector<uint256> deep_quot_siblings;
};

struct Fri3Proof {
    uint32_t version{kRCFri3ProofVersion};
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    uint32_t n_coeffs{0};
    std::vector<FriLayerCommit> layers;
    Fp3 final_value{};
    std::vector<Fp3> fold_challenges;
    std::vector<Fri3QueryOpening> queries;
    /** DEEP/OOD. has_deep=false only for nested quotient FRI. */
    bool has_deep{false};
    /**
     * If true, deep_z was fixed by the caller (not FS-sampled); verifier absorbs it.
     * When deep_z ∈ D (Haböck z=1), binding is a layer-0 Merkle opening of P at the
     * domain index — NOT the DEEP quotient path (z∈D is not a valid OOD point).
     */
    bool deep_z_forced{false};
    Fp3 deep_z{};
    Fp3 deep_eval{};
    /** Must equal deep_quot_fri->layers[0].root / n_leaves (OOD path). */
    uint256 deep_quot_root{};
    uint32_t deep_quot_n_leaves{0};
    /** Low-degree FRI on Q=(P−v)/(X−z); no recursive DEEP. Null on Haböck path. */
    std::shared_ptr<Fri3Proof> deep_quot_fri;
    /**
     * Haböck in-domain forced-z: Merkle path of deep_eval into layers[0] at
     * deep_domain_index (DomainPoint(n0, index) == deep_z). Empty on OOD path.
     */
    uint32_t deep_domain_index{0};
    std::vector<uint256> deep_domain_siblings;
};

struct Fri3CommitResult {
    Fri3Proof proof;
    std::vector<Fp3> lde_evals;
    std::vector<std::vector<Fp3>> layer_evals;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] Fri3CommitResult Fri3CommitAndFold(const std::vector<Fp3>& coeffs,
                                                 const uint256& fs_seed,
                                                 uint64_t pow_grind_nonce = 0,
                                                 bool enable_deep = true);

/**
 * Like Fri3CommitAndFold but forces evaluation at a fixed z (e.g. 1 for LogUp Σ).
 * If z ∈ D (Haböck z=1), binds P(z) via layer-0 Merkle opening; otherwise DEEP quotient.
 */
[[nodiscard]] Fri3CommitResult Fri3CommitAndFoldDeepAt(const std::vector<Fp3>& coeffs,
                                                       const uint256& fs_seed, const Fp3& deep_z,
                                                       uint64_t pow_grind_nonce = 0);

[[nodiscard]] Fp3 Fri3EvalPoly(const std::vector<Fp3>& coeffs, const Fp3& z);

[[nodiscard]] Fri3MerklePath Fri3OpenIndex(const std::vector<Fp3>& evals, uint32_t index);

[[nodiscard]] bool Fri3VerifyPath(const Fri3MerklePath& path, const uint256& root,
                                  uint32_t n_leaves);

[[nodiscard]] bool Fri3Verify(const Fri3Proof& proof, const uint256& fs_seed,
                              std::string* why = nullptr);

[[nodiscard]] size_t SerializeFri3Proof(const Fri3Proof& proof, std::vector<unsigned char>& out);
[[nodiscard]] std::optional<Fri3Proof> DeserializeFri3Proof(const std::vector<unsigned char>& in);

[[nodiscard]] uint256 Fri3LeafHash(const Fp3& v, uint32_t index);
[[nodiscard]] uint256 Fri3NodeHash(const uint256& left, const uint256& right);

[[nodiscard]] bool Fri3ForgeFlippedEvalMustFail(const Fri3CommitResult& honest,
                                                const uint256& fs_seed, uint32_t flip_index,
                                                std::string* why = nullptr);

// ============================================================================
// BATCHED FRI over Fp3 — ONE instance for ALL columns (mirror of
// FriBatchCommit/FriBatchVerify; see the construction note in
// matmul_v4_rc_fri.h §2.1–2.3 which applies verbatim with Fp2 → Fp3).
//
// CONSTRUCTION (identical shape):
//  1. Per-column LDE over the COMMON domain D of size N·16; Merkle root per
//     column; all roots absorbed before any challenge.
//  2. FS λ; U := Σ_i λ^{i−1}·X^{N−len_i}·P_i (degree-shift = maximal-degree
//     enforcement).
//  3. FS z1, z2 ∉ D (dual OOD, extension part (c1,c2)!=(0,0), z1 ≠ z2);
//     prover ships every column's evaluations at z1, z2; FS weights w1, w2;
//     DEEP composition G := w1·(U−U(z1))/(X−z1) + w2·(U−U(z2))/(X−z2), with
//     U(z_s) recomputed by the VERIFIER from the per-column claims.
//  4. Fold-commit G exactly as Fri3CommitAndFold folds; Q = 128 FS queries;
//     each query opens every column at the query index plus G's fold path and
//     checks the DEEP identity.
//
// Soundness: ε ≤ 2^-76.8 (queries, post-grind, field-independent) +
// 2^40·[(W+2)/|Fp3| + (2κ/(|Fp3|−2^32))²] ≈ 2^-76.8 + 2^-140 + 2^-286
// for W ≤ 2^12 columns — the FS terms sit ≥ 63 bits under the query term, so
// the composed bound is query-dominated (vs Fp2, where the same bracket is
// 2^-76 + 2^-156 and the wider-protocol FS union caps at ≈ 2^-72).
// ============================================================================

inline constexpr uint32_t kRCFri3BatchProofMagic = 0x33425246u; // 'FRB3'
inline constexpr uint32_t kRCFri3BatchProofVersion = 5;
inline constexpr char kRCFri3BatchDomainTag[] = "BTX_RC_FRIB3_V5";

[[nodiscard]] inline int Fri3BatchSoundnessBoundBits()
{
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull; // log2(32/17) in Q32
    const uint64_t prod = static_cast<uint64_t>(kRCFriBatchNumQueries) * kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32) - static_cast<int>(kRCFriGrindingBits);
}

inline constexpr char kRCFri3BatchSoundnessStatement[] =
    "BATCHED FRI (Fp3 substrate, v5 fold): ONE instance over ALL committed "
    "columns. Q=128, blowup=16, g=40, Fp3 (|F|=p^3~2^192), UNIQUE-DECODING "
    "alpha=17/32 => Fri3BatchSoundnessBoundBits()=76 (real 76.80). v5 "
    "half-domain fold × log2(n_coeffs) → terminal B-constant layer. DUAL-OOD "
    "DEEP (z1,z2) with extension part (c1,c2)!=(0,0) (⇒ off the base-field "
    "domain): dual gives (2k/|Fp3|)^2 ~ 2^-326 pre-grind (~2^-286 post); RLC "
    "term (W+2)/|Fp3| ~ 2^-180 pre-grind (~2^-140 post) — FS subtotal sits "
    "far above the 2^-76.8 query floor, so the composed bound is "
    "query-dominated at ~76.8 bits (margin ~12.8 over 2^-64). Degree-shift "
    "RLC enforces per-column maximal degree. COMPUTATIONAL — not eps=0.";

/** Per-query opening of one committed column at the query index. */
struct Fri3BatchColumnOpening {
    Fp3 value{};
    std::vector<uint256> siblings;
};

struct Fri3BatchQuery {
    uint32_t index{0};
    /** One opening per committed column, in column order. */
    std::vector<Fri3BatchColumnOpening> columns;
    /** Fold-path openings of the DEEP composition G (same shape as Fri3Proof). */
    std::vector<Fri3FoldStep> steps;
};

struct Fri3BatchProof {
    uint32_t version{kRCFri3BatchProofVersion};
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    /** Common padded column length N (power of two); LDE domain = N·blowup. */
    uint32_t n_coeffs{0};
    /** Per-column Merkle commitments over the common LDE domain. */
    std::vector<FriLayerCommit> columns;
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
    /** Fold-commit layers of the DEEP composition G. */
    std::vector<FriLayerCommit> fold_layers;
    Fp3 final_value{};
    std::vector<Fp3> fold_challenges;
    std::vector<Fri3BatchQuery> queries;
};

struct Fri3BatchCommitResult {
    Fri3BatchProof proof;
    /** Per-column LDE over the common domain (prover-side; NEVER shipped). */
    std::vector<std::vector<Fp3>> column_lde;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * Commit-and-prove: ONE batched FRI instance over all columns.
 * columns[i] = coefficient vector; size = logical length ℓ_i ≥ 1.
 * fs_seed MUST already bind everything the caller committed to —
 * commit-then-challenge.
 */
[[nodiscard]] Fri3BatchCommitResult Fri3BatchCommit(const std::vector<std::vector<Fp3>>& columns,
                                                    const uint256& fs_seed,
                                                    uint64_t pow_grind_nonce = 0);

[[nodiscard]] bool Fri3BatchVerify(const Fri3BatchProof& proof, const uint256& fs_seed,
                                   std::string* why = nullptr);

/**
 * Standalone column-root helper (two-epoch discipline): the Merkle root of a
 * column's LDE over the common domain of padded size n_coeffs. Byte-identical
 * to the root Fri3BatchCommit produces for the same (column, n_coeffs).
 * Returns the null hash on invalid input.
 */
[[nodiscard]] uint256 Fri3BatchColumnRoot(const std::vector<Fp3>& column, uint32_t n_coeffs);

[[nodiscard]] size_t SerializeFri3BatchProof(const Fri3BatchProof& proof,
                                             std::vector<unsigned char>& out);
[[nodiscard]] std::optional<Fri3BatchProof> DeserializeFri3BatchProof(
    const std::vector<unsigned char>& in);

[[nodiscard]] inline bool Fri3BatchClaimedBitsMeetTarget()
{
    return Fri3BatchSoundnessBoundBits() >= kRCFriTargetSoundnessBits &&
           kRCFriBatchNumQueries >= 116u && kRCFriBlowup == 16u &&
           kRCFriGrindingBits == 40u && !kRCFriConjecturedBoundEnabled;
}

[[nodiscard]] inline bool Fri3ClaimedBitsMeetTarget()
{
    return Fri3SoundnessBoundBits() >= kRCFriTargetSoundnessBits &&
           kRCFriNumQueries >= 116u && kRCFriBlowup == 16u &&
           kRCFriGrindingBits == 40u && !kRCFriConjecturedBoundEnabled;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_H
