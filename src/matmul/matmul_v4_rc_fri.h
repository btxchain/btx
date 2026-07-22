// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FRI_H
#define BTX_MATMUL_MATMUL_V4_RC_FRI_H

#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// REAL FRI PCS for ENC_RC Section-2 (proof version 5) — M6/Fable + DEEP/OOD.
//
// Pipeline: LDE (blowup) → Merkle commit → DEEP out-of-domain sample →
// log2(n_coeffs) half-domain folds → terminal B-constant layer → FS queries
// with per-layer fold-path openings + DEEP quotient openings at the same
// indices. Witness LDE is NEVER shipped.
//
// ============================================================================
// SOUNDNESS PARAMETERS (M6 — Fable cross-check; code and statement MUST agree)
// ============================================================================
// Shipped: g=40, Fp2, blowup B=16 (ρ=1/16), Q=116 unique decoding.
// FriSoundnessBoundBits() = 65. See soundness note.
//
// DEEP/OOD (ePrint 2019/336; DEEP-ALI practice): after committing P, draw z∉D,
// claim v=P(z), commit quotient Q=(P−v)/(X−z), open Q at FRI query sites,
// check P(x)=Q(x)·(x−z)+v. Closes "proximity ≠ exact evaluation" for P(z).
//
// Conjectured ρ^Q: -DBTX_RC_FRI_CONJECTURED_BOUND=1 (default OFF, never consensus).

namespace matmul::v4::rc {

using gkr_field::Fp2;

inline constexpr uint32_t kRCFriProofMagic = 0x46524935u; // 'FRI5'
inline constexpr uint32_t kRCFriProofVersion = 5;
inline constexpr char kRCFriDomainTag[] = "BTX_RC_FRI_V5";

inline constexpr uint32_t kRCFriBlowup = 16;
inline constexpr uint32_t kRCFriGrindingBits = 40;
inline constexpr uint32_t kRCFriNumQueries = 116;
inline constexpr uint32_t kRCFriNumQueriesBciKs20Optional = 53;

[[nodiscard]] inline int FriSoundnessBoundBits()
{
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull;
    const uint64_t prod = static_cast<uint64_t>(kRCFriNumQueries) * kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32) - static_cast<int>(kRCFriGrindingBits);
}

inline constexpr int kRCFriTargetSoundnessBits = 64;

inline constexpr char kRCFriSoundnessStatement[] =
    "FRI REAL (v5/M6/Fable+DEEP): blowup=16 (ρ=1/16), Q=116, g=40, Fp2; "
    "v5 half-domain fold (pair i with i+N/2) × log2(n_coeffs) → terminal "
    "B-constant layer (Merkle of B identical leaves); "
    "UNIQUE-DECODING α=17/32 ⇒ FriSoundnessBoundBits()=65; "
    "DEEP/OOD binds P(z) via quotient openings at query sites (ePrint 2019/336); "
    "OOD z resampled until Fp2.c1!=0; deep_quot_root≡nested FRI layer-0; "
    "deep_z_forced Haböck I(1) at z=1 uses layer-0 Merkle opening (not quotient). "
    "NOT conjectured ρ^Q. ROM, commit-then-challenge; fs_seed PoW-bound. "
    "COMPUTATIONAL — not ε=0.";

inline constexpr size_t kRCFriProofBytesBudget = 1536 * 1024;
/** Stage-I happy-path ceiling (must equal kRCHappyPathVerifyBudgetS @ 90s/100bps). */
inline constexpr double kRCFriVerifyBudgetS = 90.0 * 100.0 / 10000.0; // 0.9 s

/** Hard deserialize / pre-verify caps (reject before fold/query work). */
inline constexpr uint32_t kRCFriMaxFoldLayersHard = 32;
inline constexpr uint32_t kRCFriMaxQueriesHard = 128; // >= kRCFriNumQueries
inline constexpr uint32_t kRCFriMaxCoeffsHard = 1u << 20;
inline constexpr uint32_t kRCFriMaxNestedDeepHard = 2;
inline constexpr size_t kRCFriMaxProofBytesHard = 16 * 1024 * 1024;

#if defined(BTX_RC_FRI_CONJECTURED_BOUND) && BTX_RC_FRI_CONJECTURED_BOUND
inline constexpr bool kRCFriConjecturedBoundEnabled = true;
#else
inline constexpr bool kRCFriConjecturedBoundEnabled = false;
#endif

struct FriMerklePath {
    uint32_t index{0};
    Fp2 leaf{};
    std::vector<uint256> siblings;
};

struct FriFoldStep {
    /** Pair indices on domain size N: even_index = i, odd_index = i + N/2. */
    uint32_t even_index{0};
    uint32_t odd_index{0};
    Fp2 even{}; // f(x) at i
    Fp2 odd{};  // f(-x) at i+N/2
    std::vector<uint256> even_siblings;
    std::vector<uint256> odd_siblings;
};

struct FriQueryOpening {
    uint32_t index{0};
    std::vector<FriFoldStep> steps;
    /** DEEP: Q(x) leaf at the same index + Merkle siblings into deep_quot_root. */
    Fp2 deep_quot_leaf{};
    std::vector<uint256> deep_quot_siblings;
};

struct FriLayerCommit {
    uint256 root{};
    uint32_t n_leaves{0};
};

struct FriProof {
    uint32_t version{kRCFriProofVersion};
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    uint32_t n_coeffs{0};
    std::vector<FriLayerCommit> layers;
    Fp2 final_value{};
    std::vector<Fp2> fold_challenges;
    std::vector<FriQueryOpening> queries;
    /** DEEP/OOD (v3). has_deep=false only for nested quotient FRI. */
    bool has_deep{false};
    /**
     * If true, deep_z was fixed by the caller (not FS-sampled); verifier absorbs it.
     * When deep_z ∈ D (Haböck z=1), binding is a layer-0 Merkle opening of P at the
     * domain index — NOT the DEEP quotient path (z∈D is not a valid OOD point).
     */
    bool deep_z_forced{false};
    Fp2 deep_z{};
    Fp2 deep_eval{};
    /** Must equal deep_quot_fri->layers[0].root / n_leaves (OOD path). */
    uint256 deep_quot_root{};
    uint32_t deep_quot_n_leaves{0};
    /** Low-degree FRI on Q=(P−v)/(X−z); no recursive DEEP. Null on Haböck path. */
    std::shared_ptr<FriProof> deep_quot_fri;
    /**
     * Haböck in-domain forced-z: Merkle path of deep_eval into layers[0] at
     * deep_domain_index (DomainPoint(n0, index) == deep_z). Empty on OOD path.
     */
    uint32_t deep_domain_index{0};
    std::vector<uint256> deep_domain_siblings;
};

struct FriCommitResult {
    FriProof proof;
    std::vector<Fp2> lde_evals;
    std::vector<std::vector<Fp2>> layer_evals;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] FriCommitResult FriCommitAndFold(const std::vector<Fp2>& coeffs,
                                               const uint256& fs_seed,
                                               uint64_t pow_grind_nonce = 0,
                                               bool enable_deep = true);

/**
 * Like FriCommitAndFold but forces evaluation at a fixed z (e.g. 1 for LogUp Σ).
 * If z ∈ D (Haböck z=1), binds P(z) via layer-0 Merkle opening; otherwise DEEP quotient.
 */
[[nodiscard]] FriCommitResult FriCommitAndFoldDeepAt(const std::vector<Fp2>& coeffs,
                                                     const uint256& fs_seed, const Fp2& deep_z,
                                                     uint64_t pow_grind_nonce = 0);

[[nodiscard]] Fp2 FriEvalPoly(const std::vector<Fp2>& coeffs, const Fp2& z);

[[nodiscard]] FriMerklePath FriOpenIndex(const std::vector<Fp2>& evals, uint32_t index);

[[nodiscard]] bool FriVerifyPath(const FriMerklePath& path, const uint256& root,
                                 uint32_t n_leaves);

[[nodiscard]] bool FriVerify(const FriProof& proof, const uint256& fs_seed,
                             std::string* why = nullptr);

[[nodiscard]] size_t SerializeFriProof(const FriProof& proof, std::vector<unsigned char>& out);
[[nodiscard]] std::optional<FriProof> DeserializeFriProof(const std::vector<unsigned char>& in);

[[nodiscard]] uint256 FriLeafHash(const Fp2& v, uint32_t index);
[[nodiscard]] uint256 FriNodeHash(const uint256& left, const uint256& right);

[[nodiscard]] uint32_t FriNextPow2(uint32_t n);

[[nodiscard]] bool FriForgeFlippedEvalMustFail(const FriCommitResult& honest,
                                               const uint256& fs_seed, uint32_t flip_index,
                                               std::string* why = nullptr);

// ============================================================================
// BATCHED FRI (proof v7 FOUNDATION substrate) — ONE instance for ALL columns.
// Blueprint: doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md §2.1–2.3
// + companion soundness table 2026-07-21.
//
// WHY BATCHING IS MANDATORY (not cosmetic): the v6 proof carries 7 independent
// FRI instances (a/b/trace/lookup/table/inv/r). Each is 2^-65.85 post-grinding;
// the adversary attacks the weakest of its choice, so the union bound is
// ≥ 7·2^-65.85 ≈ 2^-63.05 — FAILING the 2^-64 target. A single batched
// instance over the FS random linear combination λ of all columns restores a
// single query term.
//
// QUERY COUNT: Q = 116 clears 2^-64 with < 1 bit of margin (65.85 bits).
// Per the blueprint's pre-cutover hardening recommendation the batched
// instance ships Q = kRCFriBatchNumQueries = 128:
//   128·log2(32/17) = 116.80 bits pre-grinding − 40 grinding = 76 bits.
//
// DUAL-OOD DEEP: a single OOD point z over Fp2 caps the bindable column
// degree at 2^(128−40−64) = 2^24 coefficients; consensus columns reach
// κ = 2^28. Two independent OOD points z1 ≠ z2 give
// (2κ/(|Fp2|−|D|))² ≈ 2^-196 pre-grinding (soundness table row "dual-OOD").
// Every column's claimed evaluations at BOTH z1 and z2 ride in the proof and
// are bound by the batched DEEP identity at each query site — these bound
// (C_i(z1), C_i(z2)) pairs ARE the opening primitive the §2.4 evaluation
// argument consumes.
//
// 2-ADICITY WALL (κ): Goldilocks F_p^× has 2-adicity 32; with blowup 16 a
// single column caps at 2^28 coefficients (LDE 16·2^28 = 2^32). The consensus
// trace (2^33.4 cells) therefore CANNOT be one concatenated vector — see
// RCGkrTraceLayout (matmul_v4_rc_gkr.h) for the forced multi-column split.
//
// CONSTRUCTION (per §2.2, reusing the shipped fold/query machinery verbatim):
//  1. Per-column LDE over the COMMON domain D of size N·16 (N = max padded
//     column length); Merkle root per column; all roots absorbed before any
//     challenge.
//  2. FS λ; U := Σ_i λ^{i−1}·X^{N−len_i}·P_i  (degree-shift = maximal-degree
//     enforcement: U low-degree ⇒ deg P_i < len_i for every i).
//  3. FS z1, z2 ∉ D (dual OOD); prover ships every column's evaluations at
//     z1, z2; FS weights w1, w2; DEEP composition
//     G := w1·(U − U(z1))/(X − z1) + w2·(U − U(z2))/(X − z2), where U(z_s) is
//     recomputed by the VERIFIER from the per-column claims (this is what
//     binds them).
//  4. Fold-commit G exactly as FriCommitAndFold folds; Q = 128 FS queries;
//     each query opens every column at the query index (Merkle path into the
//     column root) plus G's fold path, and checks the DEEP identity
//     G(x)·1 = w1(U(x)−v1)/(x−z1) + w2(U(x)−v2)/(x−z2) with
//     U(x) = Σ λ^{i−1} x^{N−len_i}·C_i(x) from the column openings.
//
// Soundness (Theorem 2.1): ε ≤ 2^-76.8 (queries, post-grind) +
// 2^40·[(W+2)/|Fp2| + (2κ/(|Fp2|−2^32))²] ≤ 2^-76 for W ≤ 2^11 columns.
// The legacy 7-instance layout and FriCommitAndFold remain byte-identical
// (epoch-0 golden unchanged); FriCommitAndFold stays for preprocessed-table
// roots only.
// ============================================================================

inline constexpr uint32_t kRCFriBatchProofMagic = 0x42495246u; // 'FRIB'
inline constexpr uint32_t kRCFriBatchProofVersion = 5;
inline constexpr char kRCFriBatchDomainTag[] = "BTX_RC_FRIB_V5";
/** Batched-instance query count. NAMED CONSTANT (soundness table): Q=116
 *  clears 2^-64 with <1 bit margin; Q=128 is the recommended hardening →
 *  floor(128·log2(32/17)) − 40 = 76 bits post-grinding. */
inline constexpr uint32_t kRCFriBatchNumQueries = 128;
/** RLC width cap W ≤ 2^12 keeps the (W+2)/|Fp2| batching term ≥ 76 bits post-grind. */
inline constexpr uint32_t kRCFriBatchMaxColumns = 1u << 12;
/** κ: max coefficients per committed column. LDE 16·2^28 = 2^32 = the largest
 *  power-of-two subgroup of Goldilocks F_p^× (2-adicity 32). HARD protocol cap.
 *
 *  EXECUTABLE CEILING IS MUCH LOWER. The CPU prover/verifier additionally
 *  reject any column whose LDE exceeds 2^24 (kRCFriMaxLdeLog2 below) — i.e.
 *  n_coeffs·blowup > 2^24, so ≤ 2^20 coefficients/column in practice. That is
 *  a deliberate memory guard, not the protocol bound: consensus-dimension
 *  columns (trace ≈ 2^33 cells) exceed it and route to over_budget →
 *  ExactReplay (arbiter OFF). A production FRI over the full 2^28/2^32 domain,
 *  OR a formally-aggregated split into ≤2^20 chunks, is a PARKED work item.
 *  Do NOT read kRCFriMaxColumnLog2 as "the executable handles 2^28 columns." */
inline constexpr uint32_t kRCFriMaxColumnLog2 = 28;
static_assert((uint64_t{16} << kRCFriMaxColumnLog2) == (uint64_t{1} << 32),
              "blowup·κ must equal the Goldilocks 2-adicity cap 2^32");
/** Executable LDE ceiling: the CPU guard rejects any committed column whose
 *  LDE domain (n_coeffs·blowup) exceeds 2^kRCFriMaxLdeLog2. Named so the guard
 *  sites and this constant cannot drift apart. */
inline constexpr uint32_t kRCFriMaxLdeLog2 = 24;

[[nodiscard]] inline int FriBatchSoundnessBoundBits()
{
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull; // log2(32/17) in Q32
    const uint64_t prod = static_cast<uint64_t>(kRCFriBatchNumQueries) * kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32) - static_cast<int>(kRCFriGrindingBits);
}

inline constexpr char kRCFriBatchSoundnessStatement[] =
    "BATCHED FRI (v7 substrate, v5 fold): ONE instance over ALL committed "
    "columns (7 separate instances union to 2^-63.05 — FAILS 2^-64; batching "
    "restores a single query term). Q=128, blowup=16, g=40, Fp2, UNIQUE-DECODING "
    "alpha=17/32 => FriBatchSoundnessBoundBits()=76. v5 half-domain fold × "
    "log2(n_coeffs) → terminal B-constant layer. DUAL-OOD DEEP (z1,z2) with "
    "Fp2.c1!=0 (extension coeff nonzero): single OOD caps column degree at "
    "2^24 < kappa=2^28; dual gives (2k/|Fp2|)^2 ~ 2^-196 pre-grind. "
    "Degree-shift RLC enforces per-column maximal degree. COMPUTATIONAL — "
    "not eps=0. Arbiter OFF.";

/** Per-query opening of one committed column at the query index. */
struct FriBatchColumnOpening {
    Fp2 value{};
    std::vector<uint256> siblings;
};

struct FriBatchQuery {
    uint32_t index{0};
    /** One opening per committed column, in column order. */
    std::vector<FriBatchColumnOpening> columns;
    /** Fold-path openings of the DEEP composition G (same shape as FriProof). */
    std::vector<FriFoldStep> steps;
};

struct FriBatchProof {
    uint32_t version{kRCFriBatchProofVersion};
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    /** Common padded column length N (power of two); LDE domain = N·blowup. */
    uint32_t n_coeffs{0};
    /** Per-column Merkle commitments over the common LDE domain. */
    std::vector<FriLayerCommit> columns;
    /** Logical (pre-padding) length ℓ_i of each column = enforced degree bound. */
    std::vector<uint32_t> column_len;
    /** FS RLC challenge (recomputed and checked by the verifier). */
    Fp2 lambda{};
    /** Dual OOD points (FS, both ∉ D, z1 ≠ z2). */
    Fp2 z1{};
    Fp2 z2{};
    /** Claimed per-column evaluations at z1/z2 — THE bound opening primitive. */
    std::vector<Fp2> evals_z1;
    std::vector<Fp2> evals_z2;
    /** FS DEEP batching weights (recomputed and checked). */
    Fp2 w1{};
    Fp2 w2{};
    /** Fold-commit layers of the DEEP composition G. */
    std::vector<FriLayerCommit> fold_layers;
    Fp2 final_value{};
    std::vector<Fp2> fold_challenges;
    std::vector<FriBatchQuery> queries;
};

struct FriBatchCommitResult {
    FriBatchProof proof;
    /** Per-column LDE over the common domain (prover-side; NEVER shipped). */
    std::vector<std::vector<Fp2>> column_lde;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * Commit-and-prove: ONE batched FRI instance over all columns.
 * columns[i] = coefficient vector (= wire values in the coefficient-basis
 * commitment of blueprint §1.3); size = logical length ℓ_i ≥ 1.
 * fs_seed MUST already bind everything the caller committed to (see
 * RCGkrFsSeedV7) — commit-then-challenge.
 */
[[nodiscard]] FriBatchCommitResult FriBatchCommit(const std::vector<std::vector<Fp2>>& columns,
                                                  const uint256& fs_seed,
                                                  uint64_t pow_grind_nonce = 0);

[[nodiscard]] bool FriBatchVerify(const FriBatchProof& proof, const uint256& fs_seed,
                                  std::string* why = nullptr);

/**
 * Standalone column-root helper (two-epoch discipline): the Merkle root of a
 * column's LDE over the common domain of padded size n_coeffs. Byte-identical
 * to the root FriBatchCommit produces for the same (column, n_coeffs), so an
 * outer transcript can absorb epoch-1 roots before later-epoch columns
 * (eval-argument f/g) exist. Returns the null hash on invalid input.
 */
[[nodiscard]] uint256 FriBatchColumnRoot(const std::vector<Fp2>& column, uint32_t n_coeffs);

[[nodiscard]] size_t SerializeFriBatchProof(const FriBatchProof& proof,
                                            std::vector<unsigned char>& out);
[[nodiscard]] std::optional<FriBatchProof> DeserializeFriBatchProof(
    const std::vector<unsigned char>& in);

[[nodiscard]] inline bool FriBatchClaimedBitsMeetTarget()
{
    return FriBatchSoundnessBoundBits() >= kRCFriTargetSoundnessBits &&
           kRCFriBatchNumQueries >= 116u && kRCFriBlowup == 16u &&
           kRCFriGrindingBits == 40u && !kRCFriConjecturedBoundEnabled;
}

[[nodiscard]] inline bool FriClaimedBitsMeetTarget()
{
    return FriSoundnessBoundBits() >= kRCFriTargetSoundnessBits &&
           kRCFriNumQueries >= 116u && kRCFriBlowup == 16u &&
           kRCFriGrindingBits == 40u && !kRCFriConjecturedBoundEnabled;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_H
