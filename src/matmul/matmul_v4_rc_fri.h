// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FRI_H
#define BTX_MATMUL_MATMUL_V4_RC_FRI_H

#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// REAL FRI PCS for ENC_RC Section-2 (proof version 2) — M6 / Fable oracle.
//
// Pipeline: LDE (blowup) → Merkle commit → multi-round fold → FS queries with
// per-layer fold-path openings. Witness LDE is NEVER shipped.
//
// ============================================================================
// SOUNDNESS PARAMETERS (M6 — Fable cross-check; code and statement MUST agree)
// ============================================================================
// Shipped operating point (proven unique decoding, NOT conjectured ρ^Q):
//   grinding g = 40, field = Fp2, blowup B = 16 (ρ = 1/16), queries Q = 116
//   α = (1+ρ)/2 = 17/32  (per-query miss under unique-decoding radius)
//   Q = ceil((65 + g) / (-log2 α)) = ceil(105 / log2(32/17)) = 116
//   log2(T·ε) = g + Q·log2(α) ≈ -65.85  (Fable table cites ≈ -65.26; both ≤ -64)
//   FriSoundnessBoundBits() = floor(Q·log2(32/17) − g) = 65 ≥ 64
//
// BUG FIXED (prior tip): claimed ε ≤ ρ^k = (1/8)^40 or "Q=40 clears 2^-64" /
// "~80 queries" — all invalid under unique decoding. The ethSTARK-style ρ^Q
// form is CONJECTURED and is NEVER used for consensus. Optional research-only
// path: compile with -DBTX_RC_FRI_CONJECTURED_BOUND=1 (default OFF).
//
// Fp3 (v³−2, |E|≈2^192): required only for grinding tiers g≥64 (Fable table:
// g=64 → Q=142; g=80 → Q=159). NOT built — Fp2 is sufficient at g=40. See
// soundness note.
//
// DEEP / OOD: this FRI wrapper proves proximity to a low-degree codeword; it
// does NOT by itself bind an exact evaluation. Exact-evaluation binding via
// DEEP/out-of-domain sampling is an OPEN item before external audit sign-off
// (shadow ON / ExactReplay remains consensus arbiter).
//
// CITATIONS: FRI 2018; BKS 2018; BCIKS20 ePrint 2020/654 (M11 optional).
// Assumptions: ROM, commit-then-challenge, fs_seed PoW-bound by GKR caller.

namespace matmul::v4::rc {

using gkr_field::Fp2;

inline constexpr uint32_t kRCFriProofMagic = 0x46524933u; // 'FRI3'
inline constexpr uint32_t kRCFriProofVersion = 2;
inline constexpr char kRCFriDomainTag[] = "BTX_RC_FRI_V2";

/** LDE blowup factor B; rate ρ = 1/B. Fable k=40/Fp2 tier uses B=16. */
inline constexpr uint32_t kRCFriBlowup = 16;

/** PoW grinding bits assumed (T ≤ 2^g); subtracted from the bound. */
inline constexpr uint32_t kRCFriGrindingBits = 40;

/**
 * Query count under CONSERVATIVE unique-decoding (M6 / Fable oracle).
 * Q ≥ ceil((65 + g) / log2(2B/(B+1))) with B=16, g=40 → 116.
 */
inline constexpr uint32_t kRCFriNumQueries = 116;

/**
 * Optional BCIKS20 proximity-gap query count (M11 — NOT shipped as default).
 * t ≈ ceil(2 · (65+g) / log2(B)) = ceil(210/4) = 53 for B=16,g=40 when q ≫ n².
 */
inline constexpr uint32_t kRCFriNumQueriesBciKs20Optional = 53;

/**
 * Exact claimed bits after grinding under unique-decoding:
 *   floor( Q * log2(2B/(B+1)) - g ) = floor(Q · log2(32/17) - 40) for B=16.
 */
[[nodiscard]] inline int FriSoundnessBoundBits()
{
    // log2(32/17) * 2^32 ≈ 3919317253 (verified vs Fable Q=116 → 65 bits).
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull;
    const uint64_t prod = static_cast<uint64_t>(kRCFriNumQueries) * kLog2_32_17_Q32;
    const int bits = static_cast<int>(prod >> 32) - static_cast<int>(kRCFriGrindingBits);
    return bits;
}

/** Minimum bits required by Gate M6. */
inline constexpr int kRCFriTargetSoundnessBits = 64;

/**
 * Human-readable statement — MUST match FriSoundnessBoundBits() numerically.
 */
inline constexpr char kRCFriSoundnessStatement[] =
    "FRI REAL (v2/M6/Fable): LDE blowup=16 (ρ=1/16), Q=116 queries, g=40 grinding, "
    "Fp2; UNIQUE-DECODING per-query miss α=(1+ρ)/2=17/32; "
    "ε_net≤2^g·α^Q ⇒ FriSoundnessBoundBits()=65≥64 (log2(T·ε)≈-65.85). "
    "NOT conjectured ρ^Q. NOT BCIKS20 default. Fp3 only for g≥64 (unbuilt). "
    "Proximity only — DEEP/OOD exact-eval binding OPEN. "
    "ROM, commit-then-challenge; fs_seed PoW-bound. COMPUTATIONAL — not ε=0.";

/** Soft budgets for Section-2 (toy/medium CPU). Not silicon rates. */
inline constexpr size_t kRCFriProofBytesBudget = 768 * 1024; // 768 KiB (Q=116, B=16)
inline constexpr double kRCFriVerifyBudgetS = 1.0;

#if defined(BTX_RC_FRI_CONJECTURED_BOUND) && BTX_RC_FRI_CONJECTURED_BOUND
// RESEARCH ONLY — never consensus. ethSTARK-style ε≈ρ^Q (requires δ≥1−ρ).
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
    uint32_t even_index{0};
    Fp2 even{};
    Fp2 odd{};
    std::vector<uint256> even_siblings;
    std::vector<uint256> odd_siblings;
};

struct FriQueryOpening {
    uint32_t index{0};
    std::vector<FriFoldStep> steps;
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
                                               uint64_t pow_grind_nonce = 0);

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

/** Static assert helpers used by tests: claimed bits meet target. */
[[nodiscard]] inline bool FriClaimedBitsMeetTarget()
{
    return FriSoundnessBoundBits() >= kRCFriTargetSoundnessBits &&
           kRCFriNumQueries >= 116u && // Fable k=40/B=16 unique-decoding
           kRCFriBlowup == 16u && kRCFriGrindingBits == 40u &&
           !kRCFriConjecturedBoundEnabled;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_H
