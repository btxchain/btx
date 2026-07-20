// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_COUPLED_H
#define BTX_MATMUL_MATMUL_V4_RC_COUPLED_H

#include <primitives/block.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <vector>

// ENC_RC FINAL-FORM Stage C — toy-scale coupled puzzle (CPU consensus oracle).
//
// Structural final form of the per-nonce workload:
//   local exact int8 GEMM per lobe → nonce-derived balanced permutation →
//   exact integer butterfly/reduce-scatter all-to-all → non-affine Extract →
//   feed-forward into the next barrier.
//
// INERT: not selected by GetMatMulEncodingProfile at any height.
// nMatMulRCHeight remains INT32_MAX. Optional MatMulEncodingProfile stub
// comment only — do not add a live profile enum value here.
//
// Modes (hardware-neutral; digests identical when consensus lobe order is
// fixed 0..L-1):
//   SequentialLobes — Streamed / small-machine path (CPU does lobes in order).
//   Checkpointed    — barrier-boundary state only; recomputes forward identically.
// Concurrent lobe execution on a fabric node is the SAME math with the SAME
// fixed consensus order; single-thread CPU always runs lobes sequentially.

namespace matmul::v4::rc {

/** Toy-scale coupled-puzzle constants (all dims % 32). */
inline constexpr uint32_t kRCCoupRounds = 4;       // barriers
inline constexpr uint32_t kRCCoupLobes = 4;        // parallel lobes/heads
inline constexpr uint32_t kRCCoupLobeWidth = 32;   // fixed width
inline constexpr uint32_t kRCCoupStateBytes = kRCCoupLobes * kRCCoupLobeWidth; // 128
inline constexpr uint32_t kRCCoupBankPages = 8;    // epoch/template expert bank
inline constexpr uint32_t kRCCoupMixPatterns = 2;  // C6: ≥2 expander/butterfly patterns

static_assert(kRCCoupLobeWidth % 32 == 0, "lobe width must be MX-aligned");
static_assert(kRCCoupStateBytes % 32 == 0, "active state must be MX-aligned");
static_assert((kRCCoupStateBytes & (kRCCoupStateBytes - 1)) == 0,
              "active state length must be a power of two for butterfly mix");

/** Domain-separation tags (frozen byte strings). */
inline constexpr char kRCCoupEpisodeTag[] = "BTX_RC_COUP_EPISODE_V1";
inline constexpr char kRCCoupBankTag[] = "BTX_RC_COUP_BANK_V1";
inline constexpr char kRCCoupLobeTag[] = "BTX_RC_COUP_LOBE_V1";
inline constexpr char kRCCoupBarrierTag[] = "BTX_RC_COUP_BARRIER_V1";
inline constexpr char kRCCoupPermTag[] = "BTX_RC_COUP_PERM_V1";
inline constexpr char kRCCoupMixTag[] = "BTX_RC_COUP_MIX_V1";
inline constexpr char kRCCoupExtractTag[] = "BTX_RC_COUP_EXTRACT_V1";

/**
 * Execution policy — NON-consensus residency/scheduling. Digests MUST match
 * whenever the consensus lobe order 0..L-1 is respected.
 */
enum class RCCoupExecMode : uint8_t {
    SequentialLobes = 0, // Streamed / small machine (CPU default)
    Checkpointed = 1,    // retain barrier Extracted state; recompute forward
};

struct RCCoupOptions {
    RCCoupExecMode mode{RCCoupExecMode::SequentialLobes};

    /** Test-only shortcut hooks (C4 / H). Consensus path leaves these false. */
    bool skip_barrier{false};
    uint32_t skip_barrier_index{0};
    bool skip_bank_page{false};
    uint32_t skip_page_index{0};
};

/**
 * Sole toy consensus ground truth for the coupled puzzle.
 * sigma = DeriveSigma(header) (SHA256d header path, consistent with RC).
 * Fixed work per barrier — no early exit, no nonce-dependent dimensions (C4).
 */
[[nodiscard]] uint256 RecomputeCoupledPuzzleReference(const CBlockHeader& header,
                                                      int32_t height = 0,
                                                      const RCCoupOptions& options = {});

/** Epoch/template expert bank: kRCCoupBankPages pages of 32×32 int8 (C1).
 *  Independent of nonce/sigma — conceptually cacheable across attempts. */
[[nodiscard]] std::vector<std::vector<int8_t>>
DeriveCoupledBankPages(const CBlockHeader& header, int32_t height);

/** Nonce-fresh lobe seeds from sigma (C2) — cannot amortize across nonces. */
[[nodiscard]] std::array<uint256, kRCCoupLobes> DeriveCoupledLobeSeeds(const uint256& sigma);

/**
 * Nonce-derived balanced permutation π_b over [0, kRCCoupStateBytes).
 * Every output index appears exactly once (bijection). Fixed work — no early exit.
 */
[[nodiscard]] std::array<uint32_t, kRCCoupStateBytes>
DeriveCoupledBalancedPermutation(const uint256& sigma, uint32_t barrier);

[[nodiscard]] bool IsBalancedPermutation(const std::array<uint32_t, kRCCoupStateBytes>& pi);

/**
 * Stage E note — Extract/S-box shape:
 * Barrier nonlinearity uses ExtractMXTileInt64 on each 32-wide tile of the
 * post-mix int64 state (ChaCha-mixed mantissas × E8M0 scale). That map is
 * intentionally NON-AFFINE in the accumulator and is LOOKUP-ARGUMENT-shaped:
 * a future GKR/sumcheck (linear GEMM + exchange) + lookup column for the
 * Extract transition can treat each (raw64 tile → int8 tile) as a table
 * relation without claiming Freivalds on the Extract itself.
 */

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_COUPLED_H
