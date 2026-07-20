// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_COUPLED_H
#define BTX_MATMUL_MATMUL_V4_RC_COUPLED_H

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_coupled_device.h>
#include <primitives/block.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <vector>

// ENC_RC FINAL-FORM Stage C — coupled puzzle (CPU consensus oracle).
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
//   SequentialLobes — keep bank resident; run lobes in order 0..L-1.
//   Checkpointed    — barrier-boundary Extracted state only; re-page bank.
//   Streamed        — page bank pages one-at-a-time (do not retain full bank).
//   Resident        — retain full bank + active lobe state across barriers.

namespace matmul::v4::rc {

/** Toy-scale coupled-puzzle constants (frozen; Match MakeToyRCCoupParams()). */
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
 * Parametric coupled-puzzle shape. Toy defaults match the frozen constexprs
 * above (golden digest byte-identical). Medium is CI-safe but larger.
 */
struct RCCoupParams {
    uint32_t barriers{kRCCoupRounds};
    uint32_t lobes{kRCCoupLobes};
    uint32_t lobe_width{kRCCoupLobeWidth};
    uint32_t bank_pages{kRCCoupBankPages};

    [[nodiscard]] uint32_t StateBytes() const { return lobes * lobe_width; }
};

[[nodiscard]] bool ValidateRCCoupParams(const RCCoupParams& p);
[[nodiscard]] RCCoupParams MakeToyRCCoupParams();
/** CI-safe larger shape: barriers=8, lobes=8, lobe_width=64, bank_pages=32. */
[[nodiscard]] RCCoupParams MakeMediumRCCoupParams();

/**
 * Execution policy — NON-consensus residency/scheduling. Digests MUST match
 * whenever the consensus lobe order 0..L-1 is respected.
 */
enum class RCCoupExecMode : uint8_t {
    SequentialLobes = 0, // keep bank; lobes in order (CPU default)
    Checkpointed = 1,    // retain barrier Extracted state; re-page bank
    Streamed = 2,        // page bank one-at-a-time; do not retain full bank
    Resident = 3,        // retain full bank + active lobe state
};

struct RCCoupOptions {
    RCCoupExecMode mode{RCCoupExecMode::SequentialLobes};

    /** Test-only shortcut hooks (C4 / H). Consensus path leaves these false. */
    bool skip_barrier{false};
    uint32_t skip_barrier_index{0};
    bool skip_bank_page{false};
    uint32_t skip_page_index{0};
};

/** Optional wall-clock timing for harness / measurement (not consensus). */
struct RCCoupTiming {
    double bank_s{0};
    double barriers_s{0};
    double total_s{0};
};

/**
 * Sole consensus ground truth for the coupled puzzle (toy params).
 * sigma = DeriveSigma(header) (SHA256d header path, consistent with RC).
 * Fixed work per barrier — no early exit, no nonce-dependent dimensions (C4).
 */
[[nodiscard]] uint256 RecomputeCoupledPuzzleReference(const CBlockHeader& header,
                                                      int32_t height = 0,
                                                      const RCCoupOptions& options = {});

/**
 * Parametric overload. Optional ExactGemmBackend injects local lobe GEMMs
 * (empty = CPU ExactGemmS8S8). Device-first via ExactGemmS8S8Dispatched
 * semantics: successful device output replaces CPU (no silent rescue of a
 * wrong-but-successful backend). Consensus REJECT passes an empty backend.
 */
[[nodiscard]] uint256 RecomputeCoupledPuzzleReference(
    const CBlockHeader& header, int32_t height, const RCCoupParams& params,
    const RCCoupOptions& options = {},
    const matmul::v4::lt::ExactGemmBackend& gemm = {},
    RCCoupTiming* out_timing = nullptr);

/** Miner entry: same digest as the CPU reference; may inject ExactGemm. */
[[nodiscard]] uint256 MineCoupledPuzzle(const CBlockHeader& header, int32_t height,
                                        const RCCoupParams& params,
                                        const matmul::v4::lt::ExactGemmBackend& gemm = {},
                                        const RCCoupOptions& options = {});

/** Epoch/template expert bank (toy params). */
[[nodiscard]] std::vector<std::vector<int8_t>>
DeriveCoupledBankPages(const CBlockHeader& header, int32_t height);

[[nodiscard]] std::vector<std::vector<int8_t>>
DeriveCoupledBankPages(const CBlockHeader& header, int32_t height,
                       const RCCoupParams& params);

/** Single bank page (Streamed path); same seed as DeriveCoupledBankPages[p]. */
[[nodiscard]] std::vector<int8_t>
DeriveCoupledBankPage(const CBlockHeader& header, int32_t height, uint32_t page,
                      const RCCoupParams& params);

/** Nonce-fresh lobe seeds from sigma (C2) — cannot amortize across nonces. */
[[nodiscard]] std::array<uint256, kRCCoupLobes> DeriveCoupledLobeSeeds(const uint256& sigma);

[[nodiscard]] std::vector<uint256> DeriveCoupledLobeSeeds(const uint256& sigma,
                                                          const RCCoupParams& params);

/**
 * Nonce-derived balanced permutation π_b over [0, StateBytes).
 * Every output index appears exactly once (bijection). Fixed work — no early exit.
 */
[[nodiscard]] std::array<uint32_t, kRCCoupStateBytes>
DeriveCoupledBalancedPermutation(const uint256& sigma, uint32_t barrier);

[[nodiscard]] std::vector<uint32_t>
DeriveCoupledBalancedPermutation(const uint256& sigma, uint32_t barrier,
                                 const RCCoupParams& params);

[[nodiscard]] bool IsBalancedPermutation(const std::array<uint32_t, kRCCoupStateBytes>& pi);
[[nodiscard]] bool IsBalancedPermutation(const std::vector<uint32_t>& pi, uint32_t n);

/**
 * Stage E note — Extract/S-box shape:
 * Barrier nonlinearity uses ExtractMXTileInt64 on each 32-wide tile of the
 * post-mix int64 state (ChaCha-mixed mantissas × E8M0 scale). That map is
 * intentionally NON-AFFINE in the accumulator and is LOOKUP-ARGUMENT-shaped:
 * a future GKR/sumcheck (linear GEMM + exchange) + lookup column for the
 * Extract transition can treat each (raw64 tile → int8 tile) as a table
 * relation without claiming Freivalds on the Extract itself.
 */

/**
 * Multi-backend mining inject (harness / miner-local):
 *   auto gemm = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
 *   MineCoupledPuzzle(header, height, params, gemm);
 * CUDA/HIP/Metal LaunchGemmS8S8 when RC self-qual admits; else empty → CPU.
 * Probe: ProbeRCCoupledDevice() in matmul_v4_rc_coupled_device.h.
 */

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_COUPLED_H
