// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_COUPLED_H
#define BTX_MATMUL_MATMUL_V4_RC_COUPLED_H

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_coupled_device.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_distributed.h>
#include <primitives/block.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <vector>

namespace Consensus {
struct Params;
}

// ENC_RC FINAL-FORM Stage C — coupled puzzle (CPU consensus oracle).
//
// Structural final form of the per-nonce workload:
//   local exact int8 GEMM per lobe → nonce-derived balanced permutation →
//   exact integer butterfly/reduce-scatter all-to-all → non-affine Extract →
//   feed-forward into the next barrier.
//
// Consensus wiring (STILL INERT on public nets):
//   MatMulEncodingProfile::ENC_RC_COUPLED selected only when
//   IsMatMulRCCoupledActive(height) — requires finite nMatMulRCCoupledHeight
//   (public nets assert INT32_MAX). Regtest enables via explicit height +
//   optional fMatMulRCCoupledUseToyDims.
//
// Production barrier-loop completeness (C1–C6; see RCCoupBarrierLoopComplete):
//   C1 bank cacheable (epoch/template-committed pages)
//   C2 nonce-fresh lobes (sigma-seeded)
//   C3 balanced perm + all-to-all + Extract between linear stages + feed-forward
//   C4 fixed work (no early exit / nonce-dependent dims)
//   C5 barriers ∈ [4, 8]
//   C6 ≥2 independently nonce-relabeled mix patterns
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

/**
 * Coupled domain-separation tags (F7).
 *
 * V1/V2/V3 string families MUST NOT collide. Historical coupled digests (toy V1
 * `7a7ce106…`, medium V2 `349175d5…`) were produced under the V1 tag family with
 * `transcript_version=1` (default). V3 shapes MUST select the V3 family via
 * `RCCoupOptions::transcript_version == ENC_RC_V3` (see MakeV3RCCoupOptions).
 */
/** ENC_RC_COUPLED V1 tags (default / frozen V1+V2 goldens). */
inline constexpr char kRCCoupEpisodeTag[] = "BTX_RC_COUP_EPISODE_V1";
inline constexpr char kRCCoupBankTag[] = "BTX_RC_COUP_BANK_V1";
inline constexpr char kRCCoupLobeTag[] = "BTX_RC_COUP_LOBE_V1";
inline constexpr char kRCCoupBarrierTag[] = "BTX_RC_COUP_BARRIER_V1";
inline constexpr char kRCCoupPermTag[] = "BTX_RC_COUP_PERM_V1";
inline constexpr char kRCCoupMixTag[] = "BTX_RC_COUP_MIX_V1";
inline constexpr char kRCCoupExtractTag[] = "BTX_RC_COUP_EXTRACT_V1";
inline constexpr char kRCCoupFullBankTag[] = "BTX_RC_COUP_FULL_BANK_V1";
inline constexpr char kRCCoupMaterialExchangeTag[] = "BTX_RC_COUP_MAT_XCHG_V1";

/** ENC_RC_COUPLED V2 tags (independent; selected when transcript_version==2). */
inline constexpr char kRCCoupEpisodeTagV2[] = "BTX_RC_COUP_EPISODE_V2";
inline constexpr char kRCCoupBankTagV2[] = "BTX_RC_COUP_BANK_V2";
inline constexpr char kRCCoupLobeTagV2[] = "BTX_RC_COUP_LOBE_V2";
inline constexpr char kRCCoupBarrierTagV2[] = "BTX_RC_COUP_BARRIER_V2";
inline constexpr char kRCCoupPermTagV2[] = "BTX_RC_COUP_PERM_V2";
inline constexpr char kRCCoupMixTagV2[] = "BTX_RC_COUP_MIX_V2";
inline constexpr char kRCCoupExtractTagV2[] = "BTX_RC_COUP_EXTRACT_V2";
inline constexpr char kRCCoupFullBankTagV2[] = "BTX_RC_COUP_FULL_BANK_V2";
inline constexpr char kRCCoupMaterialExchangeTagV2[] = "BTX_RC_COUP_MAT_XCHG_V2";

/** ENC_RC_COUPLED V3 tags (independent; selected when transcript_version==3). */
inline constexpr char kRCCoupEpisodeTagV3[] = "BTX_RC_COUP_EPISODE_V3";
inline constexpr char kRCCoupBankTagV3[] = "BTX_RC_COUP_BANK_V3";
inline constexpr char kRCCoupLobeTagV3[] = "BTX_RC_COUP_LOBE_V3";
inline constexpr char kRCCoupBarrierTagV3[] = "BTX_RC_COUP_BARRIER_V3";
inline constexpr char kRCCoupPermTagV3[] = "BTX_RC_COUP_PERM_V3";
inline constexpr char kRCCoupMixTagV3[] = "BTX_RC_COUP_MIX_V3";
inline constexpr char kRCCoupExtractTagV3[] = "BTX_RC_COUP_EXTRACT_V3";
inline constexpr char kRCCoupFullBankTagV3[] = "BTX_RC_COUP_FULL_BANK_V3";
inline constexpr char kRCCoupMaterialExchangeTagV3[] = "BTX_RC_COUP_MAT_XCHG_V3";
/**
 * Domain tag for digest-affecting V3 material-exchange rounds (XOR keystream +
 * balanced lane permutation). Used only when exchange_rounds > 0; V1/V2 paths
 * with exchange_rounds=0 never touch this tag (goldens preserved).
 */
inline constexpr char kRCCoupMaterialExchangeRoundsTag[] =
    "BTX_RC_COUP_MAT_XCHG_ROUNDS_V3";

/** One versioned coupled domain-tag family (pointers into the constexprs above). */
struct RCCoupDomainTagSet {
    const char* episode{kRCCoupEpisodeTag};
    const char* bank{kRCCoupBankTag};
    const char* lobe{kRCCoupLobeTag};
    const char* barrier{kRCCoupBarrierTag};
    const char* perm{kRCCoupPermTag};
    const char* mix{kRCCoupMixTag};
    const char* extract{kRCCoupExtractTag};
    const char* full_bank{kRCCoupFullBankTag};
    const char* exchange{kRCCoupMaterialExchangeTag};
    const char* exchange_rounds{kRCCoupMaterialExchangeRoundsTag};
};

/** Select coupled domain tags by transcript_version (1/2/3). Unknown → V1. */
[[nodiscard]] const RCCoupDomainTagSet& RCCoupDomainTagsForVersion(uint32_t transcript_version);
/**
 * Parametric coupled-puzzle shape. Toy defaults match the frozen constexprs
 * above (golden digest byte-identical). Medium is CI-safe but larger.
 */
struct RCCoupParams {
    uint32_t barriers{kRCCoupRounds};
    uint32_t lobes{kRCCoupLobes};
    uint32_t lobe_width{kRCCoupLobeWidth};
    uint32_t bank_pages{kRCCoupBankPages};
    /** Rows per lobe (GEMM M). V1/V2 = 1; V3 production = 128. */
    uint32_t rows_per_lobe{1};
    /** Pages accumulated per barrier×lobe under full schedule. V2=12; V3=24. */
    uint32_t pages_per_barrier_lobe{dc::kRCCoupPagesPerBarrierLobe};

    /** Active state bytes: lobes × rows_per_lobe × lobe_width (int8). */
    [[nodiscard]] uint32_t StateBytes() const
    {
        return lobes * rows_per_lobe * lobe_width;
    }
};

[[nodiscard]] bool ValidateRCCoupParams(const RCCoupParams& p);
[[nodiscard]] RCCoupParams MakeToyRCCoupParams();
/** CI-safe larger shape: barriers=8, lobes=8, lobe_width=64, bank_pages=32. */
[[nodiscard]] RCCoupParams MakeMediumRCCoupParams();
/**
 * V2 production shape (heights INT32_MAX). Honest sizes:
 *   bank_pages=768, W=8192 → int8 expanded 48 GiB; packed (×17/32) ≈ 25.5 GiB.
 *   rows_per_lobe=1, pages_per_barrier_lobe=12 → 8×8×12 covers 768 once.
 * Do NOT call this a 48 GiB packed floor — consumer 32 GiB can hold packed V2.
 */
[[nodiscard]] RCCoupParams MakeProductionRCCoupParams();

/**
 * V3 production hypothesis (heights INT32_MAX; new domain tags/goldens required
 * before any activation discussion):
 *   M=rows_per_lobe=128, W=8192, bank_pages=1536, pages/slot=24
 *   packed ≈ 51 GiB, int8 expanded 96 GiB, MACs/nonce = 12 TiMAC
 *   coverage 8×8×24 = 1536. Pending TMTO/regeneration audit (may NO-GO).
 */
[[nodiscard]] RCCoupParams MakeProductionV3RCCoupParams();

/**
 * CI-safe ratio-preserving V3 toy (frozen golden separate from V2 medium):
 *   barriers=4, lobes=4, W=64, M=32, bank_pages=64, P=4
 *   coverage 4×4×4 = 64. StateBytes = 8192 (pow2, MX-aligned).
 * Mix uses uint64 wrap (rows_per_lobe ≥ 32) — V2 M=1 digests unchanged.
 */
[[nodiscard]] RCCoupParams MakeMediumV3RCCoupParams();

/**
 * Accumulator overflow bounds (int8 ±127 inputs).
 *
 * After P page-sums of ExactGemmS8S8 (before butterfly), each lane satisfies:
 *   |acc| ≤ P · W · 127²
 * Unnormalized sum/diff butterfly (log₂(n) stages, n=StateBytes) grows by at
 * most n, so a conservative post-mix bound is:
 *   |acc| ≤ P · W · 127² · StateBytes()
 * Documented ring: when rows_per_lobe ≥ 32 the Mix* path uses explicit uint64
 * two's-complement wrap (defined modular arithmetic, no signed int64 UB).
 * V2 (M=1) keeps signed int64 Mix* for digest stability.
 */
inline constexpr int64_t kRCCoupInt8AbsMax = 127;
inline constexpr int64_t kRCCoupInt8ProdAbsMax =
    kRCCoupInt8AbsMax * kRCCoupInt8AbsMax; // 16129

[[nodiscard]] uint64_t MaxRCCoupPageSumAbsBound(const RCCoupParams& p);
[[nodiscard]] uint64_t MaxRCCoupPostMixAbsBound(const RCCoupParams& p);
/** True iff MaxRCCoupPostMixAbsBound(p) ≤ INT64_MAX (magnitude fits signed int64). */
[[nodiscard]] bool RCCoupPostMixFitsInt64(const RCCoupParams& p);
/** V3 mix policy: uint64 wrap when rows_per_lobe ≥ 32 (unless forced off). */
[[nodiscard]] bool RCCoupUseMixU64Wrap(const RCCoupParams& p, bool force_signed = false);

/**
 * Consensus checker/miner dims via -regtestrccoupledprofile × toydims:
 *   profile=2, toy=1 → MakeToyRCCoupParams (V2 CI)
 *   profile=2, toy=0 → MakeMediumRCCoupParams (V2 medium)
 *   profile=3, toy=1 → MakeMediumV3RCCoupParams (V3 CI)
 *   profile=3, toy=0 → MakeProductionV3RCCoupParams (V3 production hypothesis)
 *   otherwise        → zeroed params (ValidateRCCoupParams fails → reject)
 */
[[nodiscard]] RCCoupParams ResolveRCCoupParams(const Consensus::Params& p);

/**
 * Production barrier-loop completeness (C1–C6). True iff ValidateRCCoupParams
 * and barriers ∈ [4, 8] and kRCCoupMixPatterns ≥ 2.
 */
[[nodiscard]] bool RCCoupBarrierLoopComplete(const RCCoupParams& p);

/**
 * Structural total-MAC count (nonce-independent):
 *   rows_per_lobe × pages_per_barrier_lobe × barriers × lobes × W²
 * Checked saturating arithmetic. V3 dims → exactly 12 TiMAC.
 */
[[nodiscard]] uint64_t TotalRCCoupMacs(const RCCoupParams& p);

/** Canonical packed bank bytes: bank_pages × W² × 17/32 (no provider padding). */
[[nodiscard]] uint64_t TotalRCCoupPackedBytes(const RCCoupParams& p);
/** Expanded int8 bank bytes: bank_pages × W². */
[[nodiscard]] uint64_t TotalRCCoupExpandedBytes(const RCCoupParams& p);

/**
 * Soft peak-bytes estimate for Streamed mode (one page + active state + int64
 * accumulator). Not a production HBM proof — used by soft budget / mem-cap tests.
 */
[[nodiscard]] uint64_t EstimateRCCoupStreamedPeakBytes(const RCCoupParams& p);

/**
 * Soft peak-bytes estimate for Resident mode (full *expanded int8* bank + state
 * + int64 acc). Prefer TotalRCCoupPackedBytes for the consensus memory floor.
 */
[[nodiscard]] uint64_t EstimateRCCoupResidentPeakBytes(const RCCoupParams& p);

/**
 * SHA256d fingerprint of the parametric shape (not a puzzle digest). Used to
 * pin MakeProductionRCCoupParams() on CI without expanding a 48 GiB bank.
 */
[[nodiscard]] uint256 FingerprintRCCoupParams(const RCCoupParams& p);

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

    /**
     * Coupled transcript domain family (F7). Default ENC_RC_V1 preserves frozen
     * V1 toy / V2 medium goldens. V3 MUST set ENC_RC_V3 (MakeV3RCCoupOptions).
     */
    uint32_t transcript_version{ENC_RC_V1};

    /** Test-only shortcut hooks (C4 / H). Consensus path leaves these false. */
    bool skip_barrier{false};
    uint32_t skip_barrier_index{0};
    bool skip_bank_page{false};
    uint32_t skip_page_index{0};

    /**
     * Full-bank page schedule. Defaults to dc::kRCCoupFullBankScheduleEnabled
     * (ON — HBM / datacenter thesis). Set false explicitly only for legacy
     * golden / differential harnesses. Digest-breaking vs single-page legacy.
     */
    bool full_bank_schedule{dc::kRCCoupFullBankScheduleEnabled};

    /**
     * Material-exchange domain in the all-to-all mix. Defaults to
     * dc::kRCCoupMaterialExchangeEnabled (ON). Digests absorb exchange_rows.
     * When exchange_rounds==0 this remains a mix-seed tag only (V1/V2 goldens).
     */
    bool material_exchange{dc::kRCCoupMaterialExchangeEnabled};
    uint32_t exchange_rows{dc::kRCCoupExchangeRowsDefault};

    /**
     * Digest-affecting material-exchange rounds after the all-to-all mix.
     * Default 0 preserves V1/V2 goldens. When >0 AND material_exchange, each
     * barrier runs that many rounds of: SHA256d round-seed → XOR keystream
     * over int64 lanes → balanced lane permutation (see
     * kRCCoupMaterialExchangeRoundsTag). V3 uses MakeV3RCCoupOptions() (=4).
     */
    uint32_t exchange_rounds{0};
    /** When true, force signed int64 Mix even if rows_per_lobe≥32 (tests). */
    bool force_signed_mix{false};
};

/**
 * V3 execution options: transcript_version=ENC_RC_V3 (independent COUP_*_V3
 * domains), material_exchange ON, exchange_rows=128, exchange_rounds=4
 * (~4 GiB R/W at production state size). Pair with MakeProductionV3RCCoupParams()
 * / MakeMediumV3RCCoupParams(); does not raise heights.
 */
[[nodiscard]] RCCoupOptions MakeV3RCCoupOptions();

/**
 * CI medium-V3 options: transcript_version=ENC_RC_V3, exchange_rounds=0.
 * Pins the medium-V3 golden under independent V3 domains + uint64-wrap Mix
 * without the 4-round exchange cost.
 */
[[nodiscard]] RCCoupOptions MakeMediumV3RCCoupOptions();
/**
 * Digest-affecting material-exchange traffic estimate (read+write):
 *   exchange_rounds × barriers × StateBytes() × sizeof(int64_t) × 2
 * Zero when exchange_rounds==0 or material_exchange is off (V1/V2 path).
 * At V3 production dims + MakeV3RCCoupOptions() → exactly 4 GiB.
 */
[[nodiscard]] uint64_t TotalRCCoupExchangeBytes(const RCCoupParams& p,
                                                const RCCoupOptions& options);

/** Optional wall-clock timing for harness / measurement (not consensus). */
struct RCCoupTiming {
    double bank_s{0};
    double barriers_s{0};
    double total_s{0};
};

/**
 * Optional capture of real coupled GEMM + Extract wires for GKR ProveWinnerCoupled.
 * Digests are identical whether or not this is populated (observe-only).
 */
struct RCCoupGemmTranscript {
    uint32_t barrier{0};
    uint32_t lobe{0};
    uint32_t page_id{0};
    std::vector<int8_t> A; // 1×W lobe row
    std::vector<int8_t> B; // W×W bank page
    std::vector<int64_t> Y; // 1×W partial
};

struct RCCoupExtractTranscript {
    uint32_t barrier{0};
    uint256 extract_prf{};
    std::vector<int64_t> extract_in; // post perm+mix
    std::vector<int8_t> extract_out; // active state after Extract
    uint256 barrier_root{};
};

struct RCCoupEpisodeTranscript {
    uint256 bank_root{};
    std::vector<uint256> barrier_roots;
    std::vector<RCCoupGemmTranscript> gemms;
    std::vector<RCCoupExtractTranscript> extracts;
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
 * Optional out_tx captures real layer wires for GKR (does not change digest).
 * Malformed params (ValidateRCCoupParams false) → null digest (reject, no assert).
 */
[[nodiscard]] uint256 RecomputeCoupledPuzzleReference(
    const CBlockHeader& header, int32_t height, const RCCoupParams& params,
    const RCCoupOptions& options = {},
    const matmul::v4::lt::ExactGemmBackend& gemm = {},
    RCCoupTiming* out_timing = nullptr,
    RCCoupEpisodeTranscript* out_tx = nullptr);

/** Miner entry: same digest as the CPU reference; may inject ExactGemm.
 *  Optional out_timing measures this mining path (not the CPU-oracle-only
 *  reference) — harness reports it as wall_s / phase_wall_s. */
[[nodiscard]] uint256 MineCoupledPuzzle(const CBlockHeader& header, int32_t height,
                                        const RCCoupParams& params,
                                        const matmul::v4::lt::ExactGemmBackend& gemm = {},
                                        const RCCoupOptions& options = {},
                                        RCCoupTiming* out_timing = nullptr);

/**
 * Canonical RC bank-template projection — mirrors ComputeTemplateHash.
 *
 * Separates header fields into three roles:
 *   - Template/epoch identity (kept): nVersion, hashPrevBlock, hashMerkleRoot,
 *     nTime, nBits, matmul_dim — resident bank identity across a nonce window.
 *   - Nonce-bound attempt fields (cleared): nNonce, nNonce64, seed_a, seed_b
 *     (§H.4 seeds bind nNonce64; lobes/sigma use the FULL header via DeriveSigma).
 *   - Result fields (cleared for clarity; not in ComputeMatMulHeaderHash):
 *     matmul_digest — must not affect bank identity.
 *
 * RCBankTemplateHash(h) == ComputeTemplateHash(h).
 */
[[nodiscard]] CBlockHeader ProjectRCBankTemplateHeader(const CBlockHeader& header);
[[nodiscard]] uint256 RCBankTemplateHash(const CBlockHeader& header);

/** Epoch/template expert bank (toy params). */
[[nodiscard]] std::vector<std::vector<int8_t>>
DeriveCoupledBankPages(const CBlockHeader& header, int32_t height);

[[nodiscard]] std::vector<std::vector<int8_t>>
DeriveCoupledBankPages(const CBlockHeader& header, int32_t height,
                       const RCCoupParams& params,
                       uint32_t transcript_version = ENC_RC_V1);

/** Single bank page (Streamed path); same seed as DeriveCoupledBankPages[p]. */
[[nodiscard]] std::vector<int8_t>
DeriveCoupledBankPage(const CBlockHeader& header, int32_t height, uint32_t page,
                      const RCCoupParams& params,
                      uint32_t transcript_version = ENC_RC_V1);

/** Nonce-fresh lobe seeds from sigma (C2) — cannot amortize across nonces. */
[[nodiscard]] std::array<uint256, kRCCoupLobes> DeriveCoupledLobeSeeds(const uint256& sigma);

[[nodiscard]] std::vector<uint256> DeriveCoupledLobeSeeds(
    const uint256& sigma, const RCCoupParams& params,
    uint32_t transcript_version = ENC_RC_V1);

/**
 * Nonce-derived balanced permutation π_b over [0, StateBytes).
 * Every output index appears exactly once (bijection). Fixed work — no early exit.
 */
[[nodiscard]] std::array<uint32_t, kRCCoupStateBytes>
DeriveCoupledBalancedPermutation(const uint256& sigma, uint32_t barrier);

[[nodiscard]] std::vector<uint32_t>
DeriveCoupledBalancedPermutation(const uint256& sigma, uint32_t barrier,
                                 const RCCoupParams& params,
                                 uint32_t transcript_version = ENC_RC_V1);

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

/**
 * Stage D parity over one barrier's lobe GEMM partials: consensus segment_id =
 * lobe index (independent of device count). Integer-sum reduce across devices;
 * Extract fires once on the concatenated pre-Extract state. Digests identical
 * across N and DistReduceOrder (mirrors RunSyntheticDistributed discipline).
 */
[[nodiscard]] DistEpisodeResult RunCoupledBarrierDistributed(
    const CBlockHeader& header, int32_t height, const RCCoupParams& params,
    uint32_t barrier, uint32_t n_devices, DistReduceOrder order,
    const matmul::v4::lt::ExactGemmBackend& gemm = {});

/**
 * Bank page IDs for one (barrier, lobe).
 *
 * Legacy (full_bank_schedule=false): single page (barrier+lobe)%bank_pages —
 * current consensus behavior, digest-stable.
 *
 * Full schedule (true): dc::kRCCoupPagesPerBarrierLobe page IDs from a frozen
 * balanced permutation of [0, bank_pages). At production dims
 * 8×8×12 covers all 768 pages exactly once across the episode. Digest-breaking
 * vs legacy — keep OFF on live params (see dc::kRCCoupFullBankScheduleEnabled).
 */
[[nodiscard]] std::vector<uint32_t> SelectCoupledBankPageIds(
    uint32_t barrier, uint32_t lobe, const RCCoupParams& params, const uint256& sigma,
    bool full_bank_schedule = false, uint32_t transcript_version = ENC_RC_V1);

/**
 * Host barrier tail after lobe GEMM partials fill `acc` (int64, StateBytes()).
 * Applies balanced permutation + exact integer all-to-all mix + optional
 * material-exchange rounds + Extract once, writing Extracted active state to
 * `state_out` and optional barrier root.
 * Used by the CUDA resident episode path for PARKED permute/mix/Extract stages
 * (device-native Extract remains unwired). Digests match the CPU oracle when
 * `acc` matches ExactGemmS8S8 lobe partials. Default options keep
 * exchange_rounds=0 (V1/V2 golden-stable).
 */
[[nodiscard]] bool ApplyCoupledBarrierTail(const uint256& sigma, uint32_t barrier,
                                           const RCCoupParams& params,
                                           std::vector<int64_t>& acc,
                                           std::vector<int8_t>& state_out,
                                           uint256* barrier_root_out = nullptr,
                                           const RCCoupOptions& options = {});

/** SHA256d(episode_tag ‖ bank_root ‖ barrier_roots…). Tag follows transcript_version. */
[[nodiscard]] uint256 AssembleCoupledEpisodeDigest(
    const uint256& bank_root, const std::vector<uint256>& barrier_roots,
    uint32_t transcript_version = ENC_RC_V1);

/** Bank commitment over retained pages (same as Sequential/Resident oracle). */
[[nodiscard]] uint256 CommitCoupledBankPages(const std::vector<std::vector<int8_t>>& pages,
                                             const RCCoupParams& params,
                                             uint32_t transcript_version = ENC_RC_V1);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_COUPLED_H
