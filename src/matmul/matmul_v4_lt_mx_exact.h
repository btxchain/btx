// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MATMUL_MATMUL_V4_LT_MX_EXACT_H
#define BITCOIN_MATMUL_MATMUL_V4_LT_MX_EXACT_H

#include <matmul/matmul_v4_lt.h>

#include <cstdint>
#include <string>
#include <vector>

// Shared exact-MX helpers for ENC-DR-LT miner backends.
//
// Types MxLaneProvenance / ExactMxProjectionBackend live in matmul_v4_lt.h.
// Consensus oracle remains ComputeProjectedRightMxBlockScaleLT.
// Native MXFP4/FP8 may be attempted only behind self-qual; fail-closed otherwise.
// Public activation heights remain INT32_MAX. C-15 remains OPEN.
//
// FP32-exact window (eligibility math, not silicon proof):
//   M11 = {0,±1,±2,±3,±4,±6} → max |μ| = max |V| = 6 (11 symbols, not |x|≤11).
//   e ∈ {0..3} → max 2^e = 8.  Per-MAC |μ·2^e·V| ≤ 6·8·6 = 288.
//   |Q|_ij ≤ 288·n; at n ≤ 4096 → |Q|_max = 1,179,648 < 2^24 = 16,777,216.
//   So every integer Q entry (and every partial sum under any reduction order)
//   is exactly representable in IEEE FP32. This admits native FP32-accumulate
//   MX paths *after* MxProjectionMatchesCpuOracle self-qual — it does not
//   itself set native_*_qualified.

namespace matmul::v4::lt {

/** Real M11 max |μ| / |V| (alphabet size is 11; magnitude ceiling is 6). */
inline constexpr int32_t kLtMxMantissaMaxAbs = 6;
/** E8M0 e ∈ {0,1,2,3} → max power-of-two scale. */
inline constexpr int32_t kLtMxScalePow2Max = 8; // 2^3
/** Per-MAC |Q| contribution: 6 * 8 * 6. Matches bmx4::kProjPerMac. */
inline constexpr int32_t kLtMxProjPerMac =
    kLtMxMantissaMaxAbs * kLtMxScalePow2Max * kLtMxMantissaMaxAbs; // 288
/** IEEE FP32 consecutive-integer ceiling (exclusive gate used here). */
inline constexpr int64_t kLtMxFloat32ExactIntegerCeil = int64_t{1} << 24; // 2^24
/** Production envelope: |Q|_max at n = 4096. */
inline constexpr int64_t kLtMxProjAbsBoundAtN4096 =
    static_cast<int64_t>(kLtMxProjPerMac) * 4096; // 1,179,648

static_assert(kLtMxProjPerMac == 288, "LT MX proj per-MAC must be 6*8*6");
static_assert(kLtMxProjAbsBoundAtN4096 == 1'179'648, "288*4096 pinned");
static_assert(kLtMxProjAbsBoundAtN4096 < kLtMxFloat32ExactIntegerCeil,
              "LT MX |Q| at n=4096 must sit strictly below 2^24");

/** Worst-case |Q|_ij bound: 288·n (independent of m; m is API/dims only). */
[[nodiscard]] inline constexpr int64_t LtMxProjectionAbsBound(uint32_t n)
{
    return static_cast<int64_t>(kLtMxProjPerMac) * static_cast<int64_t>(n);
}

/** True iff the LT MX right-projection envelope for contraction length `n`
 *  fits in the FP32 exact-integer window (|Q|_max < 2^24). `m` is unused in
 *  the magnitude proof but retained so call sites pass validated (n,m). */
[[nodiscard]] bool LtMxProjectionFitsFloat32ExactInteger(uint32_t n, uint32_t m);

/** Exact GEMM-shaped form of the MX right projection: for each e in {0,1,2,3},
 *  gather mantissa rows/cols where scale==e, run ExactGemmS8S8(mu_e, V),
 *  add (result << e). Bit-identical to ComputeProjectedRightMxBlockScaleLT.
 *  Use as the CPU gold for device scale-partitioned IMMA/MFMA/Cube lowerings. */
[[nodiscard]] std::vector<int32_t> ComputeProjectedRightMxScalePartitionedGemmLT(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m,
    const ExactGemmBackend& gemm = {});

/** True iff `got` matches ComputeProjectedRightMxBlockScaleLT byte-for-byte. */
[[nodiscard]] bool MxProjectionMatchesCpuOracle(const std::vector<int8_t>& mu,
                                                const std::vector<uint8_t>& scales,
                                                const std::vector<int8_t>& V, uint32_t n,
                                                uint32_t m, const std::vector<int32_t>& got);

/** Dispatch helper: device backend if set and successful, else CPU oracle.
 *  On device failure, falls back to CPU and clears qualified native flags. */
[[nodiscard]] std::vector<int32_t> ComputeProjectedRightMxDispatched(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m,
    const ExactMxProjectionBackend& backend = {}, MxLaneProvenance* provenance = nullptr);

/** CPU reference: Q via left-to-right float32 accumulate of (μ·2^e)·V products,
 *  then exact float→int32 cast. For self-check vs the int32 oracle inside the
 *  FP32-exact window — not a native silicon path and never sets qualified flags. */
[[nodiscard]] std::vector<int32_t> SimulateProjectedRightMxFloat32AccumulateLT(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m);

/** True for env values 1/true/yes/on (case-insensitive). Missing → false. */
[[nodiscard]] bool LtEnvFlagEnabled(const char* name);

/**
 * Peak-performance policy (default = keep the exact resident path available):
 *   On Blackwell / CDNA4-class GPUs, qualified native MXFP4/MXFP8 is preferred
 *   and reported separately. If it declines, the bit-exact INT8 MX resident
 *   path remains enabled; native qualification is a performance/readiness fact,
 *   not a consensus prerequisite.
 *
 * Explicit qualification mode:
 *   BTX_MATMUL_V4_LT_REQUIRE_NATIVE_MX=1
 *     blocks the resident lane on peak-capable devices unless a native lane
 *     self-qualifies. This is intended for native-path qualification, not
 *     ordinary mining. The legacy ALLOW_EXACT_MX_FALLBACK=1 flag overrides it.
 */
[[nodiscard]] bool AllowLtExactMxFallback();

/** Log an already-rendered accelerator diagnostic from an ordinary C++ TU.
 *  CUDA/HIP compiler frontends must not instantiate logging.h's consteval
 *  format-string machinery in .cu/.hip translation units. */
void LogLtMxDiagnostic(const std::string& message);

/** Snapshot used by report JSON + startup diagnostics. */
struct LtPeakMxPathStatus {
    bool peak_capable{false};             // sm_100/120 or gfx950-class
    bool native_mxfp4_attempted{false};   // self-qual invoked vendor MXFP4 surface
    bool native_mxfp4_qualified{false};
    bool native_fp8_attempted{false};     // self-qual invoked vendor block-FP8 surface
    bool native_fp8_qualified{false};
    bool resident_native_mx_wired{false}; // native lane is in the resident Q* graph
    bool peak_ready{false};               // capable && qualified && resident-wired
    bool allow_exact_mx_fallback{true};   // default; false only in native-only mode
    bool peak_required{false};            // capable && explicit native-only mode
    bool blocks_device_resident{false};   // peak_required && !peak_ready
    std::string deficit_reason;           // empty when peak_ready or !peak_capable
};

} // namespace matmul::v4::lt

#endif // BITCOIN_MATMUL_MATMUL_V4_LT_MX_EXACT_H
