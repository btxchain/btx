// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_MX_LAYOUT_H
#define BTX_MATMUL_MATMUL_V4_RC_MX_LAYOUT_H

#include <matmul/matmul_v4_rc_extract.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC P1.2 — packed MX layout helpers (CPU).
// Spec: doc/btx-matmul-v4.5-rc-mx-contraction-layouts-p1.2.md
//
// Consensus oracle operands remain ExpandMxDequantInt8 (row-block). These
// helpers retain (μ, e) so a future device MX path can consume the contraction-
// correct axis without inventing a new alphabet mid-consensus.

namespace matmul::v4::rc {

/** E8M0 scale blocking relative to a row-major matrix. */
enum class RCMxScaleAxis : uint8_t {
    /** e[i][⌊j/32⌋] — shared along 32 consecutive columns (LT Extract / MatExpand). */
    RowBlock = 0,
    /** e[⌊i/32⌋][j] — shared along 32 consecutive rows (right operand when K = rows). */
    ColBlock = 1,
};

/** Which RC GEMM stage a packed operand is prepared for (documentation + tests). */
enum class RCMxGemmStage : uint8_t {
    Phase1ScoreQKt = 0, // Q·Kᵀ — both row-block on d_head
    Phase1ValueSV = 1,  // S·V — S row-block; V needs col-block on n_ctx
    Phase2Forward = 2,  // X·Wᵀ — X row-block; Wt col-block (= W row-blockᵀ)
    Phase2Backward = 3, // G·W — G row-block; W needs col-block on d_model
    Phase2Wgrad = 4,    // Gᵀ·X panels — G,X need col-block on b_seq
};

/** Packed M11 mantissas + E8M0 scales (not yet dequantized to int8). */
struct RCMxPacked {
    std::vector<int8_t> mu;      // rows * cols, M11 (|μ|≤6)
    std::vector<uint8_t> scales; // RowBlock: rows*(cols/32); ColBlock: (rows/32)*cols
    uint32_t rows{0};
    uint32_t cols{0};
    RCMxScaleAxis axis{RCMxScaleAxis::RowBlock};
};

[[nodiscard]] inline size_t RCMxScaleCount(uint32_t rows, uint32_t cols, RCMxScaleAxis axis)
{
    const uint32_t L = kRCMxBlockLen;
    if (axis == RCMxScaleAxis::RowBlock) {
        return static_cast<size_t>(rows) * (cols / L);
    }
    return static_cast<size_t>(rows / L) * cols;
}

[[nodiscard]] inline uint8_t RCMxScaleAt(const RCMxPacked& p, uint32_t i, uint32_t j)
{
    const uint32_t L = kRCMxBlockLen;
    if (p.axis == RCMxScaleAxis::RowBlock) {
        const uint32_t nblk = p.cols / L;
        return p.scales[static_cast<size_t>(i) * nblk + (j / L)];
    }
    return p.scales[static_cast<size_t>(i / L) * p.cols + j];
}

/** Expand μ + E8M0 streams with the requested scale axis. Mantissa bytes match
 *  ExpandMxDequantInt8's μ stream; RowBlock scales match ExpandMxDequantInt8. */
[[nodiscard]] RCMxPacked ExpandMxPacked(const uint256& seed, uint32_t rows, uint32_t cols,
                                        RCMxScaleAxis axis);

/** Dense dequant int8: out[i,j] = μ[i,j] · 2^e. RowBlock result is byte-identical
 *  to ExpandMxDequantInt8 for the same seed. */
[[nodiscard]] std::vector<int8_t> DequantMxPacked(const RCMxPacked& packed);

/** Required scale axis for a named stage operand (L or R of C=L·R). */
[[nodiscard]] RCMxScaleAxis RequiredMxScaleAxis(RCMxGemmStage stage, bool left_operand);

/** Stage-specific packed preparations (CPU). Device MX kernels may be stubs. */
[[nodiscard]] RCMxPacked PrepareMxPackedForScoreQ(const uint256& seed_Q, uint32_t n_q,
                                                  uint32_t d_head);
[[nodiscard]] RCMxPacked PrepareMxPackedForScoreK(const uint256& seed_K, uint32_t n_ctx,
                                                  uint32_t d_head);
/** V for S·V: col-block along n_ctx (contraction). NOT digest-equivalent to
 *  ExpandMxDequantInt8(seed_V) until a consensus layout migration. */
[[nodiscard]] RCMxPacked PrepareMxPackedForValueV(const uint256& seed_V, uint32_t n_ctx,
                                                  uint32_t d_head);
[[nodiscard]] RCMxPacked PrepareMxPackedForFwdX(const uint256& seed_X, uint32_t b_seq,
                                                uint32_t d_model);
/** W as right of G·W (backward): col-block along feature rows. */
[[nodiscard]] RCMxPacked PrepareMxPackedForBwdW(const uint256& seed_W, uint32_t d_model);
/** G / X for wgrad panels: col-block along batch (b_seq). */
[[nodiscard]] RCMxPacked PrepareMxPackedForWgradG(const uint256& seed_G, uint32_t b_seq,
                                                  uint32_t d_model);
[[nodiscard]] RCMxPacked PrepareMxPackedForWgradX(const uint256& seed_X, uint32_t b_seq,
                                                  uint32_t d_model);

/**
 * Stub entry for a future device MX GEMM on packed operands.
 * Always returns false in P1.2 (no native_* claim). Keeps the API surface so
 * Phase-1 S·V / Phase-2 bwd / wgrad can call a single hook later.
 */
[[nodiscard]] bool TryDeviceMxGemmPackedStub(const RCMxPacked& left, const RCMxPacked& right,
                                             uint32_t rows, uint32_t inner, uint32_t cols,
                                             std::vector<int32_t>& out);

/** Probe whether Phase-2 ExactGemm can exercise a resolved CUDA/HIP/Metal
 *  device backend (s8×s8 dequant path — not native MX). Never sets native_*. */
struct RCPhase2ExactGemmDeviceProbe {
    bool backend_resolved{false};
    bool device_gemm_returned{false};
    bool matched_cpu_exactgemm{false};
    bool used_tensor_imma_or_mfma{false}; // informational; false when stub/CPU
    std::string provider;                // "cuda" / "hip" / "metal" / "cpu" / …
    std::string detail;
};

[[nodiscard]] RCPhase2ExactGemmDeviceProbe ProbeRCPhase2ExactGemmDevice();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_MX_LAYOUT_H
