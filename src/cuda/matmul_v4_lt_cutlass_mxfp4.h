// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_LT_CUTLASS_MXFP4_H
#define BITCOIN_CUDA_MATMUL_V4_LT_CUTLASS_MXFP4_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// LT-specific CUTLASS SM120 OCP MXFP4 attempt for ComputeProjectedRightMx.
//
// Target layout (OCP MX / Colfax + CUTLASS example 79c / mx_float4_t):
//   * Element: E2M1 (float_e2m1_t), two nibbles per byte
//   * Scale:   UE8M0 (float_ue8m0_t), one scale per 32 K-elements
//   * Arch:    Sm120 + OpClassBlockScaledTensorOp (GeForce Blackwell)
//
// BTX Lever-B already stores (μ ∈ M11, e ∈ {0..3}) on 32-column blocks — the
// same abstract object as OCP MXFP4. This TU packs that object into CUTLASS's
// MX layout and may launch a block-scaled GEMM. Admission requires byte-identity
// with ComputeProjectedRightMxBlockScaleLT (MxProjectionMatchesCpuOracle).
//
// Fail-closed without CUTLASS headers / SM120 recipe / self-qual. Never raises
// activation heights. Compiling this TU alone does not set native_mxfp4_qualified.

namespace matmul_v4::cuda::lt_cutlass_mxfp4 {

inline constexpr uint32_t kBlockLen = 32;
inline constexpr uint32_t kNumScaleCodes = 4;
/** OCP UE8M0 bias: stored byte b means scale 2^(b - 127). */
inline constexpr uint8_t kUe8m0Bias = 127;

/** μ ∈ M11 → pinned E2M1 nibble (inverse of SampleMantissaNibble). 0xFF = reject. */
[[nodiscard]] inline uint8_t EncodeE2M1Nibble(int8_t mu)
{
    switch (mu) {
    case 0: return 0x0;
    case 1: return 0x2;
    case -1: return 0xA;
    case 2: return 0x4;
    case -2: return 0xC;
    case 3: return 0x5;
    case -3: return 0xD;
    case 4: return 0x6;
    case -4: return 0xE;
    case 6: return 0x7;
    case -6: return 0xF;
    default: return 0xFF;
    }
}

/** BTX power-of-two code e ∈ {0..3} → UE8M0 byte (2^e). */
[[nodiscard]] inline uint8_t EncodeUe8m0FromBtXScale(uint8_t e)
{
    if (e >= kNumScaleCodes) return 0;
    return static_cast<uint8_t>(kUe8m0Bias + e);
}

inline void PackNibble(uint8_t* buf, size_t idx, uint8_t nib)
{
    if (idx & 1U) {
        buf[idx >> 1] = static_cast<uint8_t>(buf[idx >> 1] | static_cast<uint8_t>(nib << 4));
    } else {
        buf[idx >> 1] = static_cast<uint8_t>(buf[idx >> 1] | nib);
    }
}

/** Bytes for a VEC32 UE8M0 scale tensor with Sm1xx-style 128×4 tile padding. */
[[nodiscard]] inline size_t BlkScaledScaleBytes(size_t outer, size_t K)
{
    const size_t rows = ((outer + 127) / 128) * 128;
    const size_t kblocks = (K + 31) / 32;
    const size_t cols = ((kblocks + 3) / 4) * 4;
    return rows * cols;
}

/**
 * Pack LT right-projection operands into OCP MXFP4 / CUTLASS TN layout:
 *   A (μ): M=n, K=n, row-major E2M1, SFA[row][k/32] = UE8M0(e)
 *   B (V): K=n, N=m, K-major E2M1 (index c*n+j ← V[j][c]), SFB = unit (0x7F)
 *
 * Returns false (and sets error) on size/scale/M11 violations — fail closed.
 */
[[nodiscard]] inline bool PackProjectedRightMxToCutlassMxfp4(
    const int8_t* mu, const uint8_t* scales, const int8_t* V, uint32_t n, uint32_t m,
    std::vector<uint8_t>& a_e2m1, std::vector<uint8_t>& b_e2m1,
    std::vector<uint8_t>& sfa_ue8m0, std::vector<uint8_t>& sfb_ue8m0, std::string& error)
{
    if (mu == nullptr || scales == nullptr || V == nullptr) {
        error = "PackProjectedRightMxToCutlassMxfp4: null operand";
        return false;
    }
    if (n == 0 || m == 0 || (n % kBlockLen) != 0) {
        error = "PackProjectedRightMxToCutlassMxfp4: n must be a positive multiple of 32";
        return false;
    }
    const uint32_t nblk = n / kBlockLen;
    const size_t a_elems = static_cast<size_t>(n) * n;
    const size_t b_elems = static_cast<size_t>(n) * m;

    a_e2m1.assign((a_elems + 1) / 2, 0);
    b_e2m1.assign((b_elems + 1) / 2, 0);
    // Pad unused Sm1xx scale slots with unit UE8M0 (0x7F = 2^0), matching the
    // BMX4C native packer — never leave raw zeros (2^-127) in the canvas.
    sfa_ue8m0.assign(BlkScaledScaleBytes(n, n), kUe8m0Bias);
    sfb_ue8m0.assign(BlkScaledScaleBytes(m, n), kUe8m0Bias);

    const size_t sfa_cols = ((static_cast<size_t>(nblk) + 3) / 4) * 4;
    for (uint32_t i = 0; i < n; ++i) {
        const size_t mu_row = static_cast<size_t>(i) * n;
        const size_t sc_row = static_cast<size_t>(i) * nblk;
        for (uint32_t j = 0; j < n; ++j) {
            const uint8_t nib = EncodeE2M1Nibble(mu[mu_row + j]);
            if (nib > 0x0F) {
                error = "PackProjectedRightMxToCutlassMxfp4: mu not in M11/E2M1";
                return false;
            }
            PackNibble(a_e2m1.data(), mu_row + j, nib);
        }
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            const uint8_t e = scales[sc_row + bj];
            if (e >= kNumScaleCodes) {
                error = "PackProjectedRightMxToCutlassMxfp4: scale code out of range";
                return false;
            }
            // Linear (row, kblock) into the padded scale canvas; Sm1xx atom
            // swizzle is applied by the CUTLASS recipe when linked.
            sfa_ue8m0[static_cast<size_t>(i) * sfa_cols + bj] = EncodeUe8m0FromBtXScale(e);
        }
    }

    for (uint32_t c = 0; c < m; ++c) {
        for (uint32_t j = 0; j < n; ++j) {
            const uint8_t nib = EncodeE2M1Nibble(V[static_cast<size_t>(j) * m + c]);
            if (nib > 0x0F) {
                error = "PackProjectedRightMxToCutlassMxfp4: V not in M11/E2M1";
                return false;
            }
            PackNibble(b_e2m1.data(), static_cast<size_t>(c) * n + j, nib);
        }
    }

    error.clear();
    return true;
}

/**
 * Convert FP32 block-scaled GEMM output to int32. Requires every finite value
 * to be an exact integer in int32 range; otherwise fail closed (no rounding).
 */
[[nodiscard]] inline bool Fp32OutputToExactInt32(const float* src, size_t count,
                                                 std::vector<int32_t>& out, std::string& error)
{
    if (src == nullptr) {
        error = "Fp32OutputToExactInt32: null";
        return false;
    }
    out.resize(count);
    for (size_t i = 0; i < count; ++i) {
        const float v = src[i];
        if (!(v == v) || v > 2147483647.0f || v < -2147483648.0f) {
            error = "Fp32OutputToExactInt32: non-finite or out of int32 range";
            return false;
        }
        const int32_t truncated = static_cast<int32_t>(v);
        if (static_cast<float>(truncated) != v) {
            error = "Fp32OutputToExactInt32: non-integral FP32 element";
            return false;
        }
        out[i] = truncated;
    }
    error.clear();
    return true;
}

/** True when the LT CUTLASS MXFP4 TU was compiled with CUTLASS headers. */
[[nodiscard]] bool IsLtCutlassMxfp4Compiled();

/** True only after headers + a real SM120 OCP recipe + process-local oracle self-qual. */
[[nodiscard]] bool IsLtCutlassMxfp4Linked();

/**
 * Attempt CUTLASS SM120 OCP MXFP4 B̂·V. On success `out` is byte-identical to
 * ComputeProjectedRightMxBlockScaleLT. Otherwise returns false (fail closed).
 */
[[nodiscard]] bool TryLaunchCutlassMxfp4ProjectedRight(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    std::string* error = nullptr);

} // namespace matmul_v4::cuda::lt_cutlass_mxfp4

#endif // BITCOIN_CUDA_MATMUL_V4_LT_CUTLASS_MXFP4_H
