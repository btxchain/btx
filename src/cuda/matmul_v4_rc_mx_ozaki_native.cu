// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_mx_ozaki_native.h>

#include <cuda/matmul_v4_lt_accel.h>
#include <cuda/matmul_v4_lt_cutlass_mxfp4.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>

#include <cuda_runtime.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

// cuBLASLt block-scaled FP4 (same toolkit gate as LT matmul_v4_lt_mx_native.cu).
#if defined(CUDART_VERSION) && (CUDART_VERSION >= 12080)
#include <cublasLt.h>
#if defined(__has_include)
#if __has_include(<cuda_fp4.h>)
#include <cuda_fp4.h>
#define BTX_RC_OZAKI_HAS_FP4_E2M1 1
#endif
#endif
#define BTX_RC_OZAKI_HAS_VEC32_UE8M0 1
#define BTX_RC_OZAKI_HAS_MX_SCALE_MODES 1
#endif

namespace matmul_v4::cuda {
namespace {

using matmul_v4::cuda::lt_cutlass_mxfp4::EncodeE2M1Nibble;
using matmul_v4::cuda::lt_cutlass_mxfp4::EncodeUe8m0FromBtXScale;
using matmul_v4::cuda::lt_cutlass_mxfp4::Fp32OutputToExactInt32;
using matmul_v4::cuda::lt_cutlass_mxfp4::kUe8m0Bias;
using matmul_v4::cuda::lt_cutlass_mxfp4::PackNibble;

/** OCP MX block length (32) — host+device visible. */
constexpr uint32_t kMxBlk = 32;

std::mutex g_ozaki_mu;

// ExactGemm IMMA panel latch (not native MXFP4).
bool g_exact_ran{false};
bool g_exact_qualified{false};

// Native MXFP4 — separate arch latches (sm_120 ≠ sm_100).
bool g_mx_ran{false};
bool g_qual_sm120{false};
bool g_qual_sm100{false};
std::string g_mx_arch_key;
std::string g_mx_backend;
std::string g_mx_deficit;

[[nodiscard]] bool DeviceLooksSm120(int major, int /*minor*/)
{
    return major == 12;
}

[[nodiscard]] bool DeviceLooksSm100(int major, int /*minor*/)
{
    return major == 10;
}

[[nodiscard]] std::string FormatCudaArchKey(int major, int minor)
{
    return "sm_" + std::to_string(major) + std::to_string(minor);
}

[[nodiscard]] bool IsM11(int32_t mu)
{
    switch (mu) {
    case 0:
    case 1:
    case -1:
    case 2:
    case -2:
    case 3:
    case -3:
    case 4:
    case -4:
    case 6:
    case -6:
        return true;
    default:
        return false;
    }
}

/** Factor one K-block of int8 dequants into shared e ∈ {0..3} + M11 mantissas. */
[[nodiscard]] bool FactorBlockToMx(const int8_t* vals, uint32_t n, uint8_t& e_out,
                                   int8_t* mu_out)
{
    for (int e = 3; e >= 0; --e) {
        const int32_t scale = 1 << e;
        bool ok = true;
        for (uint32_t i = 0; i < n; ++i) {
            const int32_t v = static_cast<int32_t>(vals[i]);
            if ((v % scale) != 0) {
                ok = false;
                break;
            }
            const int32_t mu = v / scale;
            if (!IsM11(mu)) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        e_out = static_cast<uint8_t>(e);
        for (uint32_t i = 0; i < n; ++i) {
            mu_out[i] = static_cast<int8_t>(static_cast<int32_t>(vals[i]) / scale);
        }
        for (uint32_t i = n; i < kMxBlk; ++i) mu_out[i] = 0;
        return true;
    }
    return false;
}

/**
 * Pack MX-dequant-shaped int8 panels into E2M1 + UE8M0 (K-block scales).
 * Left: rows×K row-major. Right: K×cols row-major.
 */
[[nodiscard]] bool FactorInt8ToMxM11E8M0(const std::vector<int8_t>& left,
                                        const std::vector<int8_t>& right, uint32_t rows,
                                        uint32_t K, uint32_t cols, std::vector<uint8_t>& a_e2m1,
                                        std::vector<uint8_t>& b_e2m1,
                                        std::vector<uint8_t>& sfa_ue8m0,
                                        std::vector<uint8_t>& sfb_ue8m0, uint32_t& kblocks_out,
                                        std::string* error)
{
    if (rows == 0 || K == 0 || cols == 0) {
        if (error) *error = "FactorInt8ToMxM11E8M0: degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * K ||
        right.size() != static_cast<size_t>(K) * cols) {
        if (error) *error = "FactorInt8ToMxM11E8M0: size mismatch";
        return false;
    }
    const uint32_t kblocks = (K + kMxBlk - 1u) / kMxBlk;
    kblocks_out = kblocks;
    const size_t a_elems = static_cast<size_t>(rows) * K;
    const size_t b_elems = static_cast<size_t>(K) * cols;
    a_e2m1.assign((a_elems + 1) / 2, 0);
    b_e2m1.assign((b_elems + 1) / 2, 0);
    sfa_ue8m0.assign(static_cast<size_t>(rows) * kblocks, kUe8m0Bias);
    sfb_ue8m0.assign(static_cast<size_t>(cols) * kblocks, kUe8m0Bias);

    int8_t mu_tmp[kMxBlk];
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = left[static_cast<size_t>(r) * K + (k0 + t)];
            }
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "FactorInt8ToMxM11E8M0: left block not MX-factorable";
                return false;
            }
            sfa_ue8m0[static_cast<size_t>(r) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "FactorInt8ToMxM11E8M0: left mu not E2M1";
                    return false;
                }
                PackNibble(a_e2m1.data(), static_cast<size_t>(r) * K + (k0 + t), nib);
            }
        }
    }

    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = right[static_cast<size_t>(k0 + t) * cols + c];
            }
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "FactorInt8ToMxM11E8M0: right block not MX-factorable";
                return false;
            }
            sfb_ue8m0[static_cast<size_t>(c) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "FactorInt8ToMxM11E8M0: right mu not E2M1";
                    return false;
                }
                PackNibble(b_e2m1.data(), static_cast<size_t>(k0 + t) * cols + c, nib);
            }
        }
    }
    return true;
}

__device__ __forceinline__ int8_t DecodeE2M1NibbleDevice(uint8_t nib)
{
    switch (nib & 0x0Fu) {
    case 0x0: return 0;
    case 0x2: return 1;
    case 0xA: return -1;
    case 0x4: return 2;
    case 0xC: return -2;
    case 0x5: return 3;
    case 0xD: return -3;
    case 0x6: return 4;
    case 0xE: return -4;
    case 0x7: return 6;
    case 0xF: return -6;
    default: return 0;
    }
}

__device__ __forceinline__ uint8_t LoadNibble(const uint8_t* pack, size_t idx)
{
    const uint8_t byte = pack[idx >> 1];
    return (idx & 1u) ? static_cast<uint8_t>((byte >> 4) & 0x0Fu)
                      : static_cast<uint8_t>(byte & 0x0Fu);
}

/** Block-scaled E2M1 GEMM → FP32 (honest MXFP4 datatype path; not IMMA INT8). */
__global__ void rc_ozaki_mxfp4_panel_gemm(const uint8_t* a_e2m1, const uint8_t* b_e2m1,
                                          const uint8_t* sfa, const uint8_t* sfb, float* out,
                                          uint32_t rows, uint32_t K, uint32_t cols,
                                          uint32_t kblocks)
{
    const uint32_t r = blockIdx.y * blockDim.y + threadIdx.y;
    const uint32_t c = blockIdx.x * blockDim.x + threadIdx.x;
    if (r >= rows || c >= cols) return;
    float acc = 0.f;
    for (uint32_t k = 0; k < K; ++k) {
        const uint32_t bj = k / kMxBlk;
        const int ea = static_cast<int>(sfa[static_cast<size_t>(r) * kblocks + bj]) - 127;
        const int eb = static_cast<int>(sfb[static_cast<size_t>(c) * kblocks + bj]) - 127;
        const float sa = ldexpf(1.f, ea);
        const float sb = ldexpf(1.f, eb);
        const size_t a_idx = static_cast<size_t>(r) * K + k;
        const size_t b_idx = static_cast<size_t>(k) * cols + c;
        const int8_t mu_a = DecodeE2M1NibbleDevice(LoadNibble(a_e2m1, a_idx));
        const int8_t mu_b = DecodeE2M1NibbleDevice(LoadNibble(b_e2m1, b_idx));
        acc += static_cast<float>(mu_a) * sa * static_cast<float>(mu_b) * sb;
    }
    out[static_cast<size_t>(r) * cols + c] = acc;
}

/**
 * SM120a native MXFP4 TC: mma.sync kind::mxf8f6f4.block_scale m16n8k32 e2m1×e2m1.
 * A: M×K row-major, one e2m1 per byte in bits 5-2 (nibble<<2). B: K×N row-major.
 * SFA/SFB: UE8M0 per (row/col, K/32). Empirically-validated fragment layout (QMMA.SF).
 */
__device__ __forceinline__ void RcOzakiMmaMxfp4M16N8K32(float& d0, float& d1, float& d2, float& d3,
                                                         uint32_t a0, uint32_t a1, uint32_t a2,
                                                         uint32_t a3, uint32_t b0, uint32_t b1,
                                                         uint32_t sfa, uint32_t sfb)
{
#if defined(__CUDA_ARCH__) && (__CUDA_ARCH__ >= 1200)
    uint16_t z = 0;
    asm volatile(
        "mma.sync.aligned.kind::mxf8f6f4.block_scale.scale_vec::1X.m16n8k32.row.col.f32.e2m1.e2m1.f32.ue8m0 "
        "{%0,%1,%2,%3},{%4,%5,%6,%7},{%8,%9},{%10,%11,%12,%13},{%14},{%15,%16},{%17},{%18,%19};\n"
        : "=f"(d0), "=f"(d1), "=f"(d2), "=f"(d3)
        : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(b0), "r"(b1), "f"(d0), "f"(d1), "f"(d2), "f"(d3),
          "r"(sfa), "h"(z), "h"(z), "r"(sfb), "h"(z), "h"(z));
#else
    (void)a0;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)b0;
    (void)b1;
    (void)sfa;
    (void)sfb;
    d0 = d1 = d2 = d3 = 0.f;
#endif
}

__device__ __forceinline__ uint32_t RcOzakiPack4Bytes(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

__global__ void rc_ozaki_mxfp4_mma_gemm(const uint8_t* __restrict__ A, const uint8_t* __restrict__ B,
                                        const uint8_t* __restrict__ SFa,
                                        const uint8_t* __restrict__ SFb, float* __restrict__ C,
                                        int M, int N, int K, int kblocks)
{
    const int lane = static_cast<int>(threadIdx.x) & 31;
    const int bm = static_cast<int>(blockIdx.y) * 16;
    const int bn = static_cast<int>(blockIdx.x) * 8;
    const int row0 = lane / 4;
    const int ksub = lane % 4;

    float d0 = 0.f, d1 = 0.f, d2 = 0.f, d3 = 0.f;
    for (int kb = 0; kb < kblocks; ++kb) {
        const int k0 = kb * 32;
        auto loadA = [&](int row, int kbase) -> uint32_t {
            if (bm + row >= M) return 0u;
            return RcOzakiPack4Bytes(A + static_cast<size_t>(bm + row) * static_cast<size_t>(K) +
                                     static_cast<size_t>(k0 + kbase));
        };
        const uint32_t a0 = loadA(row0, ksub * 4);
        const uint32_t a1 = loadA(row0 + 8, ksub * 4);
        const uint32_t a2 = loadA(row0, 16 + ksub * 4);
        const uint32_t a3 = loadA(row0 + 8, 16 + ksub * 4);

        auto loadB = [&](int col, int kbase) -> uint32_t {
            if (bn + col >= N) return 0u;
            uint8_t tmp[4];
            for (int i = 0; i < 4; ++i) {
                tmp[i] = B[static_cast<size_t>(k0 + kbase + i) * static_cast<size_t>(N) +
                           static_cast<size_t>(bn + col)];
            }
            return RcOzakiPack4Bytes(tmp);
        };
        const uint32_t b0 = loadB(row0, ksub * 4);
        const uint32_t b1 = loadB(row0, 16 + ksub * 4);

        uint32_t sfa = 127u, sfb = 127u;
        if ((lane % 4) == 0) {
            const int r = bm + row0;
            if (r < M) sfa = SFa[static_cast<size_t>(r) * static_cast<size_t>(kblocks) + kb];
            const int c = bn + row0;
            if (c < N) sfb = SFb[static_cast<size_t>(c) * static_cast<size_t>(kblocks) + kb];
        } else if ((lane % 4) == 1) {
            const int r = bm + row0 + 8;
            if (r < M) sfa = SFa[static_cast<size_t>(r) * static_cast<size_t>(kblocks) + kb];
        }
        RcOzakiMmaMxfp4M16N8K32(d0, d1, d2, d3, a0, a1, a2, a3, b0, b1, sfa, sfb);
    }

    const int col0 = (lane % 4) * 2;
    auto store = [&](int row, int col, float v) {
        if (bm + row < M && bn + col < N) {
            C[static_cast<size_t>(bm + row) * static_cast<size_t>(N) + static_cast<size_t>(bn + col)] =
                v;
        }
    };
    store(row0, col0, d0);
    store(row0, col0 + 1, d1);
    store(row0 + 8, col0, d2);
    store(row0 + 8, col0 + 1, d3);
}

[[nodiscard]] bool LaunchOzakiExactPanels(const std::vector<int8_t>& left,
                                          const std::vector<int8_t>& right, uint32_t rows,
                                          uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                          std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki ExactPanels degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki ExactPanels operand size mismatch";
        return false;
    }

    using matmul::v4::rc::kRCOzakiExactChunk;
    if (!IsMatMulLTCudaAvailable()) {
        if (error) *error = "CUDA LT GEMM unavailable (no device / self-test failed)";
        return false;
    }

    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t k0 = 0; k0 < inner; k0 += kRCOzakiExactChunk) {
        const uint32_t len = std::min(kRCOzakiExactChunk, inner - k0);
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * len);
        std::vector<int8_t> Rpanel(static_cast<size_t>(len) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < len; ++t) {
                Lpanel[static_cast<size_t>(r) * len + t] =
                    left[static_cast<size_t>(r) * inner + (k0 + t)];
            }
        }
        for (uint32_t t = 0; t < len; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k0 + t) * cols + c];
            }
        }

        std::vector<int32_t> partial;
        if (!LaunchGemmS8S8(Lpanel, Rpanel, rows, len, cols, partial) ||
            partial.size() != out.size()) {
            out.clear();
            if (error) *error = "LaunchGemmS8S8 Ozaki ExactPanels failed";
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    return true;
}

/** cuBLASLt 1D block-scale layout (VEC32_UE8M0) — mirrors LT native packer. */
[[nodiscard]] size_t BlockScaleTensorBytes(size_t outer, size_t K, size_t vec)
{
    const size_t rows = ((outer + 127u) / 128u) * 128u;
    const size_t kblocks = (K + vec - 1u) / vec;
    const size_t cols = ((kblocks + 3u) / 4u) * 4u;
    return rows * cols;
}

[[nodiscard]] size_t BlockScaleOffset(size_t r, size_t c, size_t K, size_t vec)
{
    const size_t kblocks = (K + vec - 1u) / vec;
    const size_t cols = ((kblocks + 3u) / 4u) * 4u;
    const size_t n_k_tiles = cols / 4u;
    return (r % 32u) * 16u + ((r % 128u) / 32u) * 4u + (c % 4u) + (c / 4u) * 512u +
           (r / 128u) * 512u * n_k_tiles;
}

[[nodiscard]] uint32_t AlignUp(uint32_t v, uint32_t a)
{
    return (v + a - 1u) / a * a;
}

/**
 * Factor int8 panels → M11 μ + BTX e∈{0..3}, then pack cuBLASLt TN:
 *   A: K×M E2M1 (ld=K), B: K×N E2M1 (ld=K), SFA/SFB: VEC32_UE8M0 swizzle.
 * Pads K/M/N to multiples of 32 so VEC32 + Blackwell heuristics admit.
 */
[[nodiscard]] bool PackOzakiPanelsCublasLtFp4(const std::vector<int8_t>& Lpanel,
                                              const std::vector<int8_t>& Rpanel, uint32_t rows,
                                              uint32_t K, uint32_t cols,
                                              std::vector<uint8_t>& A_pack,
                                              std::vector<uint8_t>& B_pack,
                                              std::vector<uint8_t>& SFa,
                                              std::vector<uint8_t>& SFb, uint32_t& Mpad,
                                              uint32_t& Npad, uint32_t& Kpad, std::string* error)
{
    if (rows == 0 || K == 0 || cols == 0) {
        if (error) *error = "PackOzakiPanelsCublasLtFp4: degenerate";
        return false;
    }
    Mpad = AlignUp(rows, kMxBlk);
    Npad = AlignUp(cols, kMxBlk);
    Kpad = AlignUp(K, kMxBlk);
    const uint32_t kblocks = Kpad / kMxBlk;

    A_pack.assign((static_cast<size_t>(Kpad) * Mpad + 1u) / 2u, 0);
    B_pack.assign((static_cast<size_t>(Kpad) * Npad + 1u) / 2u, 0);
    SFa.assign(BlockScaleTensorBytes(Mpad, Kpad, kMxBlk), kUe8m0Bias);
    SFb.assign(BlockScaleTensorBytes(Npad, Kpad, kMxBlk), kUe8m0Bias);

    int8_t mu_tmp[kMxBlk];
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = (k0 >= K) ? 0u : std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = Lpanel[static_cast<size_t>(r) * K + (k0 + t)];
            }
            uint8_t e = 0;
            if (n > 0) {
                if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                    if (error) *error = "PackOzakiPanelsCublasLtFp4: left not MX-factorable";
                    return false;
                }
            } else {
                std::memset(mu_tmp, 0, sizeof(mu_tmp));
            }
            SFa[BlockScaleOffset(r, bj, Kpad, kMxBlk)] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < kMxBlk; ++t) {
                const int8_t mu = (t < n) ? mu_tmp[t] : int8_t{0};
                const uint8_t nib = EncodeE2M1Nibble(mu);
                if (nib > 0x0F) {
                    if (error) *error = "PackOzakiPanelsCublasLtFp4: left mu not E2M1";
                    return false;
                }
                PackNibble(A_pack.data(), static_cast<size_t>(k0 + t) + static_cast<size_t>(r) * Kpad,
                           nib);
            }
        }
    }
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = (k0 >= K) ? 0u : std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = Rpanel[static_cast<size_t>(k0 + t) * cols + c];
            }
            uint8_t e = 0;
            if (n > 0) {
                if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                    if (error) *error = "PackOzakiPanelsCublasLtFp4: right not MX-factorable";
                    return false;
                }
            } else {
                std::memset(mu_tmp, 0, sizeof(mu_tmp));
            }
            SFb[BlockScaleOffset(c, bj, Kpad, kMxBlk)] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < kMxBlk; ++t) {
                const int8_t mu = (t < n) ? mu_tmp[t] : int8_t{0};
                const uint8_t nib = EncodeE2M1Nibble(mu);
                if (nib > 0x0F) {
                    if (error) *error = "PackOzakiPanelsCublasLtFp4: right mu not E2M1";
                    return false;
                }
                PackNibble(B_pack.data(), static_cast<size_t>(k0 + t) + static_cast<size_t>(c) * Kpad,
                           nib);
            }
        }
    }
    return true;
}

[[nodiscard]] bool Fp32ColMajorToExactInt32RowMajor(const std::vector<float>& D, uint32_t M,
                                                    uint32_t N, uint32_t rows, uint32_t cols,
                                                    std::vector<int32_t>& out)
{
    if (D.size() != static_cast<size_t>(M) * N || rows > M || cols > N) return false;
    out.resize(static_cast<size_t>(rows) * cols);
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t r = 0; r < rows; ++r) {
            const float f = D[static_cast<size_t>(c) * M + r];
            if (!std::isfinite(f)) return false;
            const float rounded = nearbyintf(f);
            if (rounded != f) return false;
            if (rounded < static_cast<float>(std::numeric_limits<int32_t>::min()) ||
                rounded > static_cast<float>(std::numeric_limits<int32_t>::max())) {
                return false;
            }
            out[static_cast<size_t>(r) * cols + c] = static_cast<int32_t>(rounded);
        }
    }
    return true;
}

#if defined(BTX_RC_OZAKI_HAS_FP4_E2M1) && defined(BTX_RC_OZAKI_HAS_MX_SCALE_MODES)

[[nodiscard]] bool RunCublasLtBlockScaledTnOzaki(const void* dA, const void* dB, const void* dSFa,
                                                 const void* dSFb, float* dD, uint32_t M,
                                                 uint32_t N, uint32_t K, void* workspace,
                                                 size_t workspace_bytes)
{
    cublasLtHandle_t lt = nullptr;
    cublasLtMatmulDesc_t op = nullptr;
    cublasLtMatrixLayout_t a_layout = nullptr;
    cublasLtMatrixLayout_t b_layout = nullptr;
    cublasLtMatrixLayout_t d_layout = nullptr;
    cublasLtMatmulPreference_t pref = nullptr;
    bool ok = false;

    if (cublasLtCreate(&lt) != CUBLAS_STATUS_SUCCESS) return false;

    do {
        if (cublasLtMatmulDescCreate(&op, CUBLAS_COMPUTE_32F, CUDA_R_32F) != CUBLAS_STATUS_SUCCESS) {
            break;
        }
        const cublasOperation_t op_t = CUBLAS_OP_T;
        const cublasOperation_t op_n = CUBLAS_OP_N;
        if (cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_TRANSA, &op_t, sizeof(op_t)) !=
                CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_TRANSB, &op_n, sizeof(op_n)) !=
                CUBLAS_STATUS_SUCCESS) {
            break;
        }
        const cublasLtMatmulMatrixScale_t scale_mode = CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0;
        if (cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_A_SCALE_MODE, &scale_mode,
                                           sizeof(scale_mode)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_B_SCALE_MODE, &scale_mode,
                                           sizeof(scale_mode)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_A_SCALE_POINTER, &dSFa,
                                           sizeof(dSFa)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_B_SCALE_POINTER, &dSFb,
                                           sizeof(dSFb)) != CUBLAS_STATUS_SUCCESS) {
            break;
        }

        if (cublasLtMatrixLayoutCreate(&a_layout, CUDA_R_4F_E2M1, K, M, K) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatrixLayoutCreate(&b_layout, CUDA_R_4F_E2M1, K, N, K) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatrixLayoutCreate(&d_layout, CUDA_R_32F, M, N, M) != CUBLAS_STATUS_SUCCESS) {
            break;
        }

        if (cublasLtMatmulPreferenceCreate(&pref) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulPreferenceSetAttribute(pref, CUBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,
                                                 &workspace_bytes,
                                                 sizeof(workspace_bytes)) != CUBLAS_STATUS_SUCCESS) {
            break;
        }

        cublasLtMatmulHeuristicResult_t heuristic{};
        int returned = 0;
        if (cublasLtMatmulAlgoGetHeuristic(lt, op, a_layout, b_layout, d_layout, d_layout, pref, 1,
                                           &heuristic, &returned) != CUBLAS_STATUS_SUCCESS ||
            returned == 0) {
            break;
        }

        const float alpha = 1.0f;
        const float beta = 0.0f;
        if (cublasLtMatmul(lt, op, &alpha, dA, a_layout, dB, b_layout, &beta, dD, d_layout, dD,
                           d_layout, &heuristic.algo, workspace, workspace_bytes,
                           /*stream=*/nullptr) != CUBLAS_STATUS_SUCCESS) {
            break;
        }
        if (cudaDeviceSynchronize() != cudaSuccess) break;
        ok = true;
    } while (false);

    if (pref) cublasLtMatmulPreferenceDestroy(pref);
    if (d_layout) cublasLtMatrixLayoutDestroy(d_layout);
    if (b_layout) cublasLtMatrixLayoutDestroy(b_layout);
    if (a_layout) cublasLtMatrixLayoutDestroy(a_layout);
    if (op) cublasLtMatmulDescDestroy(op);
    if (lt) cublasLtDestroy(lt);
    return ok;
}

/** Real TC: factor → cuBLASLt CUDA_R_4F_E2M1 + VEC32_UE8M0 → exact int32. */
[[nodiscard]] bool LaunchMxfp4OnePanelCublasLt(const std::vector<int8_t>& Lpanel,
                                               const std::vector<int8_t>& Rpanel, uint32_t rows,
                                               uint32_t len, uint32_t cols,
                                               std::vector<int32_t>& partial, std::string* error)
{
    std::vector<uint8_t> A_pack, B_pack, SFa, SFb;
    uint32_t Mpad = 0, Npad = 0, Kpad = 0;
    if (!PackOzakiPanelsCublasLtFp4(Lpanel, Rpanel, rows, len, cols, A_pack, B_pack, SFa, SFb, Mpad,
                                    Npad, Kpad, error)) {
        return false;
    }

    void *dA = nullptr, *dB = nullptr, *dSFa = nullptr, *dSFb = nullptr, *dD = nullptr,
         *dWS = nullptr;
    constexpr size_t kWorkspace = 32ull * 1024ull * 1024ull;
    auto fail = [&](const char* msg) {
        if (error) *error = msg;
        cudaFree(dA);
        cudaFree(dB);
        cudaFree(dSFa);
        cudaFree(dSFb);
        cudaFree(dD);
        cudaFree(dWS);
        return false;
    };

    if (cudaMalloc(&dA, A_pack.size()) != cudaSuccess ||
        cudaMalloc(&dB, B_pack.size()) != cudaSuccess ||
        cudaMalloc(&dSFa, SFa.size()) != cudaSuccess ||
        cudaMalloc(&dSFb, SFb.size()) != cudaSuccess ||
        cudaMalloc(&dD, static_cast<size_t>(Mpad) * Npad * sizeof(float)) != cudaSuccess ||
        cudaMalloc(&dWS, kWorkspace) != cudaSuccess) {
        return fail("rc_ozaki_mxfp4_cublaslt cudaMalloc failed");
    }
    if (cudaMemcpy(dA, A_pack.data(), A_pack.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(dB, B_pack.data(), B_pack.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(dSFa, SFa.data(), SFa.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(dSFb, SFb.data(), SFb.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemset(dD, 0, static_cast<size_t>(Mpad) * Npad * sizeof(float)) != cudaSuccess) {
        return fail("rc_ozaki_mxfp4_cublaslt H2D failed");
    }

    if (!RunCublasLtBlockScaledTnOzaki(dA, dB, dSFa, dSFb, static_cast<float*>(dD), Mpad, Npad,
                                       Kpad, dWS, kWorkspace)) {
        return fail("rc_ozaki_mxfp4_cublaslt matmul/heuristic failed");
    }

    std::vector<float> host_d(static_cast<size_t>(Mpad) * Npad);
    if (cudaMemcpy(host_d.data(), dD, host_d.size() * sizeof(float), cudaMemcpyDeviceToHost) !=
        cudaSuccess) {
        return fail("rc_ozaki_mxfp4_cublaslt D2H failed");
    }
    cudaFree(dA);
    cudaFree(dB);
    cudaFree(dSFa);
    cudaFree(dSFb);
    cudaFree(dD);
    cudaFree(dWS);

    if (!Fp32ColMajorToExactInt32RowMajor(host_d, Mpad, Npad, rows, cols, partial)) {
        if (error) *error = "rc_ozaki_mxfp4_cublaslt FP32→int32 non-exact";
        return false;
    }
    return true;
}

/**
 * Pack for SM120 QMMA.SF: one e2m1 per byte in bits 5-2 (EncodeE2M1Nibble << 2).
 * A: M×K row-major, B: K×N row-major, SFA/SFB: UE8M0 [outer × kblocks].
 */
[[nodiscard]] bool PackOzakiPanelsMmaFp4(const std::vector<int8_t>& Lpanel,
                                         const std::vector<int8_t>& Rpanel, uint32_t rows,
                                         uint32_t K, uint32_t cols, std::vector<uint8_t>& A_pack,
                                         std::vector<uint8_t>& B_pack, std::vector<uint8_t>& SFa,
                                         std::vector<uint8_t>& SFb, uint32_t& Mpad, uint32_t& Npad,
                                         uint32_t& Kpad, std::string* error)
{
    if (rows == 0 || K == 0 || cols == 0) {
        if (error) *error = "PackOzakiPanelsMmaFp4: degenerate";
        return false;
    }
    Mpad = AlignUp(rows, 16u);
    Npad = AlignUp(cols, 8u);
    Kpad = AlignUp(K, kMxBlk);
    const uint32_t kblocks = Kpad / kMxBlk;
    A_pack.assign(static_cast<size_t>(Mpad) * Kpad, 0);
    B_pack.assign(static_cast<size_t>(Kpad) * Npad, 0);
    SFa.assign(static_cast<size_t>(Mpad) * kblocks, kUe8m0Bias);
    SFb.assign(static_cast<size_t>(Npad) * kblocks, kUe8m0Bias);

    int8_t mu_tmp[kMxBlk];
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = (k0 >= K) ? 0u : std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = Lpanel[static_cast<size_t>(r) * K + (k0 + t)];
            }
            uint8_t e = 0;
            if (n > 0) {
                if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                    if (error) *error = "PackOzakiPanelsMmaFp4: left not MX-factorable";
                    return false;
                }
            } else {
                std::memset(mu_tmp, 0, sizeof(mu_tmp));
            }
            SFa[static_cast<size_t>(r) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < kMxBlk; ++t) {
                const int8_t mu = (t < n) ? mu_tmp[t] : int8_t{0};
                const uint8_t nib = EncodeE2M1Nibble(mu);
                if (nib > 0x0F) {
                    if (error) *error = "PackOzakiPanelsMmaFp4: left mu not E2M1";
                    return false;
                }
                A_pack[static_cast<size_t>(r) * Kpad + (k0 + t)] =
                    static_cast<uint8_t>(nib << 2);
            }
        }
    }
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = (k0 >= K) ? 0u : std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = Rpanel[static_cast<size_t>(k0 + t) * cols + c];
            }
            uint8_t e = 0;
            if (n > 0) {
                if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                    if (error) *error = "PackOzakiPanelsMmaFp4: right not MX-factorable";
                    return false;
                }
            } else {
                std::memset(mu_tmp, 0, sizeof(mu_tmp));
            }
            SFb[static_cast<size_t>(c) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < kMxBlk; ++t) {
                const int8_t mu = (t < n) ? mu_tmp[t] : int8_t{0};
                const uint8_t nib = EncodeE2M1Nibble(mu);
                if (nib > 0x0F) {
                    if (error) *error = "PackOzakiPanelsMmaFp4: right mu not E2M1";
                    return false;
                }
                B_pack[static_cast<size_t>(k0 + t) * Npad + c] = static_cast<uint8_t>(nib << 2);
            }
        }
    }
    return true;
}

[[nodiscard]] bool Fp32RowMajorToExactInt32RowMajor(const std::vector<float>& D, uint32_t M,
                                                    uint32_t N, uint32_t rows, uint32_t cols,
                                                    std::vector<int32_t>& out)
{
    if (D.size() != static_cast<size_t>(M) * N || rows > M || cols > N) return false;
    out.resize(static_cast<size_t>(rows) * cols);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            const float f = D[static_cast<size_t>(r) * N + c];
            if (!std::isfinite(f)) return false;
            const float rounded = nearbyintf(f);
            if (rounded != f) return false;
            if (rounded < static_cast<float>(std::numeric_limits<int32_t>::min()) ||
                rounded > static_cast<float>(std::numeric_limits<int32_t>::max())) {
                return false;
            }
            out[static_cast<size_t>(r) * cols + c] = static_cast<int32_t>(rounded);
        }
    }
    return true;
}

/**
 * Real TC: factor → QMMA.SF m16n8k32 e2m1 block_scale → exact int32.
 * K must be a multiple of 32 — never zero-pad inside a tile (sm_120 block-scale
 * e2m1 is wrong for partial-K MMA tiles). Callers hybridize remainder via scalar.
 */
[[nodiscard]] bool LaunchMxfp4OnePanelMma(const std::vector<int8_t>& Lpanel,
                                          const std::vector<int8_t>& Rpanel, uint32_t rows,
                                          uint32_t len, uint32_t cols,
                                          std::vector<int32_t>& partial, std::string* error)
{
    if (len == 0 || (len % kMxBlk) != 0) {
        if (error) *error = "rc_ozaki_mxfp4_mma: K not multiple of 32";
        return false;
    }
    std::vector<uint8_t> A_pack, B_pack, SFa, SFb;
    uint32_t Mpad = 0, Npad = 0, Kpad = 0;
    if (!PackOzakiPanelsMmaFp4(Lpanel, Rpanel, rows, len, cols, A_pack, B_pack, SFa, SFb, Mpad, Npad,
                               Kpad, error)) {
        return false;
    }
    if (Kpad != len) {
        if (error) *error = "rc_ozaki_mxfp4_mma: unexpected K pad";
        return false;
    }
    const uint32_t kblocks = Kpad / kMxBlk;

    void *dA = nullptr, *dB = nullptr, *dSFa = nullptr, *dSFb = nullptr, *dD = nullptr;
    auto fail = [&](const char* msg) {
        if (error) *error = msg;
        cudaFree(dA);
        cudaFree(dB);
        cudaFree(dSFa);
        cudaFree(dSFb);
        cudaFree(dD);
        return false;
    };

    if (cudaMalloc(&dA, A_pack.size()) != cudaSuccess ||
        cudaMalloc(&dB, B_pack.size()) != cudaSuccess ||
        cudaMalloc(&dSFa, SFa.size()) != cudaSuccess ||
        cudaMalloc(&dSFb, SFb.size()) != cudaSuccess ||
        cudaMalloc(&dD, static_cast<size_t>(Mpad) * Npad * sizeof(float)) != cudaSuccess) {
        return fail("rc_ozaki_mxfp4_mma cudaMalloc failed");
    }
    if (cudaMemcpy(dA, A_pack.data(), A_pack.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(dB, B_pack.data(), B_pack.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(dSFa, SFa.data(), SFa.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(dSFb, SFb.data(), SFb.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemset(dD, 0, static_cast<size_t>(Mpad) * Npad * sizeof(float)) != cudaSuccess) {
        return fail("rc_ozaki_mxfp4_mma H2D failed");
    }

    dim3 grid(Npad / 8u, Mpad / 16u);
    rc_ozaki_mxfp4_mma_gemm<<<grid, 32>>>(static_cast<const uint8_t*>(dA),
                                          static_cast<const uint8_t*>(dB),
                                          static_cast<const uint8_t*>(dSFa),
                                          static_cast<const uint8_t*>(dSFb),
                                          static_cast<float*>(dD), static_cast<int>(Mpad),
                                          static_cast<int>(Npad), static_cast<int>(Kpad),
                                          static_cast<int>(kblocks));
    if (cudaGetLastError() != cudaSuccess || cudaDeviceSynchronize() != cudaSuccess) {
        return fail("rc_ozaki_mxfp4_mma kernel launch failed");
    }

    std::vector<float> host_d(static_cast<size_t>(Mpad) * Npad);
    if (cudaMemcpy(host_d.data(), dD, host_d.size() * sizeof(float), cudaMemcpyDeviceToHost) !=
        cudaSuccess) {
        return fail("rc_ozaki_mxfp4_mma D2H failed");
    }
    cudaFree(dA);
    cudaFree(dB);
    cudaFree(dSFa);
    cudaFree(dSFb);
    cudaFree(dD);

    if (!Fp32RowMajorToExactInt32RowMajor(host_d, Mpad, Npad, rows, cols, partial)) {
        if (error) *error = "rc_ozaki_mxfp4_mma FP32→int32 non-exact";
        return false;
    }
    return true;
}

#else // no FP4 toolkit

[[nodiscard]] bool LaunchMxfp4OnePanelMma(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                          uint32_t, uint32_t, uint32_t, std::vector<int32_t>&,
                                          std::string* error)
{
    if (error) *error = "rc_ozaki_mxfp4_mma: toolkit lacks FP4 helpers";
    return false;
}

[[nodiscard]] bool LaunchMxfp4OnePanelCublasLt(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                               uint32_t, uint32_t, uint32_t, std::vector<int32_t>&,
                                               std::string* error)
{
    if (error) *error = "rc_ozaki_mxfp4_cublaslt: toolkit lacks FP4/VEC32";
    return false;
}

#endif

/** Scalar-decode MXFP4 panel (E2M1 nibble decode + FP32 accumulate) — NOT native. */
[[nodiscard]] bool LaunchMxfp4OnePanelScalar(const std::vector<int8_t>& Lpanel,
                                             const std::vector<int8_t>& Rpanel, uint32_t rows,
                                             uint32_t len, uint32_t cols,
                                             std::vector<int32_t>& partial, std::string* error)
{
    std::vector<uint8_t> a_e2m1, b_e2m1, sfa, sfb;
    uint32_t kblocks = 0;
    if (!FactorInt8ToMxM11E8M0(Lpanel, Rpanel, rows, len, cols, a_e2m1, b_e2m1, sfa, sfb, kblocks,
                               error)) {
        return false;
    }

    uint8_t *d_a = nullptr, *d_b = nullptr, *d_sfa = nullptr, *d_sfb = nullptr;
    float* d_out = nullptr;
    const size_t out_n = static_cast<size_t>(rows) * cols;
    auto fail = [&](const char* msg) {
        if (error) *error = msg;
        cudaFree(d_a);
        cudaFree(d_b);
        cudaFree(d_sfa);
        cudaFree(d_sfb);
        cudaFree(d_out);
        return false;
    };

    if (cudaMalloc(&d_a, a_e2m1.size()) != cudaSuccess ||
        cudaMalloc(&d_b, b_e2m1.size()) != cudaSuccess ||
        cudaMalloc(&d_sfa, sfa.size()) != cudaSuccess ||
        cudaMalloc(&d_sfb, sfb.size()) != cudaSuccess ||
        cudaMalloc(&d_out, out_n * sizeof(float)) != cudaSuccess) {
        return fail("rc_ozaki_mxfp4 cudaMalloc failed");
    }
    if (cudaMemcpy(d_a, a_e2m1.data(), a_e2m1.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(d_b, b_e2m1.data(), b_e2m1.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(d_sfa, sfa.data(), sfa.size(), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(d_sfb, sfb.data(), sfb.size(), cudaMemcpyHostToDevice) != cudaSuccess) {
        return fail("rc_ozaki_mxfp4 H2D failed");
    }

    dim3 block(16, 16);
    dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y);
    rc_ozaki_mxfp4_panel_gemm<<<grid, block>>>(d_a, d_b, d_sfa, d_sfb, d_out, rows, len, cols,
                                               kblocks);
    if (cudaGetLastError() != cudaSuccess || cudaDeviceSynchronize() != cudaSuccess) {
        return fail("rc_ozaki_mxfp4_panel_gemm launch failed");
    }

    std::vector<float> host_fp(out_n);
    if (cudaMemcpy(host_fp.data(), d_out, out_n * sizeof(float), cudaMemcpyDeviceToHost) !=
        cudaSuccess) {
        return fail("rc_ozaki_mxfp4 D2H failed");
    }
    cudaFree(d_a);
    cudaFree(d_b);
    cudaFree(d_sfa);
    cudaFree(d_sfb);
    cudaFree(d_out);

    std::string conv_err;
    if (!Fp32OutputToExactInt32(host_fp.data(), out_n, partial, conv_err)) {
        if (error) *error = conv_err.empty() ? "Fp32OutputToExactInt32 failed" : conv_err;
        return false;
    }
    return true;
}

/**
 * Scalar-decode MXFP4 Ozaki panels (E2M1 nibble decode + FP32 accumulate).
 * Exactness/reference accelerator only — NEVER flips native MXFP4 latches.
 * CRITICAL: must not call LaunchGemmS8S8. Backend marker includes scalar-decode.
 */
[[nodiscard]] bool LaunchOzakiMxfp4PanelsScalar(const std::vector<int8_t>& left,
                                                const std::vector<int8_t>& right, uint32_t rows,
                                                uint32_t inner, uint32_t cols,
                                                std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki MXFP4 degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki MXFP4 operand size mismatch";
        return false;
    }

    using matmul::v4::rc::kRCOzakiExactChunk;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t k0 = 0; k0 < inner; k0 += kRCOzakiExactChunk) {
        const uint32_t len = std::min(kRCOzakiExactChunk, inner - k0);
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * len);
        std::vector<int8_t> Rpanel(static_cast<size_t>(len) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < len; ++t) {
                Lpanel[static_cast<size_t>(r) * len + t] =
                    left[static_cast<size_t>(r) * inner + (k0 + t)];
            }
        }
        for (uint32_t t = 0; t < len; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k0 + t) * cols + c];
            }
        }

        std::vector<int32_t> partial;
        if (!LaunchMxfp4OnePanelScalar(Lpanel, Rpanel, rows, len, cols, partial, error) ||
            partial.size() != out.size()) {
            out.clear();
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    return true;
}

/** Real TC Ozaki panels via cuBLASLt block-scaled E2M1 (native claim path). */
[[nodiscard]] bool LaunchOzakiMxfp4PanelsCublasLt(const std::vector<int8_t>& left,
                                                  const std::vector<int8_t>& right, uint32_t rows,
                                                  uint32_t inner, uint32_t cols,
                                                  std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki MXFP4 TC degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki MXFP4 TC operand size mismatch";
        return false;
    }

    using matmul::v4::rc::kRCOzakiExactChunk;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t k0 = 0; k0 < inner; k0 += kRCOzakiExactChunk) {
        const uint32_t len = std::min(kRCOzakiExactChunk, inner - k0);
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * len);
        std::vector<int8_t> Rpanel(static_cast<size_t>(len) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < len; ++t) {
                Lpanel[static_cast<size_t>(r) * len + t] =
                    left[static_cast<size_t>(r) * inner + (k0 + t)];
            }
        }
        for (uint32_t t = 0; t < len; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k0 + t) * cols + c];
            }
        }

        std::vector<int32_t> partial;
        if (!LaunchMxfp4OnePanelCublasLt(Lpanel, Rpanel, rows, len, cols, partial, error) ||
            partial.size() != out.size()) {
            out.clear();
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    return true;
}

/** Real TC Ozaki panels via SM120 QMMA.SF m16n8k32 e2m1 block_scale (native claim path).
 * Full K/32 tiles → MMA; K%32 remainder → scalar-decode (exactness). Never zero-pads
 * inside an MMA tile. */
[[nodiscard]] bool LaunchOzakiMxfp4PanelsMma(const std::vector<int8_t>& left,
                                             const std::vector<int8_t>& right, uint32_t rows,
                                             uint32_t inner, uint32_t cols,
                                             std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki MXFP4 MMA degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki MXFP4 MMA operand size mismatch";
        return false;
    }

    out.assign(static_cast<size_t>(rows) * cols, 0);
    const uint32_t k_full = (inner / kMxBlk) * kMxBlk;
    const uint32_t k_rem = inner - k_full;

    auto add_partial = [&](const std::vector<int32_t>& partial) -> bool {
        if (partial.size() != out.size()) return false;
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
        return true;
    };

    using matmul::v4::rc::kRCOzakiExactChunk;
    for (uint32_t k0 = 0; k0 < k_full; k0 += kRCOzakiExactChunk) {
        uint32_t len = std::min(kRCOzakiExactChunk, k_full - k0);
        len = (len / kMxBlk) * kMxBlk; // keep MMA tiles dense
        if (len == 0) continue;
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * len);
        std::vector<int8_t> Rpanel(static_cast<size_t>(len) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < len; ++t) {
                Lpanel[static_cast<size_t>(r) * len + t] =
                    left[static_cast<size_t>(r) * inner + (k0 + t)];
            }
        }
        for (uint32_t t = 0; t < len; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k0 + t) * cols + c];
            }
        }
        std::vector<int32_t> partial;
        if (!LaunchMxfp4OnePanelMma(Lpanel, Rpanel, rows, len, cols, partial, error) ||
            !add_partial(partial)) {
            out.clear();
            return false;
        }
    }

    if (k_rem > 0) {
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * k_rem);
        std::vector<int8_t> Rpanel(static_cast<size_t>(k_rem) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < k_rem; ++t) {
                Lpanel[static_cast<size_t>(r) * k_rem + t] =
                    left[static_cast<size_t>(r) * inner + (k_full + t)];
            }
        }
        for (uint32_t t = 0; t < k_rem; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k_full + t) * cols + c];
            }
        }
        std::vector<int32_t> partial;
        if (!LaunchMxfp4OnePanelScalar(Lpanel, Rpanel, rows, k_rem, cols, partial, error) ||
            !add_partial(partial)) {
            out.clear();
            return false;
        }
    }
    return true;
}

void FillM11E8M0Max(std::vector<int8_t>& L, std::vector<int8_t>& R, uint32_t rows, uint32_t inner,
                    uint32_t cols, uint32_t seed, uint8_t e)
{
    L.assign(static_cast<size_t>(rows) * inner, 0);
    R.assign(static_cast<size_t>(inner) * cols, 0);
    const int32_t mag = 6 * (1 << e);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t k = 0; k < inner; ++k) {
            // Uniform e within each K-block (MX-shaped).
            const bool neg = ((r + (k / kMxBlk) + seed) & 1u) != 0;
            L[static_cast<size_t>(r) * inner + k] = static_cast<int8_t>(neg ? -mag : mag);
        }
    }
    for (uint32_t k = 0; k < inner; ++k) {
        for (uint32_t c = 0; c < cols; ++c) {
            const bool neg = (((k / kMxBlk) * 3u + c + seed) & 1u) != 0;
            R[static_cast<size_t>(k) * cols + c] = static_cast<int8_t>(neg ? -mag : mag);
        }
    }
}

void FillMxSeeded(std::vector<int8_t>& L, std::vector<int8_t>& R, uint32_t rows, uint32_t inner,
                  uint32_t cols, uint32_t seed)
{
    static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    L.assign(static_cast<size_t>(rows) * inner, 0);
    R.assign(static_cast<size_t>(inner) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t k = 0; k < inner; ++k) {
            const uint8_t e = static_cast<uint8_t>((seed + (k / kMxBlk)) & 3u);
            const int8_t mu = kM11[(r + k + seed) % 11];
            L[static_cast<size_t>(r) * inner + k] =
                static_cast<int8_t>(static_cast<int32_t>(mu) * (1 << e));
        }
    }
    for (uint32_t k = 0; k < inner; ++k) {
        for (uint32_t c = 0; c < cols; ++c) {
            const uint8_t e = static_cast<uint8_t>((seed * 3u + (k / kMxBlk)) & 3u);
            const int8_t mu = kM11[(k * 5u + c + seed) % 11];
            R[static_cast<size_t>(k) * cols + c] =
                static_cast<int8_t>(static_cast<int32_t>(mu) * (1 << e));
        }
    }
}

[[nodiscard]] bool DenseInt64(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                              uint32_t rows, uint32_t inner, uint32_t cols,
                              std::vector<int64_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            int64_t acc = 0;
            for (uint32_t k = 0; k < inner; ++k) {
                acc += static_cast<int64_t>(left[static_cast<size_t>(r) * inner + k]) *
                       static_cast<int64_t>(right[static_cast<size_t>(k) * cols + c]);
            }
            out[static_cast<size_t>(r) * cols + c] = acc;
        }
    }
    return true;
}

[[nodiscard]] bool ExactShapeMatches(uint32_t rows, uint32_t inner, uint32_t cols, uint32_t seed,
                                     std::string* error)
{
    std::vector<int8_t> left, right;
    FillMxSeeded(left, right, rows, inner, cols, seed);
    // Also allow non-MX pseudo for ExactPanels (IMMA accepts any int8 in range).
    for (size_t i = 0; i < left.size(); ++i) {
        left[i] = static_cast<int8_t>((static_cast<int32_t>(i + seed) % 97) - 48);
    }
    for (size_t i = 0; i < right.size(); ++i) {
        right[i] = static_cast<int8_t>((static_cast<int32_t>(i * 3 + seed) % 95) - 47);
    }
    std::vector<int64_t> cpu;
    if (!matmul::v4::rc::RcOzakiCpuLimbSplitGemmS8S8Int64(left, right, rows, inner, cols, cpu)) {
        if (error) *error = "cpu Ozaki ExactPanels oracle failed";
        return false;
    }
    std::vector<int64_t> gpu;
    if (!LaunchOzakiExactPanels(left, right, rows, inner, cols, gpu, error)) return false;
    if (gpu != cpu) {
        if (error) *error = "CUDA ExactPanels != CPU Ozaki oracle";
        return false;
    }
    return true;
}

using Mxfp4PanelLauncher = bool (*)(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                    uint32_t, uint32_t, uint32_t, std::vector<int64_t>&,
                                    std::string*);

[[nodiscard]] bool Mxfp4ShapeMatches(uint32_t rows, uint32_t inner, uint32_t cols, uint32_t seed,
                                     bool max_corner, uint8_t e, Mxfp4PanelLauncher launch,
                                     std::string* error)
{
    std::vector<int8_t> left, right;
    if (max_corner) {
        FillM11E8M0Max(left, right, rows, inner, cols, seed, e);
    } else {
        FillMxSeeded(left, right, rows, inner, cols, seed);
    }
    std::vector<int64_t> cpu;
    DenseInt64(left, right, rows, inner, cols, cpu);
    std::vector<int64_t> gpu;
    if (!launch(left, right, rows, inner, cols, gpu, error)) return false;
    if (gpu != cpu) {
        if (error) *error = "CUDA MXFP4 panels != int64 oracle";
        return false;
    }
    // Corrupted device output must fail the equality gate.
    if (!gpu.empty()) {
        auto corrupted = gpu;
        corrupted[0] += 1;
        if (corrupted == cpu) {
            if (error) *error = "corruption-equality sanity failed";
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool Mxfp4TensorSuiteMatches(std::string* error)
{
    // Prefer real QMMA.SF MMA path; fall back to cuBLASLt if MMA unavailable.
    std::string mma_err;
    auto launch_mma = &LaunchOzakiMxfp4PanelsMma;
    if (Mxfp4ShapeMatches(4, 8, 4, /*seed=*/1, /*max=*/false, 0, launch_mma, &mma_err) &&
        Mxfp4ShapeMatches(4, 4095, 4, /*seed=*/2, /*max=*/true, /*e=*/3, launch_mma, &mma_err) &&
        Mxfp4ShapeMatches(4, 4096, 4, /*seed=*/3, /*max=*/true, /*e=*/3, launch_mma, &mma_err) &&
        Mxfp4ShapeMatches(4, 4097, 4, /*seed=*/5, /*max=*/true, /*e=*/2, launch_mma, &mma_err) &&
        Mxfp4ShapeMatches(4, 8192, 4, /*seed=*/7, /*max=*/false, 0, launch_mma, &mma_err) &&
        Mxfp4ShapeMatches(8, 4096, 8, /*seed=*/11, /*max=*/true, /*e=*/1, launch_mma, &mma_err) &&
        Mxfp4ShapeMatches(4, 16384, 4, /*seed=*/13, /*max=*/false, 0, launch_mma, &mma_err) &&
        Mxfp4ShapeMatches(32, 4096, 32, /*seed=*/17, /*max=*/true, /*e=*/3, launch_mma, &mma_err)) {
        return true;
    }
    auto launch_lt = &LaunchOzakiMxfp4PanelsCublasLt;
    std::string lt_err;
    const bool lt_ok =
        Mxfp4ShapeMatches(4, 8, 4, /*seed=*/1, /*max=*/false, 0, launch_lt, &lt_err) &&
        Mxfp4ShapeMatches(4, 4095, 4, /*seed=*/2, /*max=*/true, /*e=*/3, launch_lt, &lt_err) &&
        Mxfp4ShapeMatches(4, 4096, 4, /*seed=*/3, /*max=*/true, /*e=*/3, launch_lt, &lt_err) &&
        Mxfp4ShapeMatches(4, 4097, 4, /*seed=*/5, /*max=*/true, /*e=*/2, launch_lt, &lt_err) &&
        Mxfp4ShapeMatches(4, 8192, 4, /*seed=*/7, /*max=*/false, 0, launch_lt, &lt_err) &&
        Mxfp4ShapeMatches(8, 4096, 8, /*seed=*/11, /*max=*/true, /*e=*/1, launch_lt, &lt_err) &&
        Mxfp4ShapeMatches(4, 16384, 4, /*seed=*/13, /*max=*/false, 0, launch_lt, &lt_err) &&
        Mxfp4ShapeMatches(32, 4096, 32, /*seed=*/17, /*max=*/true, /*e=*/3, launch_lt, &lt_err);
    if (!lt_ok && error) {
        *error = "mma_failed:" + mma_err + "; cublaslt_failed:" + lt_err;
    }
    return lt_ok;
}

} // namespace

bool IsRcOzakiCudaCompiled()
{
    return true;
}

bool IsRcOzakiCudaExactPanelsQualified()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    return g_exact_qualified;
}

bool SelfQualifyRcOzakiCudaExactPanelsOnce()
{
    {
        std::lock_guard<std::mutex> lock(g_ozaki_mu);
        if (g_exact_ran) return g_exact_qualified;
    }
    std::string err;
    const bool ok = ExactShapeMatches(8, 8, 8, 1u, &err) &&
                    ExactShapeMatches(32, 8192, 32, 7u, &err) &&
                    ExactShapeMatches(8, 4096, 8, 3u, &err);
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if (!g_exact_ran) {
        g_exact_ran = true;
        g_exact_qualified = ok;
    }
    return g_exact_qualified;
}

bool TryLaunchRcOzakiExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                             const std::vector<int8_t>& right, uint32_t rows,
                                             uint32_t inner, uint32_t cols,
                                             std::vector<int64_t>& out, std::string* error)
{
    return LaunchOzakiExactPanels(left, right, rows, inner, cols, out, error);
}

bool IsRcOzakiCudaMxfp4Qualified()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    // True only after a real CUTLASS/cuBLASLt tensor path quals — never from
    // the scalar-decode E2M1+FP32 kernel (BMX4C C6 honesty).
    return g_qual_sm120 || g_qual_sm100;
}

std::string RcOzakiCudaMxfp4ArchKey()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    return g_mx_arch_key;
}

std::string RcOzakiCudaMxfp4Backend()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    return g_mx_backend;
}

std::string RcOzakiCudaMxfp4Deficit()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    return g_mx_deficit;
}

bool SelfQualifyRcOzakiCudaMxfp4Once()
{
    {
        std::lock_guard<std::mutex> lock(g_ozaki_mu);
        if (g_mx_ran) return g_qual_sm120 || g_qual_sm100;
    }

    cudaDeviceProp prop{};
    std::string err;
    bool scalar_ok = false;
    bool tensor_ok = false;
    {
        int device = 0;
        if (cudaGetDevice(&device) != cudaSuccess ||
            cudaGetDeviceProperties(&prop, device) != cudaSuccess) {
            err = "cudaGetDeviceProperties failed for MXFP4 self-qual";
        }
    }

    const bool is_sm120 = DeviceLooksSm120(prop.major, prop.minor);
    const bool is_sm100 = DeviceLooksSm100(prop.major, prop.minor);

    // Scalar-decode exactness probe (reference accelerator). Matches int64 oracle
    // but is NOT a tensor-core path — must never flip g_qual_sm120 / g_qual_sm100.
    if (err.empty()) {
        auto scalar = &LaunchOzakiMxfp4PanelsScalar;
        scalar_ok = Mxfp4ShapeMatches(4, 8, 4, /*seed=*/1, /*max=*/false, 0, scalar, &err) &&
                    Mxfp4ShapeMatches(4, 4095, 4, /*seed=*/2, /*max=*/true, /*e=*/3, scalar, &err) &&
                    Mxfp4ShapeMatches(4, 4096, 4, /*seed=*/3, /*max=*/true, /*e=*/3, scalar, &err) &&
                    Mxfp4ShapeMatches(4, 4097, 4, /*seed=*/5, /*max=*/true, /*e=*/2, scalar, &err) &&
                    Mxfp4ShapeMatches(4, 8192, 4, /*seed=*/7, /*max=*/false, 0, scalar, &err) &&
                    Mxfp4ShapeMatches(8, 4096, 8, /*seed=*/11, /*max=*/true, /*e=*/1, scalar, &err) &&
                    Mxfp4ShapeMatches(4, 16384, 4, /*seed=*/13, /*max=*/false, 0, scalar, &err);
    }

    // Real TC path (QMMA.SF MMA preferred; cuBLASLt Plan B). Only this may flip
    // native latches — and only on sm_120 / sm_100 separately.
    std::string tc_err;
    std::string tc_backend;
    if (err.empty() && (is_sm120 || is_sm100)) {
        // Detect which backend matched by probing MMA first.
        std::string mma_probe;
        if (Mxfp4ShapeMatches(4, 8, 4, 1, false, 0, &LaunchOzakiMxfp4PanelsMma, &mma_probe) &&
            Mxfp4TensorSuiteMatches(&tc_err)) {
            // Re-check: if MMA tiny shape works and full suite passed, prefer MMA name.
            // Suite tries MMA first then Lt — if MMA failed suite wouldn't set via MMA.
            // Pure-K MMA (no scalar remainder) must match for cutlass/MMA native claim.
            std::string mma_full;
            if (Mxfp4ShapeMatches(4, 4096, 4, 3, true, 3, &LaunchOzakiMxfp4PanelsMma, &mma_full) &&
                Mxfp4ShapeMatches(4, 32, 4, 9, true, 2, &LaunchOzakiMxfp4PanelsMma, &mma_full)) {
                tensor_ok = true;
                tc_backend = is_sm120 ? "mxfp4_mma_sm120" : "mxfp4_mma_sm100";
            } else {
                tensor_ok = true;
                tc_backend = is_sm120 ? "mxfp4_cublaslt_sm120" : "mxfp4_cublaslt_sm100";
            }
        } else {
            tensor_ok = false;
            if (!tc_err.empty()) err = tc_err;
            else if (!mma_probe.empty()) err = mma_probe;
        }
    }

    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if (!g_mx_ran) {
        g_mx_ran = true;
        g_mx_arch_key = FormatCudaArchKey(prop.major, prop.minor);
        g_qual_sm120 = false;
        g_qual_sm100 = false;
        if (tensor_ok && is_sm120) {
            g_qual_sm120 = true;
            g_mx_backend = tc_backend.empty() ? "mxfp4_mma_sm120" : tc_backend;
            g_mx_deficit.clear();
        } else if (tensor_ok && is_sm100) {
            g_qual_sm100 = true;
            g_mx_backend = tc_backend.empty() ? "mxfp4_mma_sm100" : tc_backend;
            g_mx_deficit.clear();
        } else if (scalar_ok) {
            // BMX4C honesty: distinct scalar-decode marker; native stays false.
            g_mx_backend = "mxfp4_blockscaled_device_scalar-decode";
            g_mx_deficit =
                "rc_ozaki_mxfp4_scalar-decode_exact_but_not_native_tensor";
            if (!tc_err.empty()) {
                g_mx_deficit += "; tc_failed:" + tc_err;
            }
        } else {
            g_mx_backend.clear();
            g_mx_deficit = err.empty() ? "mxfp4_selfqual_failed" : err;
        }
    }
    return g_qual_sm120 || g_qual_sm100;
}

bool TryLaunchRcOzakiMxfp4GemmS8S8Int64(const std::vector<int8_t>& left,
                                       const std::vector<int8_t>& right, uint32_t rows,
                                       uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                       std::string* error)
{
    out.clear();
    // Native claim only: real TC (MMA or cuBLASLt). Scalar-decode must not serve this entry.
    if (!IsRcOzakiCudaMxfp4Qualified()) {
        if (error) {
            *error = "RC Ozaki MXFP4 native tensor path not qualified "
                     "(scalar-decode is not native)";
        }
        return false;
    }
    // Prefer MMA; fall back to cuBLASLt if MMA declines a production shape.
    if (LaunchOzakiMxfp4PanelsMma(left, right, rows, inner, cols, out, error)) {
        return true;
    }
    return LaunchOzakiMxfp4PanelsCublasLt(left, right, rows, inner, cols, out, error);
}

void ResetRcOzakiCudaQualForTest()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    g_exact_ran = false;
    g_exact_qualified = false;
    g_mx_ran = false;
    g_qual_sm120 = false;
    g_qual_sm100 = false;
    g_mx_arch_key.clear();
    g_mx_backend.clear();
    g_mx_deficit.clear();
}

} // namespace matmul_v4::cuda
