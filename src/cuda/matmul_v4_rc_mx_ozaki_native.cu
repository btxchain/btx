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
#include <mutex>
#include <string>
#include <vector>

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

/** One MXFP4 panel (K ≤ kRCOzakiExactChunk): factor → device E2M1 GEMM → int32. */
[[nodiscard]] bool LaunchMxfp4OnePanel(const std::vector<int8_t>& Lpanel,
                                       const std::vector<int8_t>& Rpanel, uint32_t rows,
                                       uint32_t len, uint32_t cols, std::vector<int32_t>& partial,
                                       std::string* error)
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
 * Native MXFP4 Ozaki panels. CRITICAL: must not call LaunchGemmS8S8.
 * Backend label: mxfp4_blockscaled_device.
 */
[[nodiscard]] bool LaunchOzakiMxfp4Panels(const std::vector<int8_t>& left,
                                          const std::vector<int8_t>& right, uint32_t rows,
                                          uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                          std::string* error)
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
        if (!LaunchMxfp4OnePanel(Lpanel, Rpanel, rows, len, cols, partial, error) ||
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

[[nodiscard]] bool Mxfp4ShapeMatches(uint32_t rows, uint32_t inner, uint32_t cols, uint32_t seed,
                                     bool max_corner, uint8_t e, std::string* error)
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
    if (!LaunchOzakiMxfp4Panels(left, right, rows, inner, cols, gpu, error)) return false;
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

bool SelfQualifyRcOzakiCudaMxfp4Once()
{
    {
        std::lock_guard<std::mutex> lock(g_ozaki_mu);
        if (g_mx_ran) return g_qual_sm120 || g_qual_sm100;
    }

    cudaDeviceProp prop{};
    std::string err;
    bool ok = false;
    bool is_sm120 = false;
    bool is_sm100 = false;
    {
        int device = 0;
        if (cudaGetDevice(&device) == cudaSuccess &&
            cudaGetDeviceProperties(&prop, device) == cudaSuccess) {
            is_sm120 = DeviceLooksSm120(prop.major, prop.minor);
            is_sm100 = DeviceLooksSm100(prop.major, prop.minor);
        } else {
            err = "cudaGetDeviceProperties failed for MXFP4 self-qual";
        }
    }

    // Qual vectors: K edges around ExactGemm chunk + thin multi-seed / max M11.
    if (err.empty()) {
        ok = Mxfp4ShapeMatches(4, 8, 4, /*seed=*/1, /*max=*/false, 0, &err) &&
             Mxfp4ShapeMatches(4, 4095, 4, /*seed=*/2, /*max=*/true, /*e=*/3, &err) &&
             Mxfp4ShapeMatches(4, 4096, 4, /*seed=*/3, /*max=*/true, /*e=*/3, &err) &&
             Mxfp4ShapeMatches(4, 4097, 4, /*seed=*/5, /*max=*/true, /*e=*/2, &err) &&
             Mxfp4ShapeMatches(4, 8192, 4, /*seed=*/7, /*max=*/false, 0, &err) &&
             Mxfp4ShapeMatches(8, 4096, 8, /*seed=*/11, /*max=*/true, /*e=*/1, &err) &&
             Mxfp4ShapeMatches(4, 16384, 4, /*seed=*/13, /*max=*/false, 0, &err); // thin prod-K
    }

    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if (!g_mx_ran) {
        g_mx_ran = true;
        g_mx_arch_key = FormatCudaArchKey(prop.major, prop.minor);
        g_mx_deficit = ok ? std::string{} : (err.empty() ? "mxfp4_selfqual_failed" : err);
        if (ok) {
            g_mx_backend = "mxfp4_blockscaled_device";
            // Arch-specific latches: B200 (sm_100) must not inherit sm_120 qual.
            g_qual_sm120 = is_sm120;
            g_qual_sm100 = is_sm100;
            // Non-Blackwell: still admit the honest device kernel if oracle matched
            // (datatype path, not TC peak). Record under the live arch_key.
            if (!is_sm120 && !is_sm100) {
                // Keep qualified via arch_key backend but leave sm latches false;
                // host IsRcOzakiCudaMxfp4Qualified requires a latch — set the
                // nearer class false and use a soft admit via both false + ok?
                // Spec: separate g_qual_sm120 / g_qual_sm100. For other arches that
                // still ran the device kernel successfully, set neither and fail
                // IsRcOzakiCudaMxfp4Qualified unless we add g_qual_other.
                // Prefer: qualify only on sm_10x/sm_12x (Blackwell class).
                g_mx_backend.clear();
                g_mx_deficit = "rc_ozaki_mxfp4_requires_sm100_or_sm120_arch_latch";
                ok = false;
            }
        }
        if (!ok) {
            g_qual_sm120 = false;
            g_qual_sm100 = false;
            g_mx_backend.clear();
        }
    }
    return g_qual_sm120 || g_qual_sm100;
}

bool TryLaunchRcOzakiMxfp4GemmS8S8Int64(const std::vector<int8_t>& left,
                                       const std::vector<int8_t>& right, uint32_t rows,
                                       uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                       std::string* error)
{
    // Honesty: never fall back to LaunchGemmS8S8 / ExactGemm INT8 here.
    if (!LaunchOzakiMxfp4Panels(left, right, rows, inner, cols, out, error)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if (g_mx_backend.empty()) g_mx_backend = "mxfp4_blockscaled_device";
    return true;
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
