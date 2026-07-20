// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_mx_native.h>

#include <cuda/cuda_context.h>
#include <cuda/matmul_v4_lt_cutlass_mxfp4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>

#include <cuda_runtime.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// Optional compile gates: CUDA 12.8 introduced the FP4 data type and the
// VEC16/VEC32 block-scale modes used below. cuda_runtime.h publishes the
// toolkit header version as CUDART_VERSION; CUDA_VERSION belongs to the driver
// API headers and is not guaranteed to be visible here. Using CUDA_VERSION
// silently compiled every native lane out under nvcc 13.x, leaving
// native_mxfp4_attempted/native_fp8_attempted false even on Blackwell.
//
// The CUDA_R_* and
// CUBLASLT_MATMUL_MATRIX_SCALE_* names are enum constants, not preprocessor
// macros, so `defined(NAME)` cannot be used to discover them.
#if defined(CUDART_VERSION) && (CUDART_VERSION >= 12080)
#include <cublasLt.h>
#include <cuda_fp8.h>
#define BTX_LT_CUDA_HAS_FP8_E4M3 1
#if defined(__has_include)
#if __has_include(<cuda_fp4.h>)
#include <cuda_fp4.h>
#define BTX_LT_CUDA_HAS_FP4_E2M1 1
#endif
#endif
#define BTX_LT_CUDA_HAS_VEC32_UE8M0 1
#define BTX_LT_CUDA_HAS_VEC16_UE4M3 1
#define BTX_LT_CUDA_HAS_MX_SCALE_MODES 1
#endif

namespace matmul_v4::cuda {
namespace {

std::mutex g_native_mx_mu;
bool g_native_mxfp4_attempted{false};
bool g_native_mxfp4_qualified{false};
bool g_native_fp8_attempted{false};
bool g_native_fp8_qualified{false};
bool g_native_qual_ran{false};

[[nodiscard]] bool IsBlackwellSm(int major, int minor)
{
    (void)minor;
    return (major == 10) || (major == 12);
}

[[nodiscard]] bool ToolkitDeclaresFp4()
{
#if defined(BTX_LT_CUDA_HAS_FP4_E2M1)
    return true;
#else
    return false;
#endif
}

[[nodiscard]] bool ToolkitDeclaresFp8()
{
#if defined(BTX_LT_CUDA_HAS_FP8_E4M3)
    return true;
#else
    return false;
#endif
}

[[nodiscard]] bool ToolkitDeclaresMxScaleModes()
{
#if defined(BTX_LT_CUDA_HAS_MX_SCALE_MODES)
    return true;
#else
    return false;
#endif
}

[[nodiscard]] bool ToolkitDeclaresVec32Ue8m0()
{
#if defined(BTX_LT_CUDA_HAS_VEC32_UE8M0)
    return true;
#else
    return false;
#endif
}

[[nodiscard]] constexpr uint8_t Ue8m0CodeFromExponent(uint8_t e)
{
    return static_cast<uint8_t>(127u + static_cast<unsigned>(e));
}

[[nodiscard]] constexpr uint8_t Ue8m0UnitCode() { return 127u; }

// cuBLASLt 1D block-scale layout (VEC32_UE8M0 / VEC16_UE4M3): 128×4 tiles with
// within-tile swizzle matching NVIDIA docs + BMX4 Sm1xxBlockScaledConfig.
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

void FillUnitBlockScales(std::vector<uint8_t>& buf, size_t outer, size_t K, size_t vec,
                         uint8_t unit_code)
{
    buf.assign(BlockScaleTensorBytes(outer, K, vec), 0);
    const size_t kblocks = (K + vec - 1u) / vec;
    for (size_t r = 0; r < outer; ++r) {
        for (size_t c = 0; c < kblocks; ++c) {
            buf[BlockScaleOffset(r, c, K, vec)] = unit_code;
        }
    }
}

bool PackBtxScalesVec32Ue8m0(const std::vector<uint8_t>& btx_e, uint32_t rows, uint32_t K,
                             std::vector<uint8_t>& out)
{
    if ((K % 32u) != 0) return false;
    const uint32_t nblk = K / 32u;
    if (btx_e.size() != static_cast<size_t>(rows) * nblk) return false;
    out.assign(BlockScaleTensorBytes(rows, K, 32), 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            const uint8_t e = btx_e[static_cast<size_t>(r) * nblk + bj];
            if (e > 3u) return false;
            out[BlockScaleOffset(r, bj, K, 32)] = Ue8m0CodeFromExponent(e);
        }
    }
    return true;
}

[[nodiscard]] uint8_t Ue4m3CodeFromPow2Exponent(uint8_t e)
{
#if defined(BTX_LT_CUDA_HAS_FP8_E4M3)
    const __nv_fp8_e4m3 enc{static_cast<float>(1u << e)};
    uint8_t bits = 0;
    static_assert(sizeof(enc) == 1, "E4M3 storage is one byte");
    std::memcpy(&bits, &enc, 1);
    return bits;
#else
    static constexpr uint8_t kPow2[] = {0x38, 0x40, 0x48, 0x50};
    return kPow2[e & 3u];
#endif
}

bool PackBtxScalesVec16Ue4m3Duplicated(const std::vector<uint8_t>& btx_e, uint32_t rows,
                                       uint32_t K, std::vector<uint8_t>& out)
{
    if ((K % 32u) != 0) return false;
    const uint32_t nblk32 = K / 32u;
    if (btx_e.size() != static_cast<size_t>(rows) * nblk32) return false;
    out.assign(BlockScaleTensorBytes(rows, K, 16), 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < nblk32; ++bj) {
            const uint8_t e = btx_e[static_cast<size_t>(r) * nblk32 + bj];
            if (e > 3u) return false;
            const uint8_t code = Ue4m3CodeFromPow2Exponent(e);
            const size_t c0 = static_cast<size_t>(bj) * 2u;
            out[BlockScaleOffset(r, c0, K, 16)] = code;
            out[BlockScaleOffset(r, c0 + 1u, K, 16)] = code;
        }
    }
    return true;
}

[[nodiscard]] uint8_t EncodeE2M1Nibble(int8_t mu)
{
    return lt_cutlass_mxfp4::EncodeE2M1Nibble(mu);
}

inline void PackE2M1Nibble(uint8_t* buf, size_t idx, uint8_t nib)
{
    lt_cutlass_mxfp4::PackNibble(buf, idx, nib);
}

[[nodiscard]] uint8_t EncodeE4M3Int(int8_t v)
{
#if defined(BTX_LT_CUDA_HAS_FP8_E4M3)
    const __nv_fp8_e4m3 enc{static_cast<float>(v)};
    uint8_t bits = 0;
    static_assert(sizeof(enc) == 1, "E4M3 storage is one byte");
    std::memcpy(&bits, &enc, 1);
    return bits;
#else
    (void)v;
    return 0;
#endif
}

bool PackMuFp8KMajor(const std::vector<int8_t>& mu, uint32_t n, std::vector<uint8_t>& out)
{
    if (mu.size() != static_cast<size_t>(n) * n) return false;
    out.resize(static_cast<size_t>(n) * n);
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t k = 0; k < n; ++k) {
            const int8_t v = mu[static_cast<size_t>(i) * n + k];
            if (v < -11 || v > 11) return false;
            out[static_cast<size_t>(k) + static_cast<size_t>(i) * n] = EncodeE4M3Int(v);
        }
    }
    return true;
}

bool PackVFp8KMajor(const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                    std::vector<uint8_t>& out)
{
    if (V.size() != static_cast<size_t>(n) * m) return false;
    out.resize(static_cast<size_t>(n) * m);
    for (uint32_t c = 0; c < m; ++c) {
        for (uint32_t k = 0; k < n; ++k) {
            const int8_t v = V[static_cast<size_t>(k) * m + c];
            if (v < -48 || v > 48) return false;
            out[static_cast<size_t>(k) + static_cast<size_t>(c) * n] = EncodeE4M3Int(v);
        }
    }
    return true;
}

bool PackMuE2M1KMajor(const std::vector<int8_t>& mu, uint32_t n, std::vector<uint8_t>& out)
{
    if (mu.size() != static_cast<size_t>(n) * n) return false;
    out.assign((static_cast<size_t>(n) * n + 1u) / 2u, 0);
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t k = 0; k < n; ++k) {
            const uint8_t nib = EncodeE2M1Nibble(mu[static_cast<size_t>(i) * n + k]);
            if (nib > 0x0F) return false;
            PackE2M1Nibble(out.data(), static_cast<size_t>(k) + static_cast<size_t>(i) * n, nib);
        }
    }
    return true;
}

bool PackVE2M1KMajor(const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                     std::vector<uint8_t>& out)
{
    if (V.size() != static_cast<size_t>(n) * m) return false;
    out.assign((static_cast<size_t>(n) * m + 1u) / 2u, 0);
    for (uint32_t c = 0; c < m; ++c) {
        for (uint32_t k = 0; k < n; ++k) {
            const uint8_t nib = EncodeE2M1Nibble(V[static_cast<size_t>(k) * m + c]);
            if (nib > 0x0F) return false;
            PackE2M1Nibble(out.data(), static_cast<size_t>(k) + static_cast<size_t>(c) * n, nib);
        }
    }
    return true;
}

bool Fp32ColMajorToExactInt32RowMajor(const std::vector<float>& D, uint32_t n, uint32_t m,
                                      std::vector<int32_t>& out)
{
    if (D.size() != static_cast<size_t>(n) * m) return false;
    out.resize(static_cast<size_t>(n) * m);
    for (uint32_t c = 0; c < m; ++c) {
        for (uint32_t i = 0; i < n; ++i) {
            const float f = D[static_cast<size_t>(c) * n + i];
            if (!std::isfinite(f)) return false;
            const float rounded = nearbyintf(f);
            if (rounded != f) return false;
            if (rounded < static_cast<float>(std::numeric_limits<int32_t>::min()) ||
                rounded > static_cast<float>(std::numeric_limits<int32_t>::max())) {
                return false;
            }
            out[static_cast<size_t>(i) * m + c] = static_cast<int32_t>(rounded);
        }
    }
    return true;
}

#if defined(BTX_LT_CUDA_HAS_MX_SCALE_MODES)

struct DeviceBuf {
    void* p{nullptr};
    size_t bytes{0};
    ~DeviceBuf() { Reset(); }
    void Reset()
    {
        if (p) {
            cudaFree(p);
            p = nullptr;
            bytes = 0;
        }
    }
    [[nodiscard]] bool Alloc(size_t n)
    {
        Reset();
        if (n == 0) return true;
        if (cudaMalloc(&p, n) != cudaSuccess) {
            p = nullptr;
            return false;
        }
        bytes = n;
        return true;
    }
};

[[nodiscard]] bool Upload(DeviceBuf& dst, const void* host, size_t bytes)
{
    if (!dst.Alloc(bytes)) return false;
    return cudaMemcpy(dst.p, host, bytes, cudaMemcpyHostToDevice) == cudaSuccess;
}

bool RunCublasLtBlockScaledTn(cudaDataType_t ab_type, cublasLtMatmulMatrixScale_t scale_mode,
                              const void* dA, const void* dB, const void* dSFa, const void* dSFb,
                              float* dD, uint32_t M, uint32_t N, uint32_t K, void* workspace,
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

        if (cublasLtMatrixLayoutCreate(&a_layout, ab_type, K, M, K) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatrixLayoutCreate(&b_layout, ab_type, K, N, K) != CUBLAS_STATUS_SUCCESS ||
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
                           /*stream=*/0) != CUBLAS_STATUS_SUCCESS) {
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

// 0 = declined (no algo / OOM / pack), 1 = kernel ran but non-integral FP32,
// 2 = exact int32 out.
[[nodiscard]] int LaunchPackedBlockScaledProjection(cudaDataType_t ab_type,
                                                    cublasLtMatmulMatrixScale_t scale_mode,
                                                    const std::vector<uint8_t>& A_pack,
                                                    const std::vector<uint8_t>& B_pack,
                                                    const std::vector<uint8_t>& SFa,
                                                    const std::vector<uint8_t>& SFb, uint32_t n,
                                                    uint32_t m, std::vector<int32_t>& out)
{
    out.clear();
    DeviceBuf dA, dB, dSFa, dSFb, dD, dWS;
    constexpr size_t kWorkspace = 32ull * 1024ull * 1024ull;
    if (!Upload(dA, A_pack.data(), A_pack.size()) || !Upload(dB, B_pack.data(), B_pack.size()) ||
        !Upload(dSFa, SFa.data(), SFa.size()) || !Upload(dSFb, SFb.data(), SFb.size()) ||
        !dD.Alloc(static_cast<size_t>(n) * m * sizeof(float)) || !dWS.Alloc(kWorkspace)) {
        return 0;
    }
    if (cudaMemset(dD.p, 0, dD.bytes) != cudaSuccess) return 0;

    if (!RunCublasLtBlockScaledTn(ab_type, scale_mode, dA.p, dB.p, dSFa.p, dSFb.p,
                                  static_cast<float*>(dD.p), n, m, n, dWS.p, kWorkspace)) {
        return 0;
    }

    std::vector<float> host_d(static_cast<size_t>(n) * m);
    if (cudaMemcpy(host_d.data(), dD.p, host_d.size() * sizeof(float), cudaMemcpyDeviceToHost) !=
        cudaSuccess) {
        return 0;
    }
    if (!Fp32ColMajorToExactInt32RowMajor(host_d, n, m, out)) {
        out.clear();
        return 1;
    }
    return 2;
}

#endif // BTX_LT_CUDA_HAS_MX_SCALE_MODES

[[nodiscard]] bool AttemptCublasLtBlockScaledFp8(const std::vector<int8_t>& mu,
                                                 const std::vector<uint8_t>& scales,
                                                 const std::vector<int8_t>& V, uint32_t n,
                                                 uint32_t m, std::vector<int32_t>& out,
                                                 bool* numeric_fail = nullptr)
{
    out.clear();
    if (numeric_fail) *numeric_fail = false;
#if !defined(BTX_LT_CUDA_HAS_FP8_E4M3) || !defined(BTX_LT_CUDA_HAS_VEC32_UE8M0)
    (void)mu;
    (void)scales;
    (void)V;
    (void)n;
    (void)m;
    return false;
#else
    if (n == 0 || m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) return false;
    const uint32_t nblk = n / matmul::v4::lt::kMatExpandMxBlockLen;
    if (mu.size() != static_cast<size_t>(n) * n ||
        scales.size() != static_cast<size_t>(n) * nblk ||
        V.size() != static_cast<size_t>(n) * m) {
        return false;
    }

    std::vector<uint8_t> A_pack, B_pack, SFa, SFb;
    if (!PackMuFp8KMajor(mu, n, A_pack) || !PackVFp8KMajor(V, n, m, B_pack) ||
        !PackBtxScalesVec32Ue8m0(scales, n, n, SFa)) {
        return false;
    }
    FillUnitBlockScales(SFb, m, n, 32, Ue8m0UnitCode());

    const int rc = LaunchPackedBlockScaledProjection(
        CUDA_R_8F_E4M3, CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0, A_pack, B_pack, SFa, SFb, n, m,
        out);
    if (rc == 1 && numeric_fail) *numeric_fail = true;
    return rc == 2;
#endif
}

[[nodiscard]] bool AttemptCublasLtBlockScaledFp4(const std::vector<int8_t>& mu,
                                                 const std::vector<uint8_t>& scales,
                                                 const std::vector<int8_t>& V, uint32_t n,
                                                 uint32_t m, std::vector<int32_t>& out,
                                                 bool* numeric_fail = nullptr)
{
    out.clear();
    if (numeric_fail) *numeric_fail = false;
#if !defined(BTX_LT_CUDA_HAS_FP4_E2M1) || !defined(BTX_LT_CUDA_HAS_MX_SCALE_MODES)
    (void)mu;
    (void)scales;
    (void)V;
    (void)n;
    (void)m;
    return false;
#else
    if (n == 0 || m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) return false;
    const uint32_t nblk = n / matmul::v4::lt::kMatExpandMxBlockLen;
    if (mu.size() != static_cast<size_t>(n) * n ||
        scales.size() != static_cast<size_t>(n) * nblk ||
        V.size() != static_cast<size_t>(n) * m) {
        return false;
    }

    std::vector<uint8_t> A_pack, B_pack, SFa, SFb;
    if (!PackMuE2M1KMajor(mu, n, A_pack) || !PackVE2M1KMajor(V, n, m, B_pack)) {
        return false;
    }

#if defined(BTX_LT_CUDA_HAS_VEC32_UE8M0)
    if (PackBtxScalesVec32Ue8m0(scales, n, n, SFa)) {
        FillUnitBlockScales(SFb, m, n, 32, Ue8m0UnitCode());
        const int rc = LaunchPackedBlockScaledProjection(
            CUDA_R_4F_E2M1, CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0, A_pack, B_pack, SFa, SFb, n,
            m, out);
        if (rc == 2) return true;
        if (rc == 1) {
            if (numeric_fail) *numeric_fail = true;
            return false;
        }
    }
#endif

#if defined(BTX_LT_CUDA_HAS_VEC16_UE4M3)
    if (PackBtxScalesVec16Ue4m3Duplicated(scales, n, n, SFa)) {
        FillUnitBlockScales(SFb, m, n, 16, Ue4m3CodeFromPow2Exponent(0));
        const int rc = LaunchPackedBlockScaledProjection(
            CUDA_R_4F_E2M1, CUBLASLT_MATMUL_MATRIX_SCALE_VEC16_UE4M3, A_pack, B_pack, SFa, SFb, n,
            m, out);
        if (rc == 2) return true;
        if (rc == 1) {
            if (numeric_fail) *numeric_fail = true;
            return false;
        }
    }
#endif
    return false;
#endif
}

[[nodiscard]] bool AttemptCutlassOcpMxfp4(const std::vector<int8_t>& mu,
                                          const std::vector<uint8_t>& scales,
                                          const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                          std::vector<int32_t>& out)
{
    std::string err;
    return lt_cutlass_mxfp4::TryLaunchCutlassMxfp4ProjectedRight(mu, scales, V, n, m, out, &err);
}

[[nodiscard]] bool AttemptNativeMxfp4Any(const std::vector<int8_t>& mu,
                                         const std::vector<uint8_t>& scales,
                                         const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                         std::vector<int32_t>& out)
{
    bool numeric_fail = false;
    if (AttemptCublasLtBlockScaledFp4(mu, scales, V, n, m, out, &numeric_fail)) {
        if (matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
            return true;
        }
        out.clear();
        return false;
    }
    if (numeric_fail) {
        out.clear();
        return false;
    }
    if (AttemptCutlassOcpMxfp4(mu, scales, V, n, m, out) &&
        matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        return true;
    }
    out.clear();
    return false;
}

void FillQualFixture(uint32_t n, uint32_t m, bool max_corner, std::vector<int8_t>& mu,
                     std::vector<uint8_t>& scales, std::vector<int8_t>& V)
{
    const uint32_t nblk = n / matmul::v4::lt::kMatExpandMxBlockLen;
    mu.assign(static_cast<size_t>(n) * n, 0);
    scales.assign(static_cast<size_t>(n) * nblk, 0);
    V.assign(static_cast<size_t>(n) * m, 0);
    static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    for (uint32_t i = 0; i < n * n; ++i) {
        mu[i] = max_corner ? static_cast<int8_t>((i & 1u) ? -6 : 6) : kM11[i % 11];
    }
    for (uint32_t i = 0; i < n * nblk; ++i) {
        scales[i] = max_corner ? static_cast<uint8_t>(3) : static_cast<uint8_t>(i & 3u);
    }
    for (uint32_t i = 0; i < n * m; ++i) {
        V[i] = max_corner ? static_cast<int8_t>((i % 3u == 0) ? -6 : 6)
                          : kM11[(i * 3 + 1) % 11];
    }
}

void RunNativeSelfQualOnceLocked()
{
    if (g_native_qual_ran) return;
    g_native_qual_ran = true;

    const btx::cuda::CudaRuntimeProbe runtime = btx::cuda::ProbeCudaRuntime();
    if (!runtime.compiled || !runtime.available || runtime.device_index < 0) {
        return;
    }
    cudaDeviceProp props{};
    if (cudaGetDeviceProperties(&props, runtime.device_index) != cudaSuccess) {
        return;
    }

    const bool cutlass_compiled = lt_cutlass_mxfp4::IsLtCutlassMxfp4Compiled();
    g_native_mxfp4_attempted =
        (ToolkitDeclaresFp4() && ToolkitDeclaresMxScaleModes()) || cutlass_compiled;
    g_native_fp8_attempted = ToolkitDeclaresFp8() && ToolkitDeclaresVec32Ue8m0();

    // Blackwell is where stock MX heuristics live; non-Blackwell stays attempted
    // but not qualified unless a path actually matches the suite.
    if (!IsBlackwellSm(props.major, props.minor)) {
        return;
    }
    if (cudaSetDevice(runtime.device_index) != cudaSuccess) {
        return;
    }
    if (!g_native_mxfp4_attempted && !g_native_fp8_attempted) {
        return;
    }

    struct Shape {
        uint32_t n;
        uint32_t m;
        bool max_corner;
    };
    std::vector<Shape> shapes = {
        {32, 16, false}, {32, 16, true},   {64, 32, false}, {64, 17, false},
        {128, 64, false}, {128, 64, true},
    };
    if (props.totalGlobalMem >= (512ull << 20)) {
        shapes.push_back({256, 128, false});
    }

    bool mxfp4_ok = g_native_mxfp4_attempted;
    bool fp8_ok = g_native_fp8_attempted;
    for (const auto& sh : shapes) {
        if ((sh.n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) {
            mxfp4_ok = false;
            fp8_ok = false;
            break;
        }
        std::vector<int8_t> mu, V;
        std::vector<uint8_t> scales;
        FillQualFixture(sh.n, sh.m, sh.max_corner, mu, scales, V);
        std::vector<int32_t> got;
        if (mxfp4_ok && !AttemptNativeMxfp4Any(mu, scales, V, sh.n, sh.m, got)) {
            mxfp4_ok = false;
        }
        if (fp8_ok) {
            if (!AttemptCublasLtBlockScaledFp8(mu, scales, V, sh.n, sh.m, got) ||
                !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, sh.n, sh.m, got)) {
                fp8_ok = false;
            }
        }
        if (!mxfp4_ok && !fp8_ok) break;
    }
    g_native_mxfp4_qualified = mxfp4_ok;
    g_native_fp8_qualified = fp8_ok;
}

} // namespace

uint32_t LtCudaCompiledRuntimeVersion()
{
#if defined(CUDART_VERSION)
    return CUDART_VERSION;
#else
    return 0;
#endif
}

bool IsLtCudaCublasLtBlockScaleApiCompiled()
{
#if defined(BTX_LT_CUDA_HAS_MX_SCALE_MODES)
    return true;
#else
    return false;
#endif
}

matmul::v4::lt::MxLaneProvenance ProbeLtCudaMxNativeProvenance()
{
    std::lock_guard<std::mutex> lock(g_native_mx_mu);
    RunNativeSelfQualOnceLocked();
    matmul::v4::lt::MxLaneProvenance p;
    p.native_mxfp4_attempted = g_native_mxfp4_attempted;
    p.native_mxfp4_qualified = g_native_mxfp4_qualified;
    p.native_fp8_attempted = g_native_fp8_attempted;
    p.native_fp8_qualified = g_native_fp8_qualified;
    return p;
}

bool IsLtNativeMxfp4Qualified()
{
    std::lock_guard<std::mutex> lock(g_native_mx_mu);
    RunNativeSelfQualOnceLocked();
    return g_native_mxfp4_qualified;
}

bool IsLtNativeFp8Qualified()
{
    std::lock_guard<std::mutex> lock(g_native_mx_mu);
    RunNativeSelfQualOnceLocked();
    return g_native_fp8_qualified;
}

bool SelfQualifyLtNativeMxLanesOnce()
{
    std::lock_guard<std::mutex> lock(g_native_mx_mu);
    RunNativeSelfQualOnceLocked();
    return g_native_mxfp4_qualified || g_native_fp8_qualified;
}

bool TryLaunchNativeMxfp4ProjectedRight(const std::vector<int8_t>& mu,
                                        const std::vector<uint8_t>& scales,
                                        const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                        std::vector<int32_t>& out,
                                        matmul::v4::lt::MxLaneProvenance* provenance)
{
    std::lock_guard<std::mutex> lock(g_native_mx_mu);
    g_native_mxfp4_attempted = true;
    RunNativeSelfQualOnceLocked();
    if (provenance) {
        *provenance = {};
        provenance->native_mxfp4_attempted = true;
        provenance->native_mxfp4_qualified = false;
    }
    out.clear();
    // Production dispatch requires the full self-qual suite — never promote a
    // single-shape float hit to native_mxfp4_qualified.
    if (!g_native_mxfp4_qualified) {
        return false;
    }
    // Decline without revoking suite qual (e.g. non-M11 V cannot pack E2M1).
    // Revoke only when a kernel returns non-integral FP32 or fails the oracle.
    std::vector<int32_t> got;
    bool numeric_fail = false;
    if (AttemptCublasLtBlockScaledFp4(mu, scales, V, n, m, got, &numeric_fail)) {
        if (matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) {
            out = std::move(got);
            if (provenance) provenance->native_mxfp4_qualified = true;
            return true;
        }
        g_native_mxfp4_qualified = false;
        return false;
    }
    if (numeric_fail) {
        g_native_mxfp4_qualified = false;
        return false;
    }
    if (AttemptCutlassOcpMxfp4(mu, scales, V, n, m, got)) {
        if (matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) {
            out = std::move(got);
            if (provenance) provenance->native_mxfp4_qualified = true;
            return true;
        }
        g_native_mxfp4_qualified = false;
        return false;
    }
    return false;
}

bool TryLaunchNativeFp8ProjectedRight(const std::vector<int8_t>& mu,
                                      const std::vector<uint8_t>& scales,
                                      const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                      std::vector<int32_t>& out,
                                      matmul::v4::lt::MxLaneProvenance* provenance)
{
    std::lock_guard<std::mutex> lock(g_native_mx_mu);
    g_native_fp8_attempted = true;
    RunNativeSelfQualOnceLocked();
    if (provenance) {
        *provenance = {};
        provenance->native_fp8_attempted = true;
        provenance->native_fp8_qualified = false;
    }
    out.clear();
    if (!g_native_fp8_qualified) {
        return false;
    }
    std::vector<int32_t> got;
    bool numeric_fail = false;
    if (!AttemptCublasLtBlockScaledFp8(mu, scales, V, n, m, got, &numeric_fail)) {
        if (numeric_fail) g_native_fp8_qualified = false;
        return false;
    }
    if (!matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) {
        g_native_fp8_qualified = false;
        return false;
    }
    out = std::move(got);
    if (provenance) provenance->native_fp8_qualified = true;
    return true;
}

bool IsLtPeakMxCapableDevice()
{
    const btx::cuda::CudaRuntimeProbe runtime = btx::cuda::ProbeCudaRuntime();
    if (!runtime.compiled || !runtime.available || runtime.device_index < 0) {
        return false;
    }
    cudaDeviceProp props{};
    if (cudaGetDeviceProperties(&props, runtime.device_index) != cudaSuccess) {
        return false;
    }
    return IsBlackwellSm(props.major, props.minor);
}

matmul::v4::lt::LtPeakMxPathStatus ProbeLtPeakMxPathStatus()
{
    // Single self-qual via provenance probe (avoids nested mutex locks).
    const auto prov = ProbeLtCudaMxNativeProvenance();
    matmul::v4::lt::LtPeakMxPathStatus s;
    s.peak_capable = IsLtPeakMxCapableDevice();
    s.native_mxfp4_attempted = prov.native_mxfp4_attempted;
    s.native_mxfp4_qualified = prov.native_mxfp4_qualified;
    s.native_fp8_attempted = prov.native_fp8_attempted;
    s.native_fp8_qualified = prov.native_fp8_qualified;
    // The native launchers above currently serve only the host-vector
    // projection surface. LtCudaResidentPool still executes the exact INT8
    // scale-partitioned projection, so capability must not be reported as an
    // end-to-end resident native path.
    s.resident_native_mx_wired = false;
    s.peak_ready = s.peak_capable && s.resident_native_mx_wired &&
                   (s.native_mxfp4_qualified || s.native_fp8_qualified);
    s.allow_exact_mx_fallback = matmul::v4::lt::AllowLtExactMxFallback();
    s.peak_required = s.peak_capable && !s.allow_exact_mx_fallback;
    s.blocks_device_resident = s.peak_required && !s.peak_ready;
    if (!s.peak_capable) {
        s.deficit_reason.clear();
    } else if (s.peak_ready) {
        s.deficit_reason.clear();
    } else if (s.allow_exact_mx_fallback) {
        s.deficit_reason =
            "peak-capable GPU does not have an end-to-end resident native MX path; "
            "the oracle-qualified exact INT8 MX resident path remains enabled. "
            "Do not label its rate native-MX or peak-ready.";
    } else {
        s.deficit_reason =
            "BTX_MATMUL_V4_LT_REQUIRE_NATIVE_MX=1 requested an end-to-end resident "
            "native MXFP4/MXFP8 path, but it is not wired and oracle-qualified; "
            "resident LT is intentionally blocked for this qualification run.";
    }
    return s;
}

void DiagnoseLtPeakMxPathOnce()
{
    static std::once_flag once;
    std::call_once(once, [] {
        const auto s = ProbeLtPeakMxPathStatus();
        if (!s.peak_capable) {
            matmul::v4::lt::LogLtMxDiagnostic(
                "MatMul-v4.4-LT CUDA MX: device is not Blackwell-class "
                "(sm_10x/sm_12x); exact INT8 MX scale-partitioned resident path "
                "remains enabled.\n");
            return;
        }
        if (s.peak_ready) {
            matmul::v4::lt::LogLtMxDiagnostic(
                "MatMul-v4.4-LT CUDA MX PEAK READY: resident native MX is wired and "
                "oracle-qualified.\n");
            return;
        }
        matmul::v4::lt::LogLtMxDiagnostic(
            "MatMul-v4.4-LT CUDA MX PEAK DEFICIT: " + s.deficit_reason + "\n");
        matmul::v4::lt::LogLtMxDiagnostic(
            "MatMul-v4.4-LT CUDA MX ACTION REQUIRED: wire and self-qualify the native "
            "path before using native-MX/peak-ready labels; exact INT8 results remain "
            "bit-exact fallback evidence only.\n");
    });
}

bool LtPeakMxBlocksDeviceResident()
{
    DiagnoseLtPeakMxPathOnce();
    return ProbeLtPeakMxPathStatus().blocks_device_resident;
}

} // namespace matmul_v4::cuda
