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
#include <climits>
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
// End-to-end resident Q* graph uses native projection (device μ/e/V → dQ).
bool g_resident_native_mx_wired{false};
bool g_resident_native_mx_attempted{false};
/** True only after a native oracle pass at n ≥ kLtProductionShapeMinDim (4096). */
bool g_production_shape_qualified{false};
std::string g_qual_arch_key; // Amendment v2 §1.SCOPE — per-arch, not per-card
std::string g_resident_deficit_detail;

[[nodiscard]] bool IsBlackwellSm(int major, int minor)
{
    (void)minor;
    // Peak-capable class: consumer sm_12x and datacenter sm_10x. Qualification
    // is PER-ARCH (Amendment v2 §1.SCOPE) — sm_120 ≠ sm_100.
    return (major == 10) || (major == 12);
}

[[nodiscard]] std::string FormatCudaArchKey(int major, int minor)
{
    return "sm_" + std::to_string(major * 10 + minor);
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
                              size_t workspace_bytes, cudaStream_t stream, bool sync_stream = true)
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
                           stream) != CUBLAS_STATUS_SUCCESS) {
            break;
        }
        // Host-vector lanes sync; resident device-pointer hot path stays async
        // on the caller's stream (amendment 1.A — no device sync on hot path).
        if (sync_stream) {
            if (stream == nullptr) {
                if (cudaDeviceSynchronize() != cudaSuccess) break;
            } else if (cudaStreamSynchronize(stream) != cudaSuccess) {
                break;
            }
        }
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
                                  static_cast<float*>(dD.p), n, m, n, dWS.p, kWorkspace,
                                  /*stream=*/nullptr)) {
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

// ---------------------------------------------------------------------------
// Resident Q* native projection — CRITICAL AMENDMENTS
//
// 1.A  DEVICE-POINTER HOT PATH: inputs stay on device (d_mu/d_scales/d_V/d_Q).
//      Device pack kernels write cuBLASLt FP4/FP8 + UE8M0 layouts; cuBLASLt +
//      FP32→int32 convert run on the SAME stream. NO full-tensor D2H/H2D and
//      NO cudaDeviceSynchronize on the hot path. Never call
//      TryLaunchNativeMxfp4ProjectedRight from the resident pool.
// 1.B  RC ≠ LT for native FP4: LT self-qual (Q ≪ 2^24) does NOT admit RC
//      S·V / wgrad (see matmul_v4_rc_mx_ozaki / Ozaki plan). peak_ready for
//      LT still requires production dims + actual resident layouts on silicon.
// 1.C  Staging telemetry: diagnose before changing chat staging; INT8
//      scale-partition remains the fail-closed fallback and is NEVER labeled
//      native-MX.
// ---------------------------------------------------------------------------

#if defined(BTX_LT_CUDA_HAS_MX_SCALE_MODES)

__device__ inline uint8_t DevEncodeE2M1Nibble(int8_t mu)
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

__device__ inline size_t DevBlockScaleOffset(size_t r, size_t c, size_t K, size_t vec)
{
    const size_t kblocks = (K + vec - 1u) / vec;
    const size_t cols = ((kblocks + 3u) / 4u) * 4u;
    const size_t n_k_tiles = cols / 4u;
    return (r % 32u) * 16u + ((r % 128u) / 32u) * 4u + (c % 4u) + (c / 4u) * 512u +
           (r / 128u) * 512u * n_k_tiles;
}

#if defined(BTX_LT_CUDA_HAS_FP8_E4M3)
__device__ inline uint8_t DevEncodeE4M3Int(int8_t v)
{
    const __nv_fp8_e4m3 enc{static_cast<float>(v)};
    uint8_t bits = 0;
    memcpy(&bits, &enc, 1);
    return bits;
}
#endif

// One thread per packed byte (two K-major E2M1 elements) — race-free.
__global__ void PackMuE2M1KMajorKernel(const int8_t* __restrict__ mu, uint8_t* __restrict__ out,
                                       uint32_t n, int* __restrict__ fail)
{
    const size_t tid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t nbytes = (static_cast<size_t>(n) * n + 1u) / 2u;
    if (tid >= nbytes) return;
    const size_t lin0 = tid * 2u;
    const size_t lin1 = lin0 + 1u;
    const uint32_t i0 = static_cast<uint32_t>(lin0 / n);
    const uint32_t k0 = static_cast<uint32_t>(lin0 % n);
    const uint8_t n0 = DevEncodeE2M1Nibble(mu[static_cast<size_t>(i0) * n + k0]);
    if (n0 > 0x0F) {
        atomicExch(fail, 1);
        return;
    }
    uint8_t byte = n0;
    if (lin1 < static_cast<size_t>(n) * n) {
        const uint32_t i1 = static_cast<uint32_t>(lin1 / n);
        const uint32_t k1 = static_cast<uint32_t>(lin1 % n);
        const uint8_t n1 = DevEncodeE2M1Nibble(mu[static_cast<size_t>(i1) * n + k1]);
        if (n1 > 0x0F) {
            atomicExch(fail, 1);
            return;
        }
        byte = static_cast<uint8_t>(byte | static_cast<uint8_t>(n1 << 4));
    }
    out[tid] = byte;
}

__global__ void PackVE2M1KMajorKernel(const int8_t* __restrict__ V, uint8_t* __restrict__ out,
                                      uint32_t n, uint32_t m, int* __restrict__ fail)
{
    const size_t tid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t nbytes = (static_cast<size_t>(n) * m + 1u) / 2u;
    if (tid >= nbytes) return;
    const size_t lin0 = tid * 2u;
    const size_t lin1 = lin0 + 1u;
    const uint32_t c0 = static_cast<uint32_t>(lin0 / n);
    const uint32_t k0 = static_cast<uint32_t>(lin0 % n);
    const uint8_t n0 = DevEncodeE2M1Nibble(V[static_cast<size_t>(k0) * m + c0]);
    if (n0 > 0x0F) {
        atomicExch(fail, 1);
        return;
    }
    uint8_t byte = n0;
    if (lin1 < static_cast<size_t>(n) * m) {
        const uint32_t c1 = static_cast<uint32_t>(lin1 / n);
        const uint32_t k1 = static_cast<uint32_t>(lin1 % n);
        const uint8_t n1 = DevEncodeE2M1Nibble(V[static_cast<size_t>(k1) * m + c1]);
        if (n1 > 0x0F) {
            atomicExch(fail, 1);
            return;
        }
        byte = static_cast<uint8_t>(byte | static_cast<uint8_t>(n1 << 4));
    }
    out[tid] = byte;
}

#if defined(BTX_LT_CUDA_HAS_FP8_E4M3)
__global__ void PackMuFp8KMajorKernel(const int8_t* __restrict__ mu, uint8_t* __restrict__ out,
                                      uint32_t n, int* __restrict__ fail)
{
    const size_t tid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t nelem = static_cast<size_t>(n) * n;
    if (tid >= nelem) return;
    const uint32_t i = static_cast<uint32_t>(tid / n);
    const uint32_t k = static_cast<uint32_t>(tid % n);
    const int8_t v = mu[static_cast<size_t>(i) * n + k];
    if (v < -11 || v > 11) {
        atomicExch(fail, 1);
        return;
    }
    out[static_cast<size_t>(k) + static_cast<size_t>(i) * n] = DevEncodeE4M3Int(v);
}

__global__ void PackVFp8KMajorKernel(const int8_t* __restrict__ V, uint8_t* __restrict__ out,
                                     uint32_t n, uint32_t m, int* __restrict__ fail)
{
    const size_t tid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t nelem = static_cast<size_t>(n) * m;
    if (tid >= nelem) return;
    const uint32_t c = static_cast<uint32_t>(tid / n);
    const uint32_t k = static_cast<uint32_t>(tid % n);
    const int8_t v = V[static_cast<size_t>(k) * m + c];
    if (v < -48 || v > 48) {
        atomicExch(fail, 1);
        return;
    }
    out[static_cast<size_t>(k) + static_cast<size_t>(c) * n] = DevEncodeE4M3Int(v);
}
#endif

__global__ void PackBtxScalesVec32Ue8m0Kernel(const uint8_t* __restrict__ btx_e,
                                             uint8_t* __restrict__ out, uint32_t rows, uint32_t K,
                                             int* __restrict__ fail)
{
    const uint32_t nblk = K / 32u;
    const size_t tid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t nslot = static_cast<size_t>(rows) * nblk;
    if (tid >= nslot) return;
    const uint32_t r = static_cast<uint32_t>(tid / nblk);
    const uint32_t bj = static_cast<uint32_t>(tid % nblk);
    const uint8_t e = btx_e[tid];
    if (e > 3u) {
        atomicExch(fail, 1);
        return;
    }
    out[DevBlockScaleOffset(r, bj, K, 32)] = static_cast<uint8_t>(127u + e);
}

__global__ void FillUnitBlockScalesKernel(uint8_t* __restrict__ out, uint32_t outer, uint32_t K,
                                          uint32_t vec, uint8_t unit_code)
{
    const uint32_t kblocks = (K + vec - 1u) / vec;
    const size_t tid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t nslot = static_cast<size_t>(outer) * kblocks;
    if (tid >= nslot) return;
    const uint32_t r = static_cast<uint32_t>(tid / kblocks);
    const uint32_t c = static_cast<uint32_t>(tid % kblocks);
    out[DevBlockScaleOffset(r, c, K, vec)] = unit_code;
}

#if defined(BTX_LT_CUDA_HAS_VEC16_UE4M3) && defined(BTX_LT_CUDA_HAS_FP8_E4M3)
__global__ void PackBtxScalesVec16Ue4m3DupKernel(const uint8_t* __restrict__ btx_e,
                                                uint8_t* __restrict__ out, uint32_t rows,
                                                uint32_t K, int* __restrict__ fail)
{
    const uint32_t nblk32 = K / 32u;
    const size_t tid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t nslot = static_cast<size_t>(rows) * nblk32;
    if (tid >= nslot) return;
    const uint32_t r = static_cast<uint32_t>(tid / nblk32);
    const uint32_t bj = static_cast<uint32_t>(tid % nblk32);
    const uint8_t e = btx_e[tid];
    if (e > 3u) {
        atomicExch(fail, 1);
        return;
    }
    const __nv_fp8_e4m3 enc{static_cast<float>(1u << e)};
    uint8_t code = 0;
    memcpy(&code, &enc, 1);
    const size_t c0 = static_cast<size_t>(bj) * 2u;
    out[DevBlockScaleOffset(r, c0, K, 16)] = code;
    out[DevBlockScaleOffset(r, c0 + 1u, K, 16)] = code;
}
#endif

__global__ void Fp32ColMajorToExactInt32RowMajorKernel(const float* __restrict__ D,
                                                       int32_t* __restrict__ Q, uint32_t n,
                                                       uint32_t m, int* __restrict__ fail)
{
    const size_t tid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t nelem = static_cast<size_t>(n) * m;
    if (tid >= nelem) return;
    const uint32_t i = static_cast<uint32_t>(tid / m);
    const uint32_t c = static_cast<uint32_t>(tid % m);
    const float f = D[static_cast<size_t>(c) * n + i];
    if (!isfinite(f)) {
        atomicExch(fail, 1);
        return;
    }
    const float rounded = nearbyintf(f);
    if (rounded != f) {
        atomicExch(fail, 1);
        return;
    }
    if (rounded < static_cast<float>(INT32_MIN) || rounded > static_cast<float>(INT32_MAX)) {
        atomicExch(fail, 1);
        return;
    }
    Q[static_cast<size_t>(i) * m + c] = static_cast<int32_t>(rounded);
}

// Process-persistent scratch: same-stream reuse is ordered; grow-only allocs.
struct ResidentDeviceScratch {
    DeviceBuf dA;
    DeviceBuf dB;
    DeviceBuf dSFa;
    DeviceBuf dSFb;
    DeviceBuf dD;
    DeviceBuf dWS;
    DeviceBuf dFail;
    size_t a_bytes{0};
    size_t b_bytes{0};
    size_t sfa_bytes{0};
    size_t sfb_bytes{0};
    size_t d_bytes{0};

    [[nodiscard]] bool Ensure(size_t a, size_t b, size_t sfa, size_t sfb, size_t d_elems)
    {
        constexpr size_t kWorkspace = 32ull * 1024ull * 1024ull;
        auto grow = [](DeviceBuf& buf, size_t& cap, size_t need) -> bool {
            if (need <= cap && buf.p != nullptr) return true;
            if (!buf.Alloc(need)) return false;
            cap = need;
            return true;
        };
        if (!grow(dA, a_bytes, a) || !grow(dB, b_bytes, b) || !grow(dSFa, sfa_bytes, sfa) ||
            !grow(dSFb, sfb_bytes, sfb) ||
            !grow(dD, d_bytes, d_elems * sizeof(float))) {
            return false;
        }
        if (dWS.p == nullptr || dWS.bytes < kWorkspace) {
            if (!dWS.Alloc(kWorkspace)) return false;
        }
        if (dFail.p == nullptr || dFail.bytes < sizeof(int)) {
            if (!dFail.Alloc(sizeof(int))) return false;
        }
        return true;
    }
};

ResidentDeviceScratch& ResidentScratch()
{
    static ResidentDeviceScratch s;
    return s;
}

[[nodiscard]] inline unsigned PackGrid(size_t n, unsigned block = 256)
{
    return static_cast<unsigned>((n + block - 1u) / block);
}

// 0 = declined, 1 = numeric/pack fail (after sync), 2 = launched (or exact after sync).
[[nodiscard]] int LaunchDevicePackedProjectionOnStream(
    cudaDataType_t ab_type, cublasLtMatmulMatrixScale_t scale_mode, uint32_t n, uint32_t m,
    int32_t* d_Q, cudaStream_t stream, bool sync_exactness_gate)
{
    auto& scratch = ResidentScratch();
    constexpr size_t kWorkspace = 32ull * 1024ull * 1024ull;
    // Do not clear dFail here — pack kernels own the flag; convert may set it.
    if (cudaMemsetAsync(scratch.dD.p, 0, scratch.dD.bytes, stream) != cudaSuccess) return 0;
    if (!RunCublasLtBlockScaledTn(ab_type, scale_mode, scratch.dA.p, scratch.dB.p, scratch.dSFa.p,
                                  scratch.dSFb.p, static_cast<float*>(scratch.dD.p), n, m, n,
                                  scratch.dWS.p, kWorkspace, stream,
                                  /*sync_stream=*/false)) {
        return 0;
    }
    {
        const size_t nelem = static_cast<size_t>(n) * m;
        Fp32ColMajorToExactInt32RowMajorKernel<<<PackGrid(nelem), 256, 0, stream>>>(
            static_cast<const float*>(scratch.dD.p), d_Q, n, m, static_cast<int*>(scratch.dFail.p));
        if (cudaGetLastError() != cudaSuccess) return 0;
    }
    if (!sync_exactness_gate) {
        return 2; // hot path: stay async on caller's stream
    }
    if (cudaStreamSynchronize(stream) != cudaSuccess) return 0;
    int host_fail = 0;
    if (cudaMemcpy(&host_fail, scratch.dFail.p, sizeof(int), cudaMemcpyDeviceToHost) !=
        cudaSuccess) {
        return 0;
    }
    return host_fail == 0 ? 2 : 1;
}

[[nodiscard]] bool PackAndLaunchResidentFp4(const int8_t* d_mu, const uint8_t* d_scales,
                                            const int8_t* d_V, int32_t* d_Q, uint32_t n, uint32_t m,
                                            cudaStream_t stream, bool sync_exactness_gate,
                                            bool* numeric_fail)
{
    if (numeric_fail) *numeric_fail = false;
#if !defined(BTX_LT_CUDA_HAS_FP4_E2M1)
    (void)d_mu;
    (void)d_scales;
    (void)d_V;
    (void)d_Q;
    (void)n;
    (void)m;
    (void)stream;
    (void)sync_exactness_gate;
    return false;
#else
    auto& scratch = ResidentScratch();
    const size_t a_bytes = (static_cast<size_t>(n) * n + 1u) / 2u;
    const size_t b_bytes = (static_cast<size_t>(n) * m + 1u) / 2u;

#if defined(BTX_LT_CUDA_HAS_VEC32_UE8M0)
    {
        const size_t sfa = BlockScaleTensorBytes(n, n, 32);
        const size_t sfb = BlockScaleTensorBytes(m, n, 32);
        if (!scratch.Ensure(a_bytes, b_bytes, sfa, sfb, static_cast<size_t>(n) * m)) return false;
        if (cudaMemsetAsync(scratch.dFail.p, 0, sizeof(int), stream) != cudaSuccess) return false;
        if (cudaMemsetAsync(scratch.dA.p, 0, a_bytes, stream) != cudaSuccess ||
            cudaMemsetAsync(scratch.dB.p, 0, b_bytes, stream) != cudaSuccess ||
            cudaMemsetAsync(scratch.dSFa.p, 0, sfa, stream) != cudaSuccess ||
            cudaMemsetAsync(scratch.dSFb.p, 0, sfb, stream) != cudaSuccess) {
            return false;
        }
        PackMuE2M1KMajorKernel<<<PackGrid(a_bytes), 256, 0, stream>>>(
            d_mu, static_cast<uint8_t*>(scratch.dA.p), n, static_cast<int*>(scratch.dFail.p));
        PackVE2M1KMajorKernel<<<PackGrid(b_bytes), 256, 0, stream>>>(
            d_V, static_cast<uint8_t*>(scratch.dB.p), n, m, static_cast<int*>(scratch.dFail.p));
        const size_t nscale = static_cast<size_t>(n) * (n / 32u);
        PackBtxScalesVec32Ue8m0Kernel<<<PackGrid(nscale), 256, 0, stream>>>(
            d_scales, static_cast<uint8_t*>(scratch.dSFa.p), n, n,
            static_cast<int*>(scratch.dFail.p));
        const size_t nunit = static_cast<size_t>(m) * (n / 32u);
        FillUnitBlockScalesKernel<<<PackGrid(nunit), 256, 0, stream>>>(
            static_cast<uint8_t*>(scratch.dSFb.p), m, n, 32, Ue8m0UnitCode());
        if (cudaGetLastError() != cudaSuccess) return false;
        const int rc = LaunchDevicePackedProjectionOnStream(
            CUDA_R_4F_E2M1, CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0, n, m, d_Q, stream,
            sync_exactness_gate);
        if (rc == 2) return true;
        if (rc == 1) {
            if (numeric_fail) *numeric_fail = true;
            return false;
        }
    }
#endif
#if defined(BTX_LT_CUDA_HAS_VEC16_UE4M3) && defined(BTX_LT_CUDA_HAS_FP8_E4M3)
    {
        const size_t sfa = BlockScaleTensorBytes(n, n, 16);
        const size_t sfb = BlockScaleTensorBytes(m, n, 16);
        if (!scratch.Ensure(a_bytes, b_bytes, sfa, sfb, static_cast<size_t>(n) * m)) return false;
        if (cudaMemsetAsync(scratch.dFail.p, 0, sizeof(int), stream) != cudaSuccess) return false;
        if (cudaMemsetAsync(scratch.dA.p, 0, a_bytes, stream) != cudaSuccess ||
            cudaMemsetAsync(scratch.dB.p, 0, b_bytes, stream) != cudaSuccess ||
            cudaMemsetAsync(scratch.dSFa.p, 0, sfa, stream) != cudaSuccess ||
            cudaMemsetAsync(scratch.dSFb.p, 0, sfb, stream) != cudaSuccess) {
            return false;
        }
        PackMuE2M1KMajorKernel<<<PackGrid(a_bytes), 256, 0, stream>>>(
            d_mu, static_cast<uint8_t*>(scratch.dA.p), n, static_cast<int*>(scratch.dFail.p));
        PackVE2M1KMajorKernel<<<PackGrid(b_bytes), 256, 0, stream>>>(
            d_V, static_cast<uint8_t*>(scratch.dB.p), n, m, static_cast<int*>(scratch.dFail.p));
        const size_t nscale = static_cast<size_t>(n) * (n / 32u);
        PackBtxScalesVec16Ue4m3DupKernel<<<PackGrid(nscale), 256, 0, stream>>>(
            d_scales, static_cast<uint8_t*>(scratch.dSFa.p), n, n,
            static_cast<int*>(scratch.dFail.p));
        const size_t nunit = static_cast<size_t>(m) * ((n + 15u) / 16u);
        FillUnitBlockScalesKernel<<<PackGrid(nunit), 256, 0, stream>>>(
            static_cast<uint8_t*>(scratch.dSFb.p), m, n, 16, Ue4m3CodeFromPow2Exponent(0));
        if (cudaGetLastError() != cudaSuccess) return false;
        const int rc = LaunchDevicePackedProjectionOnStream(
            CUDA_R_4F_E2M1, CUBLASLT_MATMUL_MATRIX_SCALE_VEC16_UE4M3, n, m, d_Q, stream,
            sync_exactness_gate);
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

[[nodiscard]] bool PackAndLaunchResidentFp8(const int8_t* d_mu, const uint8_t* d_scales,
                                            const int8_t* d_V, int32_t* d_Q, uint32_t n, uint32_t m,
                                            cudaStream_t stream, bool sync_exactness_gate,
                                            bool* numeric_fail)
{
    if (numeric_fail) *numeric_fail = false;
#if !defined(BTX_LT_CUDA_HAS_FP8_E4M3) || !defined(BTX_LT_CUDA_HAS_VEC32_UE8M0)
    (void)d_mu;
    (void)d_scales;
    (void)d_V;
    (void)d_Q;
    (void)n;
    (void)m;
    (void)stream;
    (void)sync_exactness_gate;
    return false;
#else
    auto& scratch = ResidentScratch();
    const size_t a_bytes = static_cast<size_t>(n) * n;
    const size_t b_bytes = static_cast<size_t>(n) * m;
    const size_t sfa = BlockScaleTensorBytes(n, n, 32);
    const size_t sfb = BlockScaleTensorBytes(m, n, 32);
    if (!scratch.Ensure(a_bytes, b_bytes, sfa, sfb, static_cast<size_t>(n) * m)) return false;
    if (cudaMemsetAsync(scratch.dFail.p, 0, sizeof(int), stream) != cudaSuccess) return false;
    if (cudaMemsetAsync(scratch.dSFa.p, 0, sfa, stream) != cudaSuccess ||
        cudaMemsetAsync(scratch.dSFb.p, 0, sfb, stream) != cudaSuccess) {
        return false;
    }
    PackMuFp8KMajorKernel<<<PackGrid(a_bytes), 256, 0, stream>>>(
        d_mu, static_cast<uint8_t*>(scratch.dA.p), n, static_cast<int*>(scratch.dFail.p));
    PackVFp8KMajorKernel<<<PackGrid(b_bytes), 256, 0, stream>>>(
        d_V, static_cast<uint8_t*>(scratch.dB.p), n, m, static_cast<int*>(scratch.dFail.p));
    const size_t nscale = static_cast<size_t>(n) * (n / 32u);
    PackBtxScalesVec32Ue8m0Kernel<<<PackGrid(nscale), 256, 0, stream>>>(
        d_scales, static_cast<uint8_t*>(scratch.dSFa.p), n, n, static_cast<int*>(scratch.dFail.p));
    const size_t nunit = static_cast<size_t>(m) * (n / 32u);
    FillUnitBlockScalesKernel<<<PackGrid(nunit), 256, 0, stream>>>(
        static_cast<uint8_t*>(scratch.dSFb.p), m, n, 32, Ue8m0UnitCode());
    if (cudaGetLastError() != cudaSuccess) return false;
    const int rc = LaunchDevicePackedProjectionOnStream(
        CUDA_R_8F_E4M3, CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0, n, m, d_Q, stream,
        sync_exactness_gate);
    if (rc == 1 && numeric_fail) *numeric_fail = true;
    return rc == 2;
#endif
}

/** Shared device-pointer core used by hot path and resident self-qual (1.A). */
[[nodiscard]] bool LaunchResidentNativeMxDeviceCore(
    const int8_t* d_mu, const uint8_t* d_scales, const int8_t* d_V, int32_t* d_Q, uint32_t n,
    uint32_t m, cudaStream_t stream, matmul::v4::lt::MxLaneProvenance* prov,
    bool sync_exactness_gate)
{
    if (d_mu == nullptr || d_scales == nullptr || d_V == nullptr || d_Q == nullptr || n == 0 ||
        m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) {
        return false;
    }
    bool numeric_fail = false;
    if (g_native_mxfp4_qualified &&
        PackAndLaunchResidentFp4(d_mu, d_scales, d_V, d_Q, n, m, stream, sync_exactness_gate,
                                 &numeric_fail)) {
        if (prov) {
            prov->native_mxfp4_attempted = true;
            prov->native_mxfp4_qualified = true;
            prov->exact_mx_scale_partitioned = false;
        }
        return true;
    }
    if (numeric_fail) return false;
    numeric_fail = false;
    if (g_native_fp8_qualified &&
        PackAndLaunchResidentFp8(d_mu, d_scales, d_V, d_Q, n, m, stream, sync_exactness_gate,
                                 &numeric_fail)) {
        if (prov) {
            prov->native_fp8_attempted = true;
            prov->native_fp8_qualified = true;
            prov->exact_mx_scale_partitioned = false;
        }
        return true;
    }
    return false;
}

#else // !BTX_LT_CUDA_HAS_MX_SCALE_MODES

[[nodiscard]] bool LaunchResidentNativeMxDeviceCore(const int8_t*, const uint8_t*, const int8_t*,
                                                    int32_t*, uint32_t, uint32_t, cudaStream_t,
                                                    matmul::v4::lt::MxLaneProvenance*, bool)
{
    return false;
}

#endif

[[nodiscard]] bool ResidentDeviceProjectionMatchesOracle(const std::vector<int8_t>& mu,
                                                         const std::vector<uint8_t>& scales,
                                                         const std::vector<int8_t>& V, uint32_t n,
                                                         uint32_t m, cudaStream_t stream)
{
#if !defined(BTX_LT_CUDA_HAS_MX_SCALE_MODES)
    (void)mu;
    (void)scales;
    (void)V;
    (void)n;
    (void)m;
    (void)stream;
    return false;
#else
    // Self-qual uses the SAME device-pointer core as the hot path (1.A):
    // upload fixtures once, then pack+GEMM+convert stay on device.
    DeviceBuf dMu, dScales, dV, dQ;
    if (!Upload(dMu, mu.data(), mu.size()) || !Upload(dScales, scales.data(), scales.size()) ||
        !Upload(dV, V.data(), V.size()) ||
        !dQ.Alloc(static_cast<size_t>(n) * m * sizeof(int32_t))) {
        return false;
    }
    matmul::v4::lt::MxLaneProvenance prov{};
    if (!LaunchResidentNativeMxDeviceCore(static_cast<const int8_t*>(dMu.p),
                                          static_cast<const uint8_t*>(dScales.p),
                                          static_cast<const int8_t*>(dV.p),
                                          static_cast<int32_t*>(dQ.p), n, m, stream, &prov,
                                          /*sync_exactness_gate=*/true)) {
        return false;
    }
    std::vector<int32_t> got(static_cast<size_t>(n) * m);
    if (cudaMemcpy(got.data(), dQ.p, got.size() * sizeof(int32_t), cudaMemcpyDeviceToHost) !=
        cudaSuccess) {
        return false;
    }
    if (!matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) return false;
    if (prov.exact_mx_scale_partitioned) return false;
    if (!prov.native_mxfp4_qualified && !prov.native_fp8_qualified) return false;
    return true;
#endif
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

void RunResidentNativeSelfQualLocked(cudaStream_t stream)
{
    g_resident_native_mx_attempted = true;
    g_resident_native_mx_wired = false;
    g_resident_deficit_detail.clear();

    if (!g_native_mxfp4_qualified && !g_native_fp8_qualified) {
        g_resident_deficit_detail =
            "standalone native MXFP4/FP8 did not byte-qualify vs CPU oracle";
        return;
    }

    // CI/medium shapes via the device-pointer entry. production_shape_qualified
    // (and thus peak_ready) additionally requires n ≥ kLtProductionShapeMinDim.
    // RC Ozaki remains a separate surface — this suite does not admit RC native FP4.
    struct Shape {
        uint32_t n;
        uint32_t m;
        bool max_corner;
    };
    std::vector<Shape> shapes = {
        {32, 16, false}, {32, 16, true}, {64, 32, false}, {128, 64, false},
        {128, 64, true}, {256, 64, false},
    };
    // Production latch: require real 4096-class shape when HBM allows (~mu+V+Q footprint).
    size_t free_b = 0, total_b = 0;
    const bool mem_ok =
        cudaMemGetInfo(&free_b, &total_b) == cudaSuccess &&
        free_b >= (6ull << 30); // ~6 GiB free headroom for n=4096 fixtures
    if (mem_ok) {
        shapes.push_back({matmul::v4::lt::kLtProductionShapeMinDim, 64, false});
        shapes.push_back({matmul::v4::lt::kLtProductionShapeMinDim, 64, true});
    }
    bool saw_production = false;
    for (const auto& sh : shapes) {
        std::vector<int8_t> mu, V;
        std::vector<uint8_t> scales;
        FillQualFixture(sh.n, sh.m, sh.max_corner, mu, scales, V);
        if (!ResidentDeviceProjectionMatchesOracle(mu, scales, V, sh.n, sh.m, stream)) {
            g_resident_deficit_detail =
                "resident device-pointer native projection mismatched CPU oracle at n=" +
                std::to_string(sh.n);
            g_resident_native_mx_wired = false;
            g_production_shape_qualified = false;
            return;
        }
        if (sh.n >= matmul::v4::lt::kLtProductionShapeMinDim) saw_production = true;
    }
    g_resident_native_mx_wired = true;
    g_production_shape_qualified = saw_production;
    if (!saw_production) {
        g_resident_deficit_detail =
            "resident wired on CI/medium shapes only; production_shape_qualified "
            "requires n>=" +
            std::to_string(matmul::v4::lt::kLtProductionShapeMinDim) +
            " (insufficient free VRAM or skipped)";
    } else {
        g_resident_deficit_detail.clear();
    }
}

void RunNativeSelfQualOnceLocked()
{
    if (g_native_qual_ran) return;
    g_native_qual_ran = true;

    const btx::cuda::CudaRuntimeProbe runtime = btx::cuda::ProbeCudaRuntime();
    if (!runtime.compiled || !runtime.available || runtime.device_index < 0) {
        g_resident_deficit_detail = "no CUDA device available for native/resident self-qual";
        return;
    }
    cudaDeviceProp props{};
    if (cudaGetDeviceProperties(&props, runtime.device_index) != cudaSuccess) {
        g_resident_deficit_detail = "cudaGetDeviceProperties failed";
        return;
    }
    g_qual_arch_key = FormatCudaArchKey(props.major, props.minor);

    const bool cutlass_compiled = lt_cutlass_mxfp4::IsLtCutlassMxfp4Compiled();
    g_native_mxfp4_attempted =
        (ToolkitDeclaresFp4() && ToolkitDeclaresMxScaleModes()) || cutlass_compiled;
    g_native_fp8_attempted = ToolkitDeclaresFp8() && ToolkitDeclaresVec32Ue8m0();

    // Blackwell is where stock MX heuristics live; non-Blackwell stays attempted
    // but not qualified unless a path actually matches the suite.
    // §1.SCOPE: sm_120 class (5090/5060 Ti) ≠ sm_100 (B200) — separate qual.
    if (!IsBlackwellSm(props.major, props.minor)) {
        g_resident_deficit_detail =
            "device is not Blackwell-class (sm_10x/sm_12x); resident native MX stays unwired "
            "(arch=" +
            g_qual_arch_key + ")";
        return;
    }
    if (cudaSetDevice(runtime.device_index) != cudaSuccess) {
        g_resident_deficit_detail = "cudaSetDevice failed";
        return;
    }
    if (!g_native_mxfp4_attempted && !g_native_fp8_attempted) {
        g_resident_deficit_detail = "toolkit lacks FP4/FP8 block-scale API surface";
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

    // FP8 may remain false-by-design when only MXFP4 byte-qualifies; peak_ready
    // uses (mxfp4 || fp8). Do not fabricate native_fp8_qualified.
    if (!mxfp4_ok && !fp8_ok) {
        g_resident_deficit_detail =
            "neither MXFP4 nor FP8 standalone projection matched the CPU oracle";
        return;
    }

    cudaStream_t stream = nullptr;
    if (cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking) != cudaSuccess) {
        g_resident_deficit_detail = "failed to create resident self-qual stream";
        return;
    }
    RunResidentNativeSelfQualLocked(stream);
    cudaStreamDestroy(stream);
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

bool IsLtResidentNativeMxWired()
{
    std::lock_guard<std::mutex> lock(g_native_mx_mu);
    RunNativeSelfQualOnceLocked();
    return g_resident_native_mx_wired;
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
        g_resident_native_mx_wired = false;
        return false;
    }
    if (numeric_fail) {
        g_native_mxfp4_qualified = false;
        g_resident_native_mx_wired = false;
        return false;
    }
    if (AttemptCutlassOcpMxfp4(mu, scales, V, n, m, got)) {
        if (matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) {
            out = std::move(got);
            if (provenance) provenance->native_mxfp4_qualified = true;
            return true;
        }
        g_native_mxfp4_qualified = false;
        g_resident_native_mx_wired = false;
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
        if (numeric_fail) {
            g_native_fp8_qualified = false;
            g_resident_native_mx_wired = false;
        }
        return false;
    }
    if (!matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) {
        g_native_fp8_qualified = false;
        g_resident_native_mx_wired = false;
        return false;
    }
    out = std::move(got);
    if (provenance) provenance->native_fp8_qualified = true;
    return true;
}

bool TryLaunchResidentNativeMxProjectedRightDevice(
    const int8_t* d_mu, const uint8_t* d_scales, const int8_t* d_V, int32_t* d_Q, uint32_t n,
    uint32_t m, void* cuda_stream, matmul::v4::lt::MxLaneProvenance* provenance)
{
    std::lock_guard<std::mutex> lock(g_native_mx_mu);
    RunNativeSelfQualOnceLocked();
    if (provenance) {
        *provenance = {};
        provenance->native_mxfp4_attempted = g_resident_native_mx_attempted;
        provenance->native_fp8_attempted = g_resident_native_mx_attempted;
    }
    // Amendment 1.A: device pointers only — never D2H pack / never host launcher.
    if (!g_resident_native_mx_wired || d_mu == nullptr || d_scales == nullptr || d_V == nullptr ||
        d_Q == nullptr || n == 0 || m == 0 ||
        (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) {
        return false;
    }
    auto* stream = static_cast<cudaStream_t>(cuda_stream);
    matmul::v4::lt::MxLaneProvenance local{};
    if (!LaunchResidentNativeMxDeviceCore(d_mu, d_scales, d_V, d_Q, n, m, stream, &local,
                                          /*sync_exactness_gate=*/false)) {
        // Hot-path miss after suite qual: revoke resident wiring (fail closed).
        g_resident_native_mx_wired = false;
        g_resident_deficit_detail =
            "resident device-pointer native launch declined after prior self-qual; "
            "INT8 exact remains (never labeled native-MX)";
        return false;
    }
    if (provenance) *provenance = local;
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
    {
        std::lock_guard<std::mutex> lock(g_native_mx_mu);
        s.resident_native_mx_wired = g_resident_native_mx_wired;
        s.production_shape_qualified = g_production_shape_qualified;
        s.arch_key = g_qual_arch_key;
    }
    s.allow_exact_mx_fallback = matmul::v4::lt::AllowLtExactMxFallback();
    // Amendment v2 §1.CORRECT: DERIVE peak_ready / blocks_device_resident only.
    matmul::v4::lt::DeriveLtPeakMxFlags(s);
    if (!s.peak_capable) {
        s.deficit_reason.clear();
    } else if (s.peak_ready) {
        s.deficit_reason.clear();
    } else if (s.allow_exact_mx_fallback) {
        s.deficit_reason =
            "peak-capable GPU does not have an end-to-end resident native MX path; "
            "the oracle-qualified exact INT8 MX resident path remains enabled. "
            "Do not label its rate native-MX or peak-ready.";
        if (!g_resident_deficit_detail.empty()) {
            s.deficit_reason += " detail: " + g_resident_deficit_detail;
        }
        if (!s.arch_key.empty()) {
            s.deficit_reason += " arch=" + s.arch_key;
        }
    } else {
        s.deficit_reason =
            "BTX_MATMUL_V4_LT_REQUIRE_NATIVE_MX=1 requested an end-to-end resident "
            "native MXFP4/MXFP8 path, but it is not wired and oracle-qualified; "
            "resident LT is intentionally blocked for this qualification run.";
        if (!g_resident_deficit_detail.empty()) {
            s.deficit_reason += " detail: " + g_resident_deficit_detail;
        }
        if (!s.arch_key.empty()) {
            s.deficit_reason += " arch=" + s.arch_key;
        }
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
