// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_lt_mx_native.h>

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>

#include <hip/hip_runtime.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// Optional hipBLASLt MX block-scale path (CDNA4 / gfx950).
// Researched scale enums (ROCm hipBLASLt 1.1+/1.4 develop):
//   HIPBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0
//   HIPBLASLT_MATMUL_MATRIX_SCALE_BLK32_UE8M0_32_8_EXT  (pre-swizzled 32×8)
// Element types: HIP_R_4F_E2M1 (MXFP4), HIP_R_8F_E4M3 (MXFP8), HIP_R_8F_UE8M0.
// Absence of headers/enums ⇒ permanent fail-closed for *qualified.

#if defined(BTX_HAVE_HIPBLASLT)
#if defined(__has_include) && __has_include(<hipblaslt/hipblaslt.h>)
#include <hipblaslt/hipblaslt.h>
#define BTX_HIP_MX_HAVE_HIPBLASLT 1
#endif
#endif

#if defined(BTX_HIP_MX_HAVE_HIPBLASLT)
#if defined(HIP_R_4F_E2M1)
#define BTX_HIP_MX_FP4_TYPE HIP_R_4F_E2M1
#elif defined(HIP_R_4F_E2M1_EXT)
#define BTX_HIP_MX_FP4_TYPE HIP_R_4F_E2M1_EXT
#endif
#if defined(HIP_R_8F_E4M3)
#define BTX_HIP_MX_FP8_TYPE HIP_R_8F_E4M3
#elif defined(HIP_R_8F_E4M3_FNUZ)
#define BTX_HIP_MX_FP8_TYPE HIP_R_8F_E4M3_FNUZ
#elif defined(HIP_R_8F_E4M3_EXT)
#define BTX_HIP_MX_FP8_TYPE HIP_R_8F_E4M3_EXT
#endif
#if defined(HIPBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0)
#define BTX_HIP_MX_SCALE_VEC32 HIPBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0
#endif
#if defined(HIPBLASLT_MATMUL_MATRIX_SCALE_BLK32_UE8M0_32_8_EXT)
#define BTX_HIP_MX_SCALE_BLK32_EXT HIPBLASLT_MATMUL_MATRIX_SCALE_BLK32_UE8M0_32_8_EXT
#endif
#if defined(BTX_HIP_MX_FP4_TYPE) && defined(BTX_HIP_MX_SCALE_VEC32)
#define BTX_HIP_MX_HAS_MXFP4_PATH 1
#endif
#if defined(BTX_HIP_MX_FP8_TYPE) && defined(BTX_HIP_MX_SCALE_VEC32)
#define BTX_HIP_MX_HAS_MXFP8_PATH 1
#endif
#endif

namespace matmul_v4::hip {
namespace {

std::mutex g_native_mx_mu;
bool g_native_mxfp4_attempted{false};
bool g_native_mxfp4_qualified{false};
bool g_native_fp8_attempted{false};
bool g_native_fp8_qualified{false};
bool g_native_qual_ran{false};

struct DeviceBuffer {
    void* ptr{nullptr};
    ~DeviceBuffer()
    {
        if (ptr) hipFree(ptr);
    }
    [[nodiscard]] bool Alloc(size_t bytes)
    {
        if (bytes == 0) {
            ptr = nullptr;
            return true;
        }
        return hipMalloc(&ptr, bytes) == hipSuccess;
    }
};

[[nodiscard]] bool ToolkitDeclaresMxfp4()
{
#if defined(BTX_HIP_MX_HAS_MXFP4_PATH)
    return true;
#else
    return false;
#endif
}

[[nodiscard]] bool ToolkitDeclaresMxfp8()
{
#if defined(BTX_HIP_MX_HAS_MXFP8_PATH)
    return true;
#else
    return false;
#endif
}

[[nodiscard]] bool IsCdna4Gfx950()
{
    int device = 0;
    hipDeviceProp_t props{};
    if (hipGetDevice(&device) != hipSuccess ||
        hipGetDeviceProperties(&props, device) != hipSuccess) {
        return false;
    }
    std::string arch{props.gcnArchName};
    if (const size_t suffix = arch.find(':'); suffix != std::string::npos) {
        arch.resize(suffix);
    }
    // CDNA4 MXFP4/MXFP8 MFMA scale is documented for gfx950 (MI350/MI355).
    return arch == "gfx950";
}

/** Inverse of SampleMantissaNibble: M11 int → OCP E2M1 nibble bit pattern. */
[[nodiscard]] uint8_t MantissaToE2M1Nibble(int8_t mu)
{
    switch (mu) {
    case 0: return 0x0;
    case 1: return 0x2;
    case 2: return 0x4;
    case 3: return 0x5;
    case 4: return 0x6;
    case 6: return 0x7;
    case -1: return 0xA;
    case -2: return 0xC;
    case -3: return 0xD;
    case -4: return 0xE;
    case -6: return 0xF;
    default: return 0xFF; // not M11
    }
}

/** E8M0 code for power-of-two 2^e (e ∈ {0..3}): bias-127. */
[[nodiscard]] uint8_t E8M0FromExponent(uint8_t e)
{
    return static_cast<uint8_t>(127U + static_cast<uint32_t>(e));
}

/** M11 → E4M3 bit pattern (IEEE-like bias-7). All eleven values are exact. */
[[nodiscard]] uint8_t MantissaToE4M3(int8_t mu)
{
    // sign | exp(4) | man(3). Values: 0,±1,±2,±3,±4,±6.
    const uint8_t sign = (mu < 0) ? 0x80U : 0U;
    const int mag = mu < 0 ? -static_cast<int>(mu) : static_cast<int>(mu);
    uint8_t bits = 0;
    switch (mag) {
    case 0: bits = 0x00; break;
    case 1: bits = 0x38; break; // 1.0 * 2^0
    case 2: bits = 0x40; break; // 1.0 * 2^1
    case 3: bits = 0x44; break; // 1.5 * 2^1
    case 4: bits = 0x48; break; // 1.0 * 2^2
    case 6: bits = 0x4C; break; // 1.5 * 2^2
    default: return 0xFF;
    }
    return static_cast<uint8_t>(sign | bits);
}

[[nodiscard]] bool PackMxfp4RowMajorMK(const std::vector<int8_t>& elems, uint32_t rows,
                                       uint32_t cols, std::vector<uint8_t>& packed)
{
    if ((cols % 2U) != 0) return false;
    packed.assign(static_cast<size_t>(rows) * (cols / 2U), 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; c += 2U) {
            const uint8_t lo = MantissaToE2M1Nibble(elems[static_cast<size_t>(r) * cols + c]);
            const uint8_t hi =
                MantissaToE2M1Nibble(elems[static_cast<size_t>(r) * cols + c + 1U]);
            if (lo == 0xFF || hi == 0xFF) return false;
            packed[static_cast<size_t>(r) * (cols / 2U) + (c / 2U)] =
                static_cast<uint8_t>(lo | (hi << 4));
        }
    }
    return true;
}

/** Pack V (K×N row-major) into N×K FP4 (K contiguous) for TRANSB=T. */
[[nodiscard]] bool PackMxfp4VAsNxK(const std::vector<int8_t>& V, uint32_t k, uint32_t n,
                                   std::vector<uint8_t>& packed)
{
    if ((k % 2U) != 0) return false;
    packed.assign(static_cast<size_t>(n) * (k / 2U), 0);
    for (uint32_t col = 0; col < n; ++col) {
        for (uint32_t row = 0; row < k; row += 2U) {
            const uint8_t lo = MantissaToE2M1Nibble(V[static_cast<size_t>(row) * n + col]);
            const uint8_t hi =
                MantissaToE2M1Nibble(V[static_cast<size_t>(row + 1U) * n + col]);
            if (lo == 0xFF || hi == 0xFF) return false;
            packed[static_cast<size_t>(col) * (k / 2U) + (row / 2U)] =
                static_cast<uint8_t>(lo | (hi << 4));
        }
    }
    return true;
}

[[nodiscard]] bool PackMxfp8RowMajorMK(const std::vector<int8_t>& elems, uint32_t rows,
                                       uint32_t cols, std::vector<uint8_t>& packed)
{
    packed.resize(static_cast<size_t>(rows) * cols);
    for (size_t i = 0; i < packed.size(); ++i) {
        const uint8_t b = MantissaToE4M3(elems[i]);
        if (b == 0xFF) return false;
        packed[i] = b;
    }
    return true;
}

[[nodiscard]] bool PackMxfp8VAsNxK(const std::vector<int8_t>& V, uint32_t k, uint32_t n,
                                   std::vector<uint8_t>& packed)
{
    packed.resize(static_cast<size_t>(n) * k);
    for (uint32_t col = 0; col < n; ++col) {
        for (uint32_t row = 0; row < k; ++row) {
            const uint8_t b = MantissaToE4M3(V[static_cast<size_t>(row) * n + col]);
            if (b == 0xFF) return false;
            packed[static_cast<size_t>(col) * k + row] = b;
        }
    }
    return true;
}

[[nodiscard]] bool EncodeUe8M0ScalesA(const std::vector<uint8_t>& scales, uint32_t m,
                                      uint32_t k, std::vector<uint8_t>& out)
{
    if ((k % matmul::v4::lt::kMatExpandMxBlockLen) != 0) return false;
    const uint32_t nblk = k / matmul::v4::lt::kMatExpandMxBlockLen;
    if (scales.size() != static_cast<size_t>(m) * nblk) return false;
    out.resize(scales.size());
    for (size_t i = 0; i < scales.size(); ++i) {
        if (scales[i] > 3U) return false;
        out[i] = E8M0FromExponent(scales[i]);
    }
    return true;
}

[[nodiscard]] bool EncodeUe8M0UnitScalesB(uint32_t n, uint32_t k, std::vector<uint8_t>& out)
{
    if ((k % matmul::v4::lt::kMatExpandMxBlockLen) != 0) return false;
    const uint32_t nblk = k / matmul::v4::lt::kMatExpandMxBlockLen;
    out.assign(static_cast<size_t>(n) * nblk, E8M0FromExponent(0));
    return true;
}

[[nodiscard]] bool ExactFp32ToInt32(const std::vector<float>& fp, std::vector<int32_t>& out)
{
    out.resize(fp.size());
    for (size_t i = 0; i < fp.size(); ++i) {
        const float v = fp[i];
        if (!std::isfinite(v)) return false;
        const float rounded = std::nearbyintf(v);
        if (rounded != v) return false;
        if (rounded > static_cast<float>(std::numeric_limits<int32_t>::max()) ||
            rounded < static_cast<float>(std::numeric_limits<int32_t>::min())) {
            return false;
        }
        out[i] = static_cast<int32_t>(rounded);
    }
    return true;
}

#if defined(BTX_HIP_MX_HAVE_HIPBLASLT)

struct LtGuards {
    hipblasLtHandle_t handle{nullptr};
    hipblasLtMatmulDesc_t op_desc{nullptr};
    hipblasLtMatrixLayout_t a_layout{nullptr};
    hipblasLtMatrixLayout_t b_layout{nullptr};
    hipblasLtMatrixLayout_t c_layout{nullptr};
    hipblasLtMatrixLayout_t d_layout{nullptr};
    hipblasLtMatmulPreference_t preference{nullptr};
    ~LtGuards()
    {
        if (preference) hipblasLtMatmulPreferenceDestroy(preference);
        if (d_layout) hipblasLtMatrixLayoutDestroy(d_layout);
        if (c_layout) hipblasLtMatrixLayoutDestroy(c_layout);
        if (b_layout) hipblasLtMatrixLayoutDestroy(b_layout);
        if (a_layout) hipblasLtMatrixLayoutDestroy(a_layout);
        if (op_desc) hipblasLtMatmulDescDestroy(op_desc);
        if (handle) hipblasLtDestroy(handle);
    }
};

[[nodiscard]] bool RunHipBlasLtBlockScaled(hipDataType a_type, hipDataType b_type,
                                           const void* dA, const void* dB, float* dC,
                                           const void* dScaleA, const void* dScaleB,
                                           uint32_t M, uint32_t N, uint32_t K,
                                           int64_t lda_elems, int64_t ldb_elems,
                                           int64_t ldc)
{
#if !defined(BTX_HIP_MX_SCALE_VEC32)
    (void)a_type; (void)b_type; (void)dA; (void)dB; (void)dC;
    (void)dScaleA; (void)dScaleB; (void)M; (void)N; (void)K;
    (void)lda_elems; (void)ldb_elems; (void)ldc;
    return false;
#else
    LtGuards g;
    if (hipblasLtCreate(&g.handle) != HIPBLAS_STATUS_SUCCESS) return false;
    if (hipblasLtMatmulDescCreate(&g.op_desc, HIPBLAS_COMPUTE_32F, HIP_R_32F) !=
        HIPBLAS_STATUS_SUCCESS) {
        return false;
    }

    const hipblasOperation_t op_a = HIPBLAS_OP_N;
    const hipblasOperation_t op_b = HIPBLAS_OP_T; // B stored as N×K
    if (hipblasLtMatmulDescSetAttribute(g.op_desc, HIPBLASLT_MATMUL_DESC_TRANSA, &op_a,
                                        sizeof(op_a)) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulDescSetAttribute(g.op_desc, HIPBLASLT_MATMUL_DESC_TRANSB, &op_b,
                                        sizeof(op_b)) != HIPBLAS_STATUS_SUCCESS) {
        return false;
    }

    const hipblasLtMatmulMatrixScale_t scale_mode = BTX_HIP_MX_SCALE_VEC32;
    if (hipblasLtMatmulDescSetAttribute(g.op_desc, HIPBLASLT_MATMUL_DESC_A_SCALE_MODE,
                                        &scale_mode, sizeof(scale_mode)) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulDescSetAttribute(g.op_desc, HIPBLASLT_MATMUL_DESC_B_SCALE_MODE,
                                        &scale_mode, sizeof(scale_mode)) !=
            HIPBLAS_STATUS_SUCCESS) {
        return false;
    }
    if (hipblasLtMatmulDescSetAttribute(g.op_desc, HIPBLASLT_MATMUL_DESC_A_SCALE_POINTER,
                                        &dScaleA, sizeof(dScaleA)) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulDescSetAttribute(g.op_desc, HIPBLASLT_MATMUL_DESC_B_SCALE_POINTER,
                                        &dScaleB, sizeof(dScaleB)) != HIPBLAS_STATUS_SUCCESS) {
        return false;
    }

    // A: M×K (op N). B: N×K in memory (op T ⇒ logical K×N). C/D: M×N.
    if (hipblasLtMatrixLayoutCreate(&g.a_layout, a_type, M, K, lda_elems) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutCreate(&g.b_layout, b_type, N, K, ldb_elems) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutCreate(&g.c_layout, HIP_R_32F, M, N, ldc) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutCreate(&g.d_layout, HIP_R_32F, M, N, ldc) !=
            HIPBLAS_STATUS_SUCCESS) {
        return false;
    }
    const hipblasLtOrder_t order = HIPBLASLT_ORDER_ROW;
    if (hipblasLtMatrixLayoutSetAttribute(g.a_layout, HIPBLASLT_MATRIX_LAYOUT_ORDER, &order,
                                          sizeof(order)) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutSetAttribute(g.b_layout, HIPBLASLT_MATRIX_LAYOUT_ORDER, &order,
                                          sizeof(order)) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutSetAttribute(g.c_layout, HIPBLASLT_MATRIX_LAYOUT_ORDER, &order,
                                          sizeof(order)) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutSetAttribute(g.d_layout, HIPBLASLT_MATRIX_LAYOUT_ORDER, &order,
                                          sizeof(order)) != HIPBLAS_STATUS_SUCCESS) {
        return false;
    }

    constexpr size_t kWorkspace = 64ULL << 20;
    DeviceBuffer workspace;
    if (!workspace.Alloc(kWorkspace)) return false;
    if (hipblasLtMatmulPreferenceCreate(&g.preference) != HIPBLAS_STATUS_SUCCESS) return false;
    if (hipblasLtMatmulPreferenceSetAttribute(
            g.preference, HIPBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES, &kWorkspace,
            sizeof(kWorkspace)) != HIPBLAS_STATUS_SUCCESS) {
        return false;
    }

    hipblasLtMatmulHeuristicResult_t heuristic{};
    int returned = 0;
    if (hipblasLtMatmulAlgoGetHeuristic(g.handle, g.op_desc, g.a_layout, g.b_layout,
                                        g.c_layout, g.d_layout, g.preference, 1, &heuristic,
                                        &returned) != HIPBLAS_STATUS_SUCCESS ||
        returned < 1) {
        return false;
    }

    const float alpha = 1.0f;
    const float beta = 0.0f;
    if (hipblasLtMatmul(g.handle, g.op_desc, &alpha, dA, g.a_layout, dB, g.b_layout, &beta, dC,
                        g.c_layout, dC, g.d_layout, &heuristic.algo, workspace.ptr, kWorkspace,
                        /*stream=*/nullptr) != HIPBLAS_STATUS_SUCCESS) {
        return false;
    }
    return hipDeviceSynchronize() == hipSuccess;
#endif
}

#endif // BTX_HIP_MX_HAVE_HIPBLASLT

[[nodiscard]] bool AttemptHipBlasLtBlockScaledMxfp4(const std::vector<int8_t>& mu,
                                                    const std::vector<uint8_t>& scales,
                                                    const std::vector<int8_t>& V, uint32_t n,
                                                    uint32_t m, std::vector<int32_t>& out)
{
    out.clear();
#if !defined(BTX_HIP_MX_HAS_MXFP4_PATH)
    (void)mu; (void)scales; (void)V; (void)n; (void)m;
    return false;
#else
    if (!matmul::v4::lt::LtMxProjectionFitsFloat32ExactInteger(n, m)) return false;
    if (n == 0 || m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) return false;
    if (mu.size() != static_cast<size_t>(n) * n ||
        scales.size() != static_cast<size_t>(n) * (n / matmul::v4::lt::kMatExpandMxBlockLen) ||
        V.size() != static_cast<size_t>(n) * m) {
        return false;
    }

    std::vector<uint8_t> packed_a;
    std::vector<uint8_t> packed_b;
    std::vector<uint8_t> scale_a;
    std::vector<uint8_t> scale_b;
    if (!PackMxfp4RowMajorMK(mu, n, n, packed_a) || !PackMxfp4VAsNxK(V, n, m, packed_b) ||
        !EncodeUe8M0ScalesA(scales, n, n, scale_a) || !EncodeUe8M0UnitScalesB(m, n, scale_b)) {
        return false;
    }

    DeviceBuffer dA, dB, dC, dSA, dSB;
    const size_t a_bytes = packed_a.size();
    const size_t b_bytes = packed_b.size();
    const size_t c_bytes = static_cast<size_t>(n) * m * sizeof(float);
    if (!dA.Alloc(a_bytes) || !dB.Alloc(b_bytes) || !dC.Alloc(c_bytes) ||
        !dSA.Alloc(scale_a.size()) || !dSB.Alloc(scale_b.size())) {
        return false;
    }
    if (hipMemcpy(dA.ptr, packed_a.data(), a_bytes, hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dB.ptr, packed_b.data(), b_bytes, hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dSA.ptr, scale_a.data(), scale_a.size(), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dSB.ptr, scale_b.data(), scale_b.size(), hipMemcpyHostToDevice) != hipSuccess) {
        return false;
    }

    // ld in elements (library packs FP4 internally from element dims).
    if (!RunHipBlasLtBlockScaled(BTX_HIP_MX_FP4_TYPE, BTX_HIP_MX_FP4_TYPE, dA.ptr, dB.ptr,
                                 static_cast<float*>(dC.ptr), dSA.ptr, dSB.ptr, n, m, n,
                                 /*lda=*/n, /*ldb=*/n, /*ldc=*/m)) {
        return false;
    }

    std::vector<float> fp(static_cast<size_t>(n) * m);
    if (hipMemcpy(fp.data(), dC.ptr, c_bytes, hipMemcpyDeviceToHost) != hipSuccess) return false;
    return ExactFp32ToInt32(fp, out);
#endif
}

[[nodiscard]] bool AttemptHipBlasLtBlockScaledFp8(const std::vector<int8_t>& mu,
                                                  const std::vector<uint8_t>& scales,
                                                  const std::vector<int8_t>& V, uint32_t n,
                                                  uint32_t m, std::vector<int32_t>& out)
{
    out.clear();
#if !defined(BTX_HIP_MX_HAS_MXFP8_PATH)
    (void)mu; (void)scales; (void)V; (void)n; (void)m;
    return false;
#else
    if (!matmul::v4::lt::LtMxProjectionFitsFloat32ExactInteger(n, m)) return false;
    if (n == 0 || m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) return false;
    if (mu.size() != static_cast<size_t>(n) * n ||
        scales.size() != static_cast<size_t>(n) * (n / matmul::v4::lt::kMatExpandMxBlockLen) ||
        V.size() != static_cast<size_t>(n) * m) {
        return false;
    }

    std::vector<uint8_t> packed_a;
    std::vector<uint8_t> packed_b;
    std::vector<uint8_t> scale_a;
    std::vector<uint8_t> scale_b;
    if (!PackMxfp8RowMajorMK(mu, n, n, packed_a) || !PackMxfp8VAsNxK(V, n, m, packed_b) ||
        !EncodeUe8M0ScalesA(scales, n, n, scale_a) || !EncodeUe8M0UnitScalesB(m, n, scale_b)) {
        return false;
    }

    DeviceBuffer dA, dB, dC, dSA, dSB;
    const size_t a_bytes = packed_a.size();
    const size_t b_bytes = packed_b.size();
    const size_t c_bytes = static_cast<size_t>(n) * m * sizeof(float);
    if (!dA.Alloc(a_bytes) || !dB.Alloc(b_bytes) || !dC.Alloc(c_bytes) ||
        !dSA.Alloc(scale_a.size()) || !dSB.Alloc(scale_b.size())) {
        return false;
    }
    if (hipMemcpy(dA.ptr, packed_a.data(), a_bytes, hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dB.ptr, packed_b.data(), b_bytes, hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dSA.ptr, scale_a.data(), scale_a.size(), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dSB.ptr, scale_b.data(), scale_b.size(), hipMemcpyHostToDevice) != hipSuccess) {
        return false;
    }

    if (!RunHipBlasLtBlockScaled(BTX_HIP_MX_FP8_TYPE, BTX_HIP_MX_FP8_TYPE, dA.ptr, dB.ptr,
                                 static_cast<float*>(dC.ptr), dSA.ptr, dSB.ptr, n, m, n,
                                 /*lda=*/n, /*ldb=*/n, /*ldc=*/m)) {
        return false;
    }

    std::vector<float> fp(static_cast<size_t>(n) * m);
    if (hipMemcpy(fp.data(), dC.ptr, c_bytes, hipMemcpyDeviceToHost) != hipSuccess) return false;
    return ExactFp32ToInt32(fp, out);
#endif
}

/** rocBLAS has no public OCP MX block-scale GEMM; keep an explicit decline. */
[[nodiscard]] bool AttemptRocBlasBlockScaledMx(const std::vector<int8_t>& /*mu*/,
                                               const std::vector<uint8_t>& /*scales*/,
                                               const std::vector<int8_t>& /*V*/, uint32_t /*n*/,
                                               uint32_t /*m*/, std::vector<int32_t>& /*out*/)
{
    return false;
}

void RunNativeSelfQualOnceLocked()
{
    if (g_native_qual_ran) return;
    g_native_qual_ran = true;

    int count = 0;
    if (hipGetDeviceCount(&count) != hipSuccess || count <= 0) return;
    if (!IsCdna4Gfx950()) return;
    if (!ToolkitDeclaresMxfp4() && !ToolkitDeclaresMxfp8()) return;

    g_native_mxfp4_attempted = ToolkitDeclaresMxfp4();
    g_native_fp8_attempted = ToolkitDeclaresMxfp8();

    const std::array<std::pair<uint32_t, uint32_t>, 4> shapes = {{
        {32, 16},
        {64, 32},
        {64, 17},
        {96, 48},
    }};
    bool mxfp4_ok = g_native_mxfp4_attempted;
    bool fp8_ok = g_native_fp8_attempted;
    for (const auto& [n, m] : shapes) {
        if (n % matmul::v4::lt::kMatExpandMxBlockLen != 0) {
            mxfp4_ok = false;
            fp8_ok = false;
            break;
        }
        if (!matmul::v4::lt::LtMxProjectionFitsFloat32ExactInteger(n, m)) {
            mxfp4_ok = false;
            fp8_ok = false;
            break;
        }
        // Corner-ish mantissas + all four exponents exercised.
        std::vector<int8_t> mu(static_cast<size_t>(n) * n);
        std::vector<uint8_t> scales(static_cast<size_t>(n) * (n / 32));
        std::vector<int8_t> V(static_cast<size_t>(n) * m);
        static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
        for (size_t i = 0; i < mu.size(); ++i) mu[i] = kM11[i % 11];
        for (size_t i = 0; i < scales.size(); ++i) {
            scales[i] = static_cast<uint8_t>(i & 3U);
        }
        for (size_t i = 0; i < V.size(); ++i) V[i] = kM11[(i * 3) % 11];

        std::vector<int32_t> got;
        if (mxfp4_ok) {
            if ((!AttemptHipBlasLtBlockScaledMxfp4(mu, scales, V, n, m, got) &&
                 !AttemptRocBlasBlockScaledMx(mu, scales, V, n, m, got)) ||
                !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) {
                mxfp4_ok = false;
            }
        }
        if (fp8_ok) {
            if ((!AttemptHipBlasLtBlockScaledFp8(mu, scales, V, n, m, got) &&
                 !AttemptRocBlasBlockScaledMx(mu, scales, V, n, m, got)) ||
                !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) {
                fp8_ok = false;
            }
        }
    }
    g_native_mxfp4_qualified = mxfp4_ok;
    g_native_fp8_qualified = fp8_ok;
}

} // namespace

matmul::v4::lt::MxLaneProvenance ProbeLtHipMxNativeProvenance()
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
    if (!g_native_mxfp4_qualified) return false;
    if (!matmul::v4::lt::LtMxProjectionFitsFloat32ExactInteger(n, m)) return false;
    if ((!AttemptHipBlasLtBlockScaledMxfp4(mu, scales, V, n, m, out) &&
         !AttemptRocBlasBlockScaledMx(mu, scales, V, n, m, out)) ||
        !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        out.clear();
        // Runtime mismatch after self-qual: revoke and stay fail-closed.
        g_native_mxfp4_qualified = false;
        return false;
    }
    if (provenance) provenance->native_mxfp4_qualified = true;
    return true;
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
    if (!g_native_fp8_qualified) return false;
    if (!matmul::v4::lt::LtMxProjectionFitsFloat32ExactInteger(n, m)) return false;
    if ((!AttemptHipBlasLtBlockScaledFp8(mu, scales, V, n, m, out) &&
         !AttemptRocBlasBlockScaledMx(mu, scales, V, n, m, out)) ||
        !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        out.clear();
        g_native_fp8_qualified = false;
        return false;
    }
    if (provenance) provenance->native_fp8_qualified = true;
    return true;
}

bool IsLtPeakMxCapableDevice()
{
    return IsCdna4Gfx950();
}

matmul::v4::lt::LtPeakMxPathStatus ProbeLtPeakMxPathStatus()
{
    const auto prov = ProbeLtHipMxNativeProvenance();
    matmul::v4::lt::LtPeakMxPathStatus s;
    s.peak_capable = IsLtPeakMxCapableDevice();
    s.native_mxfp4_attempted = prov.native_mxfp4_attempted;
    s.native_mxfp4_qualified = prov.native_mxfp4_qualified;
    s.native_fp8_attempted = prov.native_fp8_attempted;
    s.native_fp8_qualified = prov.native_fp8_qualified;
    // Native launchers currently serve the host-vector projection surface;
    // the persistent HIP Q* graph still runs exact INT8 scale partitions.
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
            "peak-capable GPU (gfx950) does not have an end-to-end resident native "
            "MX path; the oracle-qualified exact INT8 MX resident path remains "
            "enabled. Do not label its rate native-MX or peak-ready.";
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
                "MatMul-v4.4-LT HIP MX: device is not CDNA4 gfx950; exact INT8 MX "
                "scale-partitioned resident path remains enabled.\n");
            return;
        }
        if (s.peak_ready) {
            matmul::v4::lt::LogLtMxDiagnostic(
                "MatMul-v4.4-LT HIP MX PEAK READY: resident native MX is wired and "
                "oracle-qualified.\n");
            return;
        }
        matmul::v4::lt::LogLtMxDiagnostic(
            "MatMul-v4.4-LT HIP MX PEAK DEFICIT: " + s.deficit_reason + "\n");
        matmul::v4::lt::LogLtMxDiagnostic(
            "MatMul-v4.4-LT HIP MX ACTION REQUIRED: wire and self-qualify the native "
            "path before using native-MX/peak-ready labels; exact INT8 results remain "
            "bit-exact fallback evidence only.\n");
    });
}

bool LtPeakMxBlocksDeviceResident()
{
    DiagnoseLtPeakMxPathOnce();
    return ProbeLtPeakMxPathStatus().blocks_device_resident;
}

} // namespace matmul_v4::hip
