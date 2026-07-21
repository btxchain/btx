// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_rc_mx_ozaki_native.h>

#include <hip/matmul_v4_lt_accel.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>

#include <hip/hip_runtime.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

// HIP_R_4F_E2M1 / scale enums are NOT preprocessor macros.
// Gate on CMake BTX_HIP_MXFP4_TYPES only — never defined(HIP_R_4F_E2M1).

#if defined(BTX_HAVE_HIPBLASLT)
#if defined(__has_include) && __has_include(<hipblaslt/hipblaslt.h>)
#include <hipblaslt/hipblaslt.h>
#define BTX_RC_HIP_HAVE_HIPBLASLT 1
#endif
#endif

#if defined(BTX_RC_HIP_HAVE_HIPBLASLT) && defined(BTX_HIP_MXFP4_TYPES)
#define BTX_RC_HIP_MX_FP4_TYPE HIP_R_4F_E2M1
#define BTX_RC_HIP_MX_SCALE_VEC32 HIPBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0
#define BTX_RC_HIP_HAS_MXFP4_PATH 1
#endif

namespace matmul_v4::hip {
namespace {

std::mutex g_mu;
bool g_exact_ran{false};
bool g_exact_qualified{false};
bool g_mx_ran{false};
bool g_mx_attempted{false};
bool g_mx_qualified{false};
std::string g_mx_arch;
std::string g_mx_backend;
std::string g_mx_deficit;

constexpr uint8_t kUe8m0Bias = 127;

[[nodiscard]] std::string HipArchKey()
{
    int device = 0;
    hipDeviceProp_t props{};
    if (hipGetDevice(&device) != hipSuccess ||
        hipGetDeviceProperties(&props, device) != hipSuccess) {
        return {};
    }
    std::string arch{props.gcnArchName};
    if (const size_t suffix = arch.find(':'); suffix != std::string::npos) {
        arch.resize(suffix);
    }
    return arch;
}

[[nodiscard]] bool IsGfx950() { return HipArchKey() == "gfx950"; }
[[nodiscard]] bool IsGfx942() { return HipArchKey() == "gfx942"; }

[[nodiscard]] bool IsM11(int32_t mu)
{
    switch (mu) {
    case 0: case 1: case -1: case 2: case -2: case 3: case -3:
    case 4: case -4: case 6: case -6: return true;
    default: return false;
    }
}

[[nodiscard]] uint8_t EncodeE2M1Nibble(int8_t mu)
{
    switch (mu) {
    case 0: return 0x0; case 1: return 0x2; case 2: return 0x4; case 3: return 0x5;
    case 4: return 0x6; case 6: return 0x7; case -1: return 0xA; case -2: return 0xC;
    case -3: return 0xD; case -4: return 0xE; case -6: return 0xF; default: return 0xFF;
    }
}

[[nodiscard]] bool FactorBlockToMx(const int8_t* vals, uint32_t n, uint8_t& e_out, int8_t* mu_out)
{
    for (int e = 3; e >= 0; --e) {
        const int32_t scale = 1 << e;
        bool ok = true;
        for (uint32_t i = 0; i < n; ++i) {
            const int32_t v = static_cast<int32_t>(vals[i]);
            if ((v % scale) != 0) { ok = false; break; }
            if (!IsM11(v / scale)) { ok = false; break; }
        }
        if (!ok) continue;
        e_out = static_cast<uint8_t>(e);
        for (uint32_t i = 0; i < n; ++i) {
            mu_out[i] = static_cast<int8_t>(static_cast<int32_t>(vals[i]) / scale);
        }
        for (uint32_t i = n; i < kRcOzakiHipMxBlk; ++i) mu_out[i] = 0;
        return true;
    }
    return false;
}

void PackNibble(uint8_t* packed, size_t elem_index, uint8_t nib)
{
    const size_t byte = elem_index / 2;
    if ((elem_index & 1u) == 0) {
        packed[byte] = static_cast<uint8_t>((packed[byte] & 0xF0u) | (nib & 0x0Fu));
    } else {
        packed[byte] = static_cast<uint8_t>((packed[byte] & 0x0Fu) | ((nib & 0x0Fu) << 4));
    }
}

[[nodiscard]] uint8_t UnpackNibble(const uint8_t* packed, size_t elem_index)
{
    const uint8_t b = packed[elem_index / 2];
    return ((elem_index & 1u) == 0) ? static_cast<uint8_t>(b & 0x0Fu)
                                   : static_cast<uint8_t>((b >> 4) & 0x0Fu);
}

struct DeviceBuffer {
    void* ptr{nullptr};
    ~DeviceBuffer() { if (ptr) hipFree(ptr); }
    [[nodiscard]] bool Alloc(size_t bytes)
    {
        if (bytes == 0) { ptr = nullptr; return true; }
        return hipMalloc(&ptr, bytes) == hipSuccess;
    }
};

/** Attempt hipBLASLt block-scaled MXFP4 with opA=T opB=N VEC32.
 *  Returns false unless BTX_HIP_MXFP4_TYPES + gfx950 + K%32==0.
 *  Caller must still byte-compare against the int64 oracle before qualifying. */
[[nodiscard]] bool AttemptHipBlasLtRcOzakiMxfp4(const RcOzakiHipMxPack& pack, uint32_t rows,
                                               uint32_t K, uint32_t cols,
                                               std::vector<int64_t>& out, std::string* error)
{
#if !defined(BTX_RC_HIP_HAS_MXFP4_PATH)
    (void)pack; (void)rows; (void)K; (void)cols; (void)out;
    if (error) *error = "BTX_HIP_MXFP4_TYPES not set (toolkit lacks HIP_R_4F_E2M1+VEC32)";
    return false;
#else
    // VEC32 UE8M0 scales along K blocks of 32 — never launch partial-K as native.
    if ((K % kRcOzakiHipMxBlk) != 0) {
        if (error) *error = "hipBLASLt VEC32 requires K multiple of 32";
        return false;
    }
    // gfx950 covers MI350X / MI355X CDNA4. Arch gate selects the attempt surface
    // only — qualification still requires oracle byte-match (never arch alone).
    if (!IsGfx950()) {
        if (error) *error = "requires gfx950 silicon";
        return false;
    }
    // hipBLASLt: A is K×M (op T → logical M×K), B is K×N (op N).
    DeviceBuffer dA, dB, dC, dSfa, dSfb, dWorkspace;
    const size_t a_bytes = pack.a_e2m1.size();
    const size_t b_bytes = pack.b_e2m1.size();
    const size_t c_bytes = static_cast<size_t>(rows) * cols * sizeof(float);
    if (!dA.Alloc(a_bytes) || !dB.Alloc(b_bytes) || !dC.Alloc(c_bytes) ||
        !dSfa.Alloc(pack.sfa_ue8m0.size()) || !dSfb.Alloc(pack.sfb_ue8m0.size())) {
        if (error) *error = "hipMalloc failed for RC Ozaki MXFP4";
        return false;
    }
    if (hipMemcpy(dA.ptr, pack.a_e2m1.data(), a_bytes, hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dB.ptr, pack.b_e2m1.data(), b_bytes, hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dSfa.ptr, pack.sfa_ue8m0.data(), pack.sfa_ue8m0.size(),
                  hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dSfb.ptr, pack.sfb_ue8m0.data(), pack.sfb_ue8m0.size(),
                  hipMemcpyHostToDevice) != hipSuccess) {
        if (error) *error = "H2D failed for RC Ozaki MXFP4";
        return false;
    }

    hipblasLtHandle_t handle{nullptr};
    hipblasLtMatmulDesc_t op_desc{nullptr};
    hipblasLtMatrixLayout_t a_layout{nullptr}, b_layout{nullptr}, c_layout{nullptr},
        d_layout{nullptr};
    hipblasLtMatmulPreference_t preference{nullptr};
    auto cleanup = [&]() {
        if (preference) hipblasLtMatmulPreferenceDestroy(preference);
        if (d_layout) hipblasLtMatrixLayoutDestroy(d_layout);
        if (c_layout) hipblasLtMatrixLayoutDestroy(c_layout);
        if (b_layout) hipblasLtMatrixLayoutDestroy(b_layout);
        if (a_layout) hipblasLtMatrixLayoutDestroy(a_layout);
        if (op_desc) hipblasLtMatmulDescDestroy(op_desc);
        if (handle) hipblasLtDestroy(handle);
    };

    if (hipblasLtCreate(&handle) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulDescCreate(&op_desc, HIPBLAS_COMPUTE_32F, HIP_R_32F) !=
            HIPBLAS_STATUS_SUCCESS) {
        cleanup();
        if (error) *error = "hipblasLt create failed";
        return false;
    }
    const hipblasOperation_t op_a = HIPBLAS_OP_T; // A stored K×M
    const hipblasOperation_t op_b = HIPBLAS_OP_N; // B stored K×N
    if (hipblasLtMatmulDescSetAttribute(op_desc, HIPBLASLT_MATMUL_DESC_TRANSA, &op_a,
                                        sizeof(op_a)) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulDescSetAttribute(op_desc, HIPBLASLT_MATMUL_DESC_TRANSB, &op_b,
                                        sizeof(op_b)) != HIPBLAS_STATUS_SUCCESS) {
        cleanup();
        if (error) *error = "hipblasLt set TRANSA/TRANSB failed";
        return false;
    }
    const hipblasLtMatmulMatrixScale_t scale_mode = BTX_RC_HIP_MX_SCALE_VEC32;
    if (hipblasLtMatmulDescSetAttribute(op_desc, HIPBLASLT_MATMUL_DESC_A_SCALE_MODE,
                                        &scale_mode, sizeof(scale_mode)) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulDescSetAttribute(op_desc, HIPBLASLT_MATMUL_DESC_B_SCALE_MODE,
                                        &scale_mode, sizeof(scale_mode)) !=
            HIPBLAS_STATUS_SUCCESS) {
        cleanup();
        if (error) *error = "hipblasLt set VEC32 scale mode failed";
        return false;
    }
    const void* sfa = dSfa.ptr;
    const void* sfb = dSfb.ptr;
    if (hipblasLtMatmulDescSetAttribute(op_desc, HIPBLASLT_MATMUL_DESC_A_SCALE_POINTER, &sfa,
                                        sizeof(sfa)) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulDescSetAttribute(op_desc, HIPBLASLT_MATMUL_DESC_B_SCALE_POINTER, &sfb,
                                        sizeof(sfb)) != HIPBLAS_STATUS_SUCCESS) {
        cleanup();
        if (error) *error = "hipblasLt set scale pointers failed";
        return false;
    }
    // A layout: rows=K cols=M (physical), op T → logical M×K
    // B layout: rows=K cols=N, op N → logical K×N
    const int64_t lda = static_cast<int64_t>(rows); // leading dim of K×M
    const int64_t ldb = static_cast<int64_t>(cols);
    const int64_t ldc = static_cast<int64_t>(cols);
    if (hipblasLtMatrixLayoutCreate(&a_layout, BTX_RC_HIP_MX_FP4_TYPE, K, rows, lda) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutCreate(&b_layout, BTX_RC_HIP_MX_FP4_TYPE, K, cols, ldb) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutCreate(&c_layout, HIP_R_32F, rows, cols, ldc) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutCreate(&d_layout, HIP_R_32F, rows, cols, ldc) !=
            HIPBLAS_STATUS_SUCCESS) {
        cleanup();
        if (error) *error = "hipblasLt matrix layout create failed";
        return false;
    }
    constexpr size_t kWorkspace = 64ULL << 20;
    if (!dWorkspace.Alloc(kWorkspace) ||
        hipblasLtMatmulPreferenceCreate(&preference) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulPreferenceSetAttribute(preference, HIPBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,
                                              &kWorkspace, sizeof(kWorkspace)) !=
            HIPBLAS_STATUS_SUCCESS) {
        cleanup();
        if (error) *error = "hipblasLt preference failed";
        return false;
    }
    hipblasLtMatmulHeuristicResult_t heuristic{};
    int returned = 0;
    if (hipblasLtMatmulAlgoGetHeuristic(handle, op_desc, a_layout, b_layout, c_layout, d_layout,
                                        preference, 1, &heuristic, &returned) !=
            HIPBLAS_STATUS_SUCCESS ||
        returned < 1) {
        cleanup();
        if (error) *error = "hipblasLt no MXFP4 heuristic (gfx950 + toolkit required)";
        return false;
    }
    const float alpha = 1.0f;
    const float beta = 0.0f;
    if (hipblasLtMatmul(handle, op_desc, &alpha, dA.ptr, a_layout, dB.ptr, b_layout, &beta,
                        dC.ptr, c_layout, dC.ptr, d_layout, &heuristic.algo, dWorkspace.ptr,
                        kWorkspace, nullptr) != HIPBLAS_STATUS_SUCCESS ||
        hipDeviceSynchronize() != hipSuccess) {
        cleanup();
        if (error) *error = "hipblasLt MXFP4 matmul failed";
        return false;
    }
    std::vector<float> fp(static_cast<size_t>(rows) * cols);
    if (hipMemcpy(fp.data(), dC.ptr, c_bytes, hipMemcpyDeviceToHost) != hipSuccess) {
        cleanup();
        if (error) *error = "D2H failed";
        return false;
    }
    cleanup();
    out.resize(fp.size());
    for (size_t i = 0; i < fp.size(); ++i) {
        const float v = fp[i];
        if (!std::isfinite(v) || v != std::nearbyintf(v)) {
            if (error) *error = "MXFP4 FP32 output not exact integer";
            out.clear();
            return false;
        }
        out[i] = static_cast<int64_t>(v);
    }
    if (error) error->clear();
    return true;
#endif
}

[[nodiscard]] bool LaunchHipExactPanels(const std::vector<int8_t>& left,
                                        const std::vector<int8_t>& right, uint32_t rows,
                                        uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                        std::string* error)
{
    out.clear();
    if (!IsMatMulLTHipAvailable()) {
        if (error) *error = "requires gfx950 silicon"; // or any HIP ExactGemm device
        return false;
    }
    constexpr uint32_t kChunk = matmul::v4::rc::kRCOzakiExactChunk;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t k0 = 0; k0 < inner; k0 += kChunk) {
        const uint32_t len = std::min(kChunk, inner - k0);
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
            if (error) *error = "HIP LaunchGemmS8S8 declined for RC Ozaki panels";
            out.clear();
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    if (error) error->clear();
    return true;
}

} // namespace

bool IsRcOzakiHipCompiled() { return true; }

std::string RcOzakiHipDeficit()
{
    if (IsRcOzakiHipMxfp4Qualified()) return {};
    const std::string arch = HipArchKey();
    if (arch == "gfx942") return "requires gfx942 silicon"; // FP8 lane pending separate qual
    return "requires gfx950 silicon";
}

int8_t DecodeRcOzakiHipE2M1Nibble(uint8_t nib)
{
    switch (nib & 0x0Fu) {
    case 0x0: return 0; case 0x2: return 1; case 0xA: return -1; case 0x4: return 2;
    case 0xC: return -2; case 0x5: return 3; case 0xD: return -3; case 0x6: return 4;
    case 0xE: return -4; case 0x7: return 6; case 0xF: return -6; default: return 0;
    }
}

bool PackRcOzakiHipMxfp4OpATOpBN(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                uint32_t rows, uint32_t K, uint32_t cols, RcOzakiHipMxPack& out,
                                std::string* error)
{
    out = {};
    if (rows == 0 || K == 0 || cols == 0) {
        if (error) *error = "PackRcOzakiHipMxfp4: degenerate shape";
        return false;
    }
    if ((K % kRcOzakiHipMxBlk) != 0) {
        if (error) *error = "PackRcOzakiHipMxfp4: K must be multiple of 32 for VEC32 UE8M0";
        return false;
    }
    if ((K % 2u) != 0) {
        if (error) *error = "PackRcOzakiHipMxfp4: K must be even for E2M1 packing";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * K ||
        right.size() != static_cast<size_t>(K) * cols) {
        if (error) *error = "PackRcOzakiHipMxfp4: size mismatch";
        return false;
    }
    const uint32_t kblocks = (K + kRcOzakiHipMxBlk - 1u) / kRcOzakiHipMxBlk;
    out.kblocks = kblocks;
    const size_t a_elems = static_cast<size_t>(K) * rows;
    const size_t b_elems = static_cast<size_t>(K) * cols;
    out.a_e2m1.assign((a_elems + 1) / 2, 0);
    out.b_e2m1.assign((b_elems + 1) / 2, 0);
    out.sfa_ue8m0.assign(static_cast<size_t>(rows) * kblocks, kUe8m0Bias);
    out.sfb_ue8m0.assign(static_cast<size_t>(cols) * kblocks, kUe8m0Bias);
    int8_t mu_tmp[kRcOzakiHipMxBlk];
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kRcOzakiHipMxBlk;
            const uint32_t n = std::min(kRcOzakiHipMxBlk, K - k0);
            int8_t block[kRcOzakiHipMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = left[static_cast<size_t>(r) * K + (k0 + t)];
            }
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "PackRcOzakiHipMxfp4: left block not MX-factorable";
                return false;
            }
            out.sfa_ue8m0[static_cast<size_t>(r) * kblocks + bj] =
                static_cast<uint8_t>(kUe8m0Bias + e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "PackRcOzakiHipMxfp4: left mu not E2M1";
                    return false;
                }
                PackNibble(out.a_e2m1.data(), static_cast<size_t>(k0 + t) * rows + r, nib);
            }
        }
    }
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kRcOzakiHipMxBlk;
            const uint32_t n = std::min(kRcOzakiHipMxBlk, K - k0);
            int8_t block[kRcOzakiHipMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = right[static_cast<size_t>(k0 + t) * cols + c];
            }
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "PackRcOzakiHipMxfp4: right block not MX-factorable";
                return false;
            }
            out.sfb_ue8m0[static_cast<size_t>(c) * kblocks + bj] =
                static_cast<uint8_t>(kUe8m0Bias + e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "PackRcOzakiHipMxfp4: right mu not E2M1";
                    return false;
                }
                PackNibble(out.b_e2m1.data(), static_cast<size_t>(k0 + t) * cols + c, nib);
            }
        }
    }
    if (error) error->clear();
    return true;
}

bool HostReferenceRcOzakiHipMxfp4GemmFromPack(const RcOzakiHipMxPack& pack, uint32_t rows,
                                             uint32_t inner, uint32_t cols,
                                             std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (pack.kblocks == 0 || rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "HostReferenceRcOzakiHipMxfp4: empty pack/shape";
        return false;
    }
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            int64_t acc = 0;
            for (uint32_t k = 0; k < inner; ++k) {
                const uint32_t bj = k / kRcOzakiHipMxBlk;
                const uint8_t ea = pack.sfa_ue8m0[static_cast<size_t>(r) * pack.kblocks + bj];
                const uint8_t eb = pack.sfb_ue8m0[static_cast<size_t>(c) * pack.kblocks + bj];
                const int32_t sa = 1 << (static_cast<int>(ea) - static_cast<int>(kUe8m0Bias));
                const int32_t sb = 1 << (static_cast<int>(eb) - static_cast<int>(kUe8m0Bias));
                const int8_t ma = DecodeRcOzakiHipE2M1Nibble(
                    UnpackNibble(pack.a_e2m1.data(), static_cast<size_t>(k) * rows + r));
                const int8_t mb = DecodeRcOzakiHipE2M1Nibble(
                    UnpackNibble(pack.b_e2m1.data(), static_cast<size_t>(k) * cols + c));
                acc += static_cast<int64_t>(ma) * sa * static_cast<int64_t>(mb) * sb;
            }
            out[static_cast<size_t>(r) * cols + c] = acc;
        }
    }
    if (error) error->clear();
    return true;
}

bool IsRcOzakiHipExactPanelsQualified()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_exact_qualified;
}

bool SelfQualifyRcOzakiHipExactPanelsOnce()
{
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_exact_ran) return g_exact_qualified;
    }
    std::string err;
    bool ok = false;
    if (IsMatMulLTHipAvailable()) {
        std::vector<int8_t> L(64), R(64);
        for (size_t i = 0; i < L.size(); ++i) {
            L[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 97) - 48);
            R[i] = static_cast<int8_t>((static_cast<int32_t>(i * 3) % 95) - 47);
        }
        std::vector<int64_t> cpu, device;
        ok = matmul::v4::rc::RcOzakiCpuLimbSplitGemmS8S8Int64(L, R, 8, 8, 8, cpu) &&
             LaunchHipExactPanels(L, R, 8, 8, 8, device, &err) && device == cpu;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_exact_ran) {
        g_exact_ran = true;
        g_exact_qualified = ok;
    }
    return g_exact_qualified;
}

bool TryLaunchRcOzakiHipExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                                const std::vector<int8_t>& right, uint32_t rows,
                                                uint32_t inner, uint32_t cols,
                                                std::vector<int64_t>& out, std::string* error)
{
    if (!SelfQualifyRcOzakiHipExactPanelsOnce() || !IsRcOzakiHipExactPanelsQualified()) {
        out.clear();
        if (error) *error = RcOzakiHipDeficit();
        return false;
    }
    return LaunchHipExactPanels(left, right, rows, inner, cols, out, error);
}

bool IsRcOzakiHipMxfp4Qualified()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_mx_qualified;
}

bool IsRcOzakiHipMxfp4Attempted()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_mx_attempted;
}

std::string RcOzakiHipMxfp4ArchKey()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_mx_arch;
}

std::string RcOzakiHipMxfp4Backend()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_mx_backend;
}

std::string RcOzakiHipMxfp4Deficit()
{
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_mx_deficit.empty()) return g_mx_deficit;
    return RcOzakiHipDeficit();
}

bool SelfQualifyRcOzakiHipMxfp4Once()
{
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_mx_ran) return g_mx_qualified;
    }
    const std::string arch = HipArchKey();
    std::string err;
    bool qualified = false;
    bool attempted = false;
    std::string backend;
    std::string deficit = "requires gfx950 silicon";

#if defined(BTX_RC_HIP_HAS_MXFP4_PATH)
    if (IsGfx950()) {
        // Build MX-factorable panels and attempt hipBLASLt; require int64 match.
        // gfx950 selects the attempt surface only — never qualify from arch name.
        constexpr uint32_t rows = 4, cols = 4, K = 64;
        std::vector<int8_t> L(static_cast<size_t>(rows) * K);
        std::vector<int8_t> R(static_cast<size_t>(K) * cols);
        static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t k = 0; k < K; ++k) {
                const uint8_t e = static_cast<uint8_t>((k / 32u) % 4);
                L[static_cast<size_t>(r) * K + k] =
                    static_cast<int8_t>(kM11[(r + k) % 11] * (1 << e));
            }
        }
        for (uint32_t k = 0; k < K; ++k) {
            for (uint32_t c = 0; c < cols; ++c) {
                const uint8_t e = static_cast<uint8_t>((k / 32u + 1) % 4);
                R[static_cast<size_t>(k) * cols + c] =
                    static_cast<int8_t>(kM11[(c + k) % 11] * (1 << e));
            }
        }
        RcOzakiHipMxPack pack;
        std::vector<int64_t> dense(static_cast<size_t>(rows) * cols, 0);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t c = 0; c < cols; ++c) {
                int64_t acc = 0;
                for (uint32_t k = 0; k < K; ++k) {
                    acc += static_cast<int64_t>(L[static_cast<size_t>(r) * K + k]) *
                           static_cast<int64_t>(R[static_cast<size_t>(k) * cols + c]);
                }
                dense[static_cast<size_t>(r) * cols + c] = acc;
            }
        }
        attempted = true;
        std::vector<int64_t> device;
        const bool pack_ok = PackRcOzakiHipMxfp4OpATOpBN(L, R, rows, K, cols, pack, &err);
        const bool device_ok =
            pack_ok && AttemptHipBlasLtRcOzakiMxfp4(pack, rows, K, cols, device, &err) &&
            device == dense;
        if (device_ok) {
            qualified = true;
            backend = "mxfp4_hipblaslt_gfx950_opAT_opBN_VEC32";
            deficit.clear();
        } else {
            // Soft exactness probe via host scalar decode — never qualifies.
            std::vector<int64_t> from_pack;
            if (pack_ok &&
                HostReferenceRcOzakiHipMxfp4GemmFromPack(pack, rows, K, cols, from_pack,
                                                         &err) &&
                from_pack == dense) {
                backend = "mxfp4_host_pack_scalar-decode";
                deficit =
                    "rc_ozaki_hip_mxfp4_scalar-decode_exact_but_not_native_tensor";
                if (!err.empty()) deficit += "; hipblaslt_failed:" + err;
            } else {
                backend.clear();
                deficit = err.empty() ? "requires gfx950 silicon" : err;
            }
            qualified = false;
        }
    } else if (IsGfx942()) {
        deficit = "requires gfx942 silicon"; // FP8 lane not admitted here
        backend.clear();
    } else {
        deficit = "requires gfx950 silicon";
    }
#else
    (void)IsGfx950;
    (void)IsGfx942;
    deficit = "BTX_HIP_MXFP4_TYPES unset; requires gfx950 silicon";
#endif

    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_mx_ran) {
        g_mx_ran = true;
        g_mx_attempted = attempted;
        g_mx_qualified = qualified;
        g_mx_arch = arch;
        g_mx_backend = backend;
        g_mx_deficit = deficit;
    }
    return g_mx_qualified;
}

bool TryLaunchRcOzakiHipMxfp4GemmS8S8Int64(const std::vector<int8_t>& left,
                                          const std::vector<int8_t>& right, uint32_t rows,
                                          uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                          std::string* error)
{
    out.clear();
    if (!SelfQualifyRcOzakiHipMxfp4Once() || !IsRcOzakiHipMxfp4Qualified()) {
        if (error) *error = RcOzakiHipMxfp4Deficit();
        return false;
    }
    RcOzakiHipMxPack pack;
    if (!PackRcOzakiHipMxfp4OpATOpBN(left, right, rows, inner, cols, pack, error)) return false;
    return AttemptHipBlasLtRcOzakiMxfp4(pack, rows, inner, cols, out, error);
}

void ResetRcOzakiHipQualForTest()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_exact_ran = false;
    g_exact_qualified = false;
    g_mx_ran = false;
    g_mx_attempted = false;
    g_mx_qualified = false;
    g_mx_arch.clear();
    g_mx_backend.clear();
    g_mx_deficit.clear();
}

} // namespace matmul_v4::hip
