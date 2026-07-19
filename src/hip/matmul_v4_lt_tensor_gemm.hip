// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

#include <matmul/matmul_v4_lt.h>

#include <hip/hip_runtime.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

// HIP LT ExactGemm preference layer (MI300/MI350 class — gfx942 / gfx950).
//
// Two distinct paths (never conflate labels):
//   1) MFMA / library path — hipBLASLt HIPBLAS_COMPUTE_32I (preferred) or
//      rocBLAS gemm_ex i8×i8→i32. IsLtMfmaGemmAvailable() is true ONLY after
//      this path executes and matches ExactGemmS8S8 bit-for-bit on square +
//      MatExpand panel shapes.
//   2) Device ALU — portable scalar int accumulate kernel. Advertised only as
//      IsLtDeviceAluGemmAvailable() / TryLaunchLtDeviceAluGemm*. Never MFMA.
//
// When hipBLASLt/rocBLAS headers+libs are absent (BTX_HAVE_HIPBLASLT /
// BTX_HAVE_ROCBLAS unset), the MFMA path is compile-time absent and the
// availability flag stays false.

#if defined(BTX_HAVE_HIPBLASLT)
#if defined(__has_include) && __has_include(<hipblaslt/hipblaslt.h>)
#include <hipblaslt/hipblaslt.h>
#define BTX_HIP_LT_TENSOR_HAVE_HIPBLASLT 1
#endif
#endif
#if !defined(BTX_HIP_LT_TENSOR_HAVE_HIPBLASLT) && defined(BTX_HAVE_ROCBLAS)
#if defined(__has_include) && __has_include(<rocblas/rocblas.h>)
#include <rocblas/rocblas.h>
#define BTX_HIP_LT_TENSOR_HAVE_ROCBLAS 1
#endif
#endif

namespace matmul_v4::hip {
namespace {

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

/** Persistent library handles / workspace for MFMA ExactGemm. Host launches
 *  use per-call DeviceBuffer; resident MatExpand passes device pointers. */
struct MfmaLibPool {
    std::mutex mu;

#if defined(BTX_HIP_LT_TENSOR_HAVE_HIPBLASLT)
    hipblasLtHandle_t lt{nullptr};
    void* workspace{nullptr};
    size_t workspace_bytes{0};
#elif defined(BTX_HIP_LT_TENSOR_HAVE_ROCBLAS)
    rocblas_handle roc{nullptr};
#endif
    bool ready{false};

    ~MfmaLibPool() { Release(); }

    void Release()
    {
#if defined(BTX_HIP_LT_TENSOR_HAVE_HIPBLASLT)
        if (workspace) {
            hipFree(workspace);
            workspace = nullptr;
            workspace_bytes = 0;
        }
        if (lt) {
            hipblasLtDestroy(lt);
            lt = nullptr;
        }
#elif defined(BTX_HIP_LT_TENSOR_HAVE_ROCBLAS)
        if (roc) {
            rocblas_destroy_handle(roc);
            roc = nullptr;
        }
#endif
        ready = false;
    }

    [[nodiscard]] bool EnsureHandles(size_t need_workspace)
    {
#if defined(BTX_HIP_LT_TENSOR_HAVE_HIPBLASLT)
        if (!ready) {
            if (hipblasLtCreate(&lt) != HIPBLAS_STATUS_SUCCESS) {
                lt = nullptr;
                return false;
            }
            ready = true;
        }
        if (need_workspace <= workspace_bytes) return true;
        if (workspace) {
            hipFree(workspace);
            workspace = nullptr;
            workspace_bytes = 0;
        }
        if (need_workspace == 0) return true;
        if (hipMalloc(&workspace, need_workspace) != hipSuccess) return false;
        workspace_bytes = need_workspace;
        return true;
#elif defined(BTX_HIP_LT_TENSOR_HAVE_ROCBLAS)
        (void)need_workspace;
        if (!ready) {
            if (rocblas_create_handle(&roc) != rocblas_status_success) {
                roc = nullptr;
                return false;
            }
            ready = true;
        }
        return true;
#else
        (void)need_workspace;
        return false;
#endif
    }
};

MfmaLibPool& MfmaPool()
{
    static MfmaLibPool pool;
    return pool;
}

__global__ void DeviceAluGemmS8S8(const int8_t* A, const int8_t* B, int32_t* D, int M, int N, int K)
{
    const int col = blockIdx.x * blockDim.x + threadIdx.x;
    const int row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= M || col >= N) return;
    int32_t acc = 0;
    const size_t arow = static_cast<size_t>(row) * K;
    for (int k = 0; k < K; ++k) {
        acc += static_cast<int32_t>(A[arow + k]) * static_cast<int32_t>(B[static_cast<size_t>(k) * N + col]);
    }
    D[static_cast<size_t>(row) * N + col] = acc;
}

[[nodiscard]] bool LaunchDeviceAluS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                       uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) {
        out.clear();
        return true;
    }
    DeviceBuffer dA, dB, dD;
    const size_t lhs_bytes = static_cast<size_t>(rows) * k;
    const size_t rhs_bytes = static_cast<size_t>(k) * cols;
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);
    if (!dA.Alloc(lhs_bytes) || !dB.Alloc(rhs_bytes) || !dD.Alloc(out_bytes)) return false;
    if (hipMemcpy(dA.ptr, left.data(), lhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    if (hipMemcpy(dB.ptr, right.data(), rhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    const dim3 block(16, 16, 1);
    const dim3 grid((cols + 15) / 16, (rows + 15) / 16, 1);
    hipLaunchKernelGGL(DeviceAluGemmS8S8, grid, block, 0, 0, static_cast<const int8_t*>(dA.ptr),
                       static_cast<const int8_t*>(dB.ptr), static_cast<int32_t*>(dD.ptr),
                       static_cast<int>(rows), static_cast<int>(cols), static_cast<int>(k));
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) return false;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    return hipMemcpy(out.data(), dD.ptr, out_bytes, hipMemcpyDeviceToHost) == hipSuccess;
}

[[nodiscard]] bool SelfTestDeviceAluOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        constexpr uint32_t kDim = 24;
        std::vector<int8_t> left(static_cast<size_t>(kDim) * kDim);
        std::vector<int8_t> right(static_cast<size_t>(kDim) * kDim);
        for (uint32_t i = 0; i < kDim * kDim; ++i) {
            left[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 7 - 101);
            right[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 11 + 53);
        }
        const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu;
        if (!LaunchDeviceAluS8S8(left, right, kDim, kDim, kDim, gpu) || gpu != cpu) return;
        ok = true;
    });
    return ok;
}

#if defined(BTX_HIP_LT_TENSOR_HAVE_HIPBLASLT)

[[nodiscard]] bool RunHipBlasLtS8S8(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                    uint32_t M, uint32_t N, uint32_t K, hipStream_t stream,
                                    std::string& error)
{
    constexpr size_t kDefaultWorkspace = 8ull << 20;
    auto& pool = MfmaPool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.EnsureHandles(kDefaultWorkspace)) {
        error = "hipblasLtCreate / workspace alloc failed";
        return false;
    }

    hipblasLtMatmulDesc_t op_desc = nullptr;
    hipblasLtMatrixLayout_t a_layout = nullptr;
    hipblasLtMatrixLayout_t b_layout = nullptr;
    hipblasLtMatrixLayout_t c_layout = nullptr;
    hipblasLtMatmulPreference_t preference = nullptr;

    auto cleanup = [&]() {
        if (preference) hipblasLtMatmulPreferenceDestroy(preference);
        if (c_layout) hipblasLtMatrixLayoutDestroy(c_layout);
        if (b_layout) hipblasLtMatrixLayoutDestroy(b_layout);
        if (a_layout) hipblasLtMatrixLayoutDestroy(a_layout);
        if (op_desc) hipblasLtMatmulDescDestroy(op_desc);
    };

    if (hipblasLtMatmulDescCreate(&op_desc, HIPBLAS_COMPUTE_32I, HIP_R_32I) != HIPBLAS_STATUS_SUCCESS) {
        error = "hipblasLtMatmulDescCreate failed";
        cleanup();
        return false;
    }
    const hipblasOperation_t op_n = HIPBLAS_OP_N;
    if (hipblasLtMatmulDescSetAttribute(op_desc, HIPBLASLT_MATMUL_DESC_TRANSA, &op_n, sizeof(op_n)) !=
            HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatmulDescSetAttribute(op_desc, HIPBLASLT_MATMUL_DESC_TRANSB, &op_n, sizeof(op_n)) !=
            HIPBLAS_STATUS_SUCCESS) {
        error = "hipblasLtMatmulDescSetAttribute failed";
        cleanup();
        return false;
    }
    if (hipblasLtMatrixLayoutCreate(&a_layout, HIP_R_8I, M, K, K) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutCreate(&b_layout, HIP_R_8I, K, N, N) != HIPBLAS_STATUS_SUCCESS ||
        hipblasLtMatrixLayoutCreate(&c_layout, HIP_R_32I, M, N, N) != HIPBLAS_STATUS_SUCCESS) {
        error = "hipblasLtMatrixLayoutCreate failed";
        cleanup();
        return false;
    }
    const hipblasLtOrder_t order = HIPBLASLT_ORDER_ROW;
    hipblasLtMatrixLayoutSetAttribute(a_layout, HIPBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));
    hipblasLtMatrixLayoutSetAttribute(b_layout, HIPBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));
    hipblasLtMatrixLayoutSetAttribute(c_layout, HIPBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));

    if (hipblasLtMatmulPreferenceCreate(&preference) != HIPBLAS_STATUS_SUCCESS) {
        error = "hipblasLtMatmulPreferenceCreate failed";
        cleanup();
        return false;
    }
    hipblasLtMatmulPreferenceSetAttribute(preference, HIPBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,
                                          &pool.workspace_bytes, sizeof(pool.workspace_bytes));

    hipblasLtMatmulHeuristicResult_t heuristic{};
    int returned = 0;
    if (hipblasLtMatmulAlgoGetHeuristic(pool.lt, op_desc, a_layout, b_layout, c_layout, c_layout, preference, 1,
                                        &heuristic, &returned) != HIPBLAS_STATUS_SUCCESS ||
        returned < 1) {
        error = "no hipBLASLt s8xs8->s32 heuristic";
        cleanup();
        return false;
    }
    const int32_t alpha = 1;
    const int32_t beta = 0;
    if (hipblasLtMatmul(pool.lt, op_desc, &alpha, dA, a_layout, dB, b_layout, &beta, dC, c_layout, dC, c_layout,
                        &heuristic.algo, pool.workspace, pool.workspace_bytes, stream) != HIPBLAS_STATUS_SUCCESS) {
        error = "hipblasLtMatmul s8xs8->s32 failed";
        cleanup();
        return false;
    }
    cleanup();
    return true;
}

#elif defined(BTX_HIP_LT_TENSOR_HAVE_ROCBLAS)

[[nodiscard]] bool RunRocBlasS8S8(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                  uint32_t M, uint32_t N, uint32_t K, hipStream_t stream,
                                  std::string& error)
{
    // Row-major C = A*B via column-major BLAS: C^T = B^T * A^T.
    auto& pool = MfmaPool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.EnsureHandles(0)) {
        error = "rocblas_create_handle failed";
        return false;
    }
    if (stream) {
        if (rocblas_set_stream(pool.roc, stream) != rocblas_status_success) {
            error = "rocblas_set_stream failed";
            return false;
        }
    }
    const int32_t alpha = 1;
    const int32_t beta = 0;
    const rocblas_status st = rocblas_gemm_ex(
        pool.roc, rocblas_operation_none, rocblas_operation_none,
        static_cast<rocblas_int>(N), static_cast<rocblas_int>(M), static_cast<rocblas_int>(K), &alpha,
        dB, rocblas_datatype_i8_r, static_cast<rocblas_int>(N),
        dA, rocblas_datatype_i8_r, static_cast<rocblas_int>(K), &beta,
        dC, rocblas_datatype_i32_r, static_cast<rocblas_int>(N),
        dC, rocblas_datatype_i32_r, static_cast<rocblas_int>(N),
        rocblas_datatype_i32_r, rocblas_gemm_algo_standard, 0, rocblas_gemm_flags_none);
    if (st != rocblas_status_success) {
        error = "rocblas_gemm_ex i8xi8->i32 failed";
        return false;
    }
    return true;
}

[[nodiscard]] bool RunHipBlasLtS8S8(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                    uint32_t M, uint32_t N, uint32_t K, hipStream_t stream,
                                    std::string& error)
{
    return RunRocBlasS8S8(dA, dB, dC, M, N, K, stream, error);
}

#else

[[nodiscard]] bool RunHipBlasLtS8S8(const int8_t*, const int8_t*, int32_t*,
                                    uint32_t, uint32_t, uint32_t, hipStream_t, std::string& error)
{
    error = "hipBLASLt/rocBLAS not linked";
    return false;
}

#endif

[[nodiscard]] bool LaunchBlasS8S8Host(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                      uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
#if !defined(BTX_HIP_LT_TENSOR_HAVE_HIPBLASLT) && !defined(BTX_HIP_LT_TENSOR_HAVE_ROCBLAS)
    (void)left; (void)right; (void)rows; (void)k; (void)cols; (void)out;
    return false;
#else
    if (rows == 0 || k == 0 || cols == 0) {
        out.clear();
        return true;
    }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int8_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);
    // Per-call device buffers (like CUDA IMMA host path) — library handle stays pooled.
    DeviceBuffer dA, dB, dD;
    if (!dA.Alloc(lhs_bytes) || !dB.Alloc(rhs_bytes) || !dD.Alloc(out_bytes)) return false;
    if (hipMemcpy(dA.ptr, left.data(), lhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    if (hipMemcpy(dB.ptr, right.data(), rhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    std::string error;
    if (!RunHipBlasLtS8S8(static_cast<const int8_t*>(dA.ptr), static_cast<const int8_t*>(dB.ptr),
                          static_cast<int32_t*>(dD.ptr), rows, cols, k, /*stream=*/nullptr, error)) {
        return false;
    }
    if (hipDeviceSynchronize() != hipSuccess) return false;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    return hipMemcpy(out.data(), dD.ptr, out_bytes, hipMemcpyDeviceToHost) == hipSuccess;
#endif
}

[[nodiscard]] bool SelfTestBlasMfmaOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
#if !defined(BTX_HIP_LT_TENSOR_HAVE_HIPBLASLT) && !defined(BTX_HIP_LT_TENSOR_HAVE_ROCBLAS)
        return;
#else
        constexpr uint32_t kDim = 32;
        std::vector<int8_t> left(static_cast<size_t>(kDim) * kDim);
        std::vector<int8_t> right(static_cast<size_t>(kDim) * kDim);
        for (uint32_t i = 0; i < kDim * kDim; ++i) {
            left[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 7 - 101);
            right[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 11 + 53);
        }
        const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu;
        if (!LaunchBlasS8S8Host(left, right, kDim, kDim, kDim, gpu) || gpu != cpu) {
            return;
        }
        // MatExpand panel: G (n×n) * W (n×w) with normative kMatExpandPanelW.
        constexpr uint32_t kN = 64;
        constexpr uint32_t kW = matmul::v4::lt::kMatExpandPanelW;
        std::vector<int8_t> G(static_cast<size_t>(kN) * kN);
        std::vector<int8_t> W(static_cast<size_t>(kN) * kW);
        for (uint32_t i = 0; i < kN * kN; ++i) {
            G[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 3 - 17);
        }
        for (uint32_t i = 0; i < kN * kW; ++i) {
            W[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 5 + 9);
        }
        const auto cpu_panel = matmul::v4::lt::ExactGemmS8S8(G, W, kN, kN, kW);
        std::vector<int32_t> gpu_panel;
        if (!LaunchBlasS8S8Host(G, W, kN, kN, kW, gpu_panel) || gpu_panel != cpu_panel) {
            return;
        }
        ok = true;
#endif
    });
    return ok;
}

[[nodiscard]] bool HipDevicePresent()
{
    int count = 0;
    return hipGetDeviceCount(&count) == hipSuccess && count > 0;
}

} // namespace

bool IsLtMfmaGemmAvailable()
{
    if (!HipDevicePresent()) return false;
    return SelfTestBlasMfmaOnce();
}

bool TryLaunchLtMfmaGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                             uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (!IsLtMfmaGemmAvailable()) return false;
    return LaunchBlasS8S8Host(left, right, rows, inner, cols, out);
}

bool TryLaunchLtMfmaGemmS8S8Device(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                   uint32_t rows, uint32_t cols, uint32_t inner, void* stream)
{
    if (dA == nullptr || dB == nullptr || dC == nullptr) return false;
    if (rows == 0 || cols == 0 || inner == 0) return true;
    if (!IsLtMfmaGemmAvailable()) return false;
    std::string error;
    return RunHipBlasLtS8S8(dA, dB, dC, rows, cols, inner, static_cast<hipStream_t>(stream), error);
}

bool TryLaunchLtMfmaGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                              uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    // No dedicated MFMA s32×s8 recipe — never advertise one.
    return false;
}

bool IsLtDeviceAluGemmAvailable()
{
    if (!HipDevicePresent()) return false;
    return SelfTestDeviceAluOnce();
}

bool TryLaunchLtDeviceAluGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (!IsLtDeviceAluGemmAvailable()) return false;
    return LaunchDeviceAluS8S8(left, right, rows, inner, cols, out);
}

bool TryLaunchLtDeviceAluGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                                   uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

} // namespace matmul_v4::hip
