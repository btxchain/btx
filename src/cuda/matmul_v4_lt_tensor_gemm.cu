// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

#include <cuda/cuda_context.h>
#include <matmul/matmul_v4_lt.h>

#include <cublasLt.h>
#include <cuda_runtime.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

// CUDA IMMA path for LT ExactGemm: cuBLASLt CUBLAS_COMPUTE_32I (s8xs8->s32).
// Self-tested bit-for-bit against ExactGemmS8S8 before IsLtImmaGemmAvailable
// returns true. S32S8 declines to scalar (no dedicated IMMA shape here) so we
// never advertise a tensor path we did not run.
//
// Target arches (PR #89): sm_90 (H100/H200), sm_100 (B200), sm_120 (5090).

namespace matmul_v4::cuda {
namespace {

struct DeviceBuffer {
    void* ptr{nullptr};
    ~DeviceBuffer()
    {
        if (ptr) cudaFree(ptr);
    }
    [[nodiscard]] bool Alloc(size_t bytes)
    {
        if (bytes == 0) {
            ptr = nullptr;
            return true;
        }
        return cudaMalloc(&ptr, bytes) == cudaSuccess;
    }
};

struct ImmaLtPool {
    std::mutex mu;
    cublasLtHandle_t lt{nullptr};
    void* workspace{nullptr};
    size_t workspace_bytes{0};
    bool ready{false};

    ~ImmaLtPool() { Release(); }

    void Release()
    {
        if (workspace) {
            cudaFree(workspace);
            workspace = nullptr;
            workspace_bytes = 0;
        }
        if (lt) {
            cublasLtDestroy(lt);
            lt = nullptr;
        }
        ready = false;
    }

    [[nodiscard]] bool Ensure(size_t need_workspace)
    {
        if (!ready) {
            if (cublasLtCreate(&lt) != CUBLAS_STATUS_SUCCESS) {
                lt = nullptr;
                return false;
            }
            ready = true;
        }
        if (need_workspace <= workspace_bytes) return true;
        if (workspace) {
            cudaFree(workspace);
            workspace = nullptr;
            workspace_bytes = 0;
        }
        if (need_workspace == 0) return true;
        if (cudaMalloc(&workspace, need_workspace) != cudaSuccess) return false;
        workspace_bytes = need_workspace;
        return true;
    }
};

ImmaLtPool& ImmaPool()
{
    static ImmaLtPool pool;
    return pool;
}

[[nodiscard]] bool RunCublasLtS8S8(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                   uint32_t M, uint32_t N, uint32_t K,
                                   cudaStream_t stream, std::string& error)
{
    constexpr size_t kDefaultWorkspace = 8ull << 20;

    auto& pool = ImmaPool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.Ensure(kDefaultWorkspace)) {
        error = "cublasLtCreate / workspace alloc failed";
        return false;
    }

    cublasLtMatmulDesc_t op_desc = nullptr;
    cublasLtMatrixLayout_t a_layout = nullptr;
    cublasLtMatrixLayout_t b_layout = nullptr;
    cublasLtMatrixLayout_t c_layout = nullptr;
    cublasLtMatmulPreference_t preference = nullptr;

    auto cleanup = [&]() {
        if (preference) cublasLtMatmulPreferenceDestroy(preference);
        if (c_layout) cublasLtMatrixLayoutDestroy(c_layout);
        if (b_layout) cublasLtMatrixLayoutDestroy(b_layout);
        if (a_layout) cublasLtMatrixLayoutDestroy(a_layout);
        if (op_desc) cublasLtMatmulDescDestroy(op_desc);
    };

    if (cublasLtMatmulDescCreate(&op_desc, CUBLAS_COMPUTE_32I, CUDA_R_32I) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulDescCreate failed";
        cleanup();
        return false;
    }
    const cublasOperation_t op_n = CUBLAS_OP_N;
    if (cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_TRANSA, &op_n, sizeof(op_n)) != CUBLAS_STATUS_SUCCESS ||
        cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_TRANSB, &op_n, sizeof(op_n)) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulDescSetAttribute failed";
        cleanup();
        return false;
    }
    if (cublasLtMatrixLayoutCreate(&a_layout, CUDA_R_8I, M, K, K) != CUBLAS_STATUS_SUCCESS ||
        cublasLtMatrixLayoutCreate(&b_layout, CUDA_R_8I, K, N, N) != CUBLAS_STATUS_SUCCESS ||
        cublasLtMatrixLayoutCreate(&c_layout, CUDA_R_32I, M, N, N) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatrixLayoutCreate failed";
        cleanup();
        return false;
    }
    const cublasLtOrder_t order = CUBLASLT_ORDER_ROW;
    cublasLtMatrixLayoutSetAttribute(a_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));
    cublasLtMatrixLayoutSetAttribute(b_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));
    cublasLtMatrixLayoutSetAttribute(c_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));

    if (cublasLtMatmulPreferenceCreate(&preference) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulPreferenceCreate failed";
        cleanup();
        return false;
    }
    cublasLtMatmulPreferenceSetAttribute(preference, CUBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,
                                         &pool.workspace_bytes, sizeof(pool.workspace_bytes));

    cublasLtMatmulHeuristicResult_t heuristic{};
    int returned = 0;
    if (cublasLtMatmulAlgoGetHeuristic(pool.lt, op_desc, a_layout, b_layout, c_layout, c_layout,
                                       preference, 1, &heuristic, &returned) != CUBLAS_STATUS_SUCCESS ||
        returned < 1) {
        error = "no IMMA s8xs8->s32 heuristic";
        cleanup();
        return false;
    }
    const int32_t alpha = 1;
    const int32_t beta = 0;
    if (cublasLtMatmul(pool.lt, op_desc, &alpha, dA, a_layout, dB, b_layout, &beta, dC, c_layout, dC, c_layout,
                       &heuristic.algo, pool.workspace, pool.workspace_bytes, stream) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmul IMMA failed";
        cleanup();
        return false;
    }
    cleanup();
    return true;
}

[[nodiscard]] bool LaunchImmaS8S8Host(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                      uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) {
        out.clear();
        return true;
    }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int8_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);
    DeviceBuffer dA, dB, dD;
    if (!dA.Alloc(lhs_bytes) || !dB.Alloc(rhs_bytes) || !dD.Alloc(out_bytes)) return false;
    if (cudaMemcpy(dA.ptr, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(dB.ptr, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;
    std::string error;
    if (!RunCublasLtS8S8(static_cast<const int8_t*>(dA.ptr), static_cast<const int8_t*>(dB.ptr),
                         static_cast<int32_t*>(dD.ptr), rows, cols, k, /*stream=*/nullptr, error)) {
        return false;
    }
    if (cudaDeviceSynchronize() != cudaSuccess) return false;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    return cudaMemcpy(out.data(), dD.ptr, out_bytes, cudaMemcpyDeviceToHost) == cudaSuccess;
}

[[nodiscard]] bool SelfTestImmaOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        constexpr uint32_t kDim = 32;
        std::vector<int8_t> left(static_cast<size_t>(kDim) * kDim);
        std::vector<int8_t> right(static_cast<size_t>(kDim) * kDim);
        for (uint32_t i = 0; i < kDim * kDim; ++i) {
            left[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 7 - 101);
            right[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 11 + 53);
        }
        const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu;
        if (!LaunchImmaS8S8Host(left, right, kDim, kDim, kDim, gpu) || gpu != cpu) {
            return;
        }
        constexpr uint32_t kN = 64;
        constexpr uint32_t kW = 16;
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
        if (!LaunchImmaS8S8Host(G, W, kN, kN, kW, gpu_panel) || gpu_panel != cpu_panel) {
            return;
        }
        ok = true;
    });
    return ok;
}

[[nodiscard]] LtCudaArchNameClass ClassifyArch(uint32_t major, uint32_t minor)
{
    (void)minor;
    if (major == 9) return LtCudaArchNameClass::Hopper;
    if (major == 10) return LtCudaArchNameClass::BlackwellDc;
    if (major == 12) return LtCudaArchNameClass::BlackwellConsumer;
    if (major == 0) return LtCudaArchNameClass::Unknown;
    return LtCudaArchNameClass::Other;
}

[[nodiscard]] const char* NameClassString(LtCudaArchNameClass c)
{
    switch (c) {
    case LtCudaArchNameClass::Hopper: return "hopper";
    case LtCudaArchNameClass::BlackwellDc: return "blackwell_dc";
    case LtCudaArchNameClass::BlackwellConsumer: return "blackwell_consumer";
    case LtCudaArchNameClass::Other: return "other";
    case LtCudaArchNameClass::Unknown:
    default: return "unknown";
    }
}

} // namespace

LtCudaArchProbe ProbeLtCudaArch()
{
    LtCudaArchProbe out;
    const btx::cuda::CudaRuntimeProbe runtime = btx::cuda::ProbeCudaRuntime();
    if (!runtime.compiled || !runtime.available || runtime.device_index < 0) {
        out.name_class_string = NameClassString(LtCudaArchNameClass::Unknown);
        out.sm_string = "sm_00";
        return out;
    }
    out.available = true;
    out.device_index = runtime.device_index;
    out.device_name = runtime.device_name;
    out.compute_capability_major = runtime.compute_capability_major;
    out.compute_capability_minor = runtime.compute_capability_minor;
    out.sm_string = "sm_" + std::to_string(runtime.compute_capability_major) +
                    std::to_string(runtime.compute_capability_minor);
    out.name_class = ClassifyArch(runtime.compute_capability_major, runtime.compute_capability_minor);
    out.name_class_string = NameClassString(out.name_class);
    return out;
}

LtCudaExactGemmCapabilities ProbeLtCudaExactGemmCapabilities()
{
    LtCudaExactGemmCapabilities caps;
    caps.arch = ProbeLtCudaArch();
    caps.exact_s8_s8_s32 = IsLtImmaGemmAvailable();
    caps.exact_partitioned_s32_s8 = false;
    caps.device_scalar_gemm = caps.arch.available;
    caps.device_hashing = false;
    return caps;
}

bool IsLtImmaGemmAvailable()
{
    int device_count = 0;
    if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count <= 0) {
        return false;
    }
    return SelfTestImmaOnce();
}

bool TryLaunchLtImmaGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                             uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (!IsLtImmaGemmAvailable()) return false;
    return LaunchImmaS8S8Host(left, right, rows, inner, cols, out);
}

bool TryLaunchLtImmaGemmS8S8Device(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                   uint32_t rows, uint32_t cols, uint32_t inner, void* stream)
{
    if (dA == nullptr || dB == nullptr || dC == nullptr) return false;
    if (rows == 0 || cols == 0 || inner == 0) return true;
    if (!IsLtImmaGemmAvailable()) return false;
    std::string error;
    return RunCublasLtS8S8(dA, dB, dC, rows, cols, inner,
                           static_cast<cudaStream_t>(stream), error);
}

bool TryLaunchLtImmaGemmS32S8(const std::vector<int32_t>& /*left*/, const std::vector<int8_t>& /*right*/,
                              uint32_t /*rows*/, uint32_t /*inner*/, uint32_t /*cols*/,
                              std::vector<int32_t>& /*out*/)
{
    return false;
}

} // namespace matmul_v4::cuda
