// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

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

[[nodiscard]] bool RunCublasLtS8S8(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                   uint32_t M, uint32_t N, uint32_t K, std::string& error)
{
    cublasLtHandle_t lt = nullptr;
    if (cublasLtCreate(&lt) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtCreate failed";
        return false;
    }
    cublasLtMatmulDesc_t op_desc = nullptr;
    cublasLtMatrixLayout_t a_layout = nullptr;
    cublasLtMatrixLayout_t b_layout = nullptr;
    cublasLtMatrixLayout_t c_layout = nullptr;
    cublasLtMatmulPreference_t preference = nullptr;
    bool ok = false;

    auto cleanup = [&]() {
        if (preference) cublasLtMatmulPreferenceDestroy(preference);
        if (c_layout) cublasLtMatrixLayoutDestroy(c_layout);
        if (b_layout) cublasLtMatrixLayoutDestroy(b_layout);
        if (a_layout) cublasLtMatrixLayoutDestroy(a_layout);
        if (op_desc) cublasLtMatmulDescDestroy(op_desc);
        cublasLtDestroy(lt);
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
    // Row-major via leading-dimension = cols for each matrix.
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
    cublasLtMatmulHeuristicResult_t heuristic{};
    int returned = 0;
    if (cublasLtMatmulAlgoGetHeuristic(lt, op_desc, a_layout, b_layout, c_layout, c_layout,
                                       preference, 1, &heuristic, &returned) != CUBLAS_STATUS_SUCCESS ||
        returned < 1) {
        error = "no IMMA s8xs8->s32 heuristic";
        cleanup();
        return false;
    }
    const int32_t alpha = 1;
    const int32_t beta = 0;
    if (cublasLtMatmul(lt, op_desc, &alpha, dA, a_layout, dB, b_layout, &beta, dC, c_layout, dC, c_layout,
                       &heuristic.algo, nullptr, 0, nullptr) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmul IMMA failed";
        cleanup();
        return false;
    }
    ok = true;
    cleanup();
    return ok;
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
                         static_cast<int32_t*>(dD.ptr), rows, cols, k, error)) {
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
        constexpr uint32_t kDim = 32; // IMMA-friendly multiple
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
        ok = true;
    });
    return ok;
}

} // namespace

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

bool TryLaunchLtImmaGemmS32S8(const std::vector<int32_t>& /*left*/, const std::vector<int8_t>& /*right*/,
                              uint32_t /*rows*/, uint32_t /*inner*/, uint32_t /*cols*/,
                              std::vector<int32_t>& /*out*/)
{
    // No dedicated IMMA s32xs8 recipe in this TU — decline so the scalar/
    // ALU ExactGemmS32S8 path serves the call (C6: do not claim tensor).
    return false;
}

} // namespace matmul_v4::cuda
