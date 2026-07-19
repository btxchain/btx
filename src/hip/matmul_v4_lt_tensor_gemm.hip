// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

#include <matmul/matmul_v4_lt.h>

#include <hip/hip_runtime.h>

#include <cstdint>
#include <mutex>
#include <vector>

// HIP MFMA preference for LT ExactGemm. Uses a portable device ALU GEMM that
// is self-tested against ExactGemm*; when rocBLAS/hipBLASLt MFMA heuristics
// are unavailable this still provides a calibrated device path. IsLtMfmaGemmAvailable
// is true only after self-test — callers that need "true MFMA tensor cores"
// should treat the availability flag as "device ExactGemm preferred" and rely
// on the bit-exact contract rather than a datasheet claim.

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

__global__ void GemmS8S8(const int8_t* A, const int8_t* B, int32_t* D, int M, int N, int K)
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

[[nodiscard]] bool LaunchDeviceS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
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
    hipLaunchKernelGGL(GemmS8S8, grid, block, 0, 0, static_cast<const int8_t*>(dA.ptr),
                       static_cast<const int8_t*>(dB.ptr), static_cast<int32_t*>(dD.ptr),
                       static_cast<int>(rows), static_cast<int>(cols), static_cast<int>(k));
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) return false;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    return hipMemcpy(out.data(), dD.ptr, out_bytes, hipMemcpyDeviceToHost) == hipSuccess;
}

[[nodiscard]] bool SelfTestOnce()
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
        if (!LaunchDeviceS8S8(left, right, kDim, kDim, kDim, gpu) || gpu != cpu) return;
        ok = true;
    });
    return ok;
}

} // namespace

bool IsLtMfmaGemmAvailable()
{
    int count = 0;
    if (hipGetDeviceCount(&count) != hipSuccess || count <= 0) return false;
    return SelfTestOnce();
}

bool TryLaunchLtMfmaGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                             uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (!IsLtMfmaGemmAvailable()) return false;
    return LaunchDeviceS8S8(left, right, rows, inner, cols, out);
}

bool TryLaunchLtMfmaGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                              uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false; // decline → scalar ExactGemmS32S8
}

} // namespace matmul_v4::hip
