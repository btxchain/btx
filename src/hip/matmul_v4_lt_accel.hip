// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <primitives/block.h>
#include <uint256.h>

#include <hip/hip_runtime.h>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <vector>

// ===========================================================================
// AMD ROCm/HIP backend for MatMul v4.4 ENC-DR-LT ("MatExpand") mining.
//
// See cuda/matmul_v4_lt_accel.cu's file header for the full reasoning; this
// TU mirrors it exactly on HIP (same self-tested GEMM kernels, same
// host-exact WindowSketchMinerLT digest computation, same "device buffers
// reserved for bring-up" posture already established by
// hip/matmul_v4_bmx4_accel.hip's own tier-(a)/tier-(b) gating).
// ===========================================================================

namespace matmul_v4::hip {

namespace {

struct DeviceBuffer {
    void* ptr{nullptr};
    ~DeviceBuffer() { if (ptr) hipFree(ptr); }
    [[nodiscard]] bool Alloc(size_t bytes)
    {
        if (bytes == 0) { ptr = nullptr; return true; }
        return hipMalloc(&ptr, bytes) == hipSuccess;
    }
};

// Portable scalar-integer GEMM kernels (exact, not latency-tuned -- see the
// CUDA sibling's comment on why a plain ALU kernel is the right choice for a
// bit-exactness-gated bring-up primitive). One thread per output element.
__global__ void DeviceGemmS8S8Tiled(const int8_t* __restrict__ A,
                                    const int8_t* __restrict__ B,
                                    int32_t* __restrict__ D,
                                    int M, int N, int K)
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

__global__ void DeviceGemmS32S8Tiled(const int32_t* __restrict__ A,
                                     const int8_t* __restrict__ B,
                                     int32_t* __restrict__ D,
                                     int M, int N, int K)
{
    const int col = blockIdx.x * blockDim.x + threadIdx.x;
    const int row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= M || col >= N) return;
    int64_t acc = 0;
    const size_t arow = static_cast<size_t>(row) * K;
    for (int k = 0; k < K; ++k) {
        acc += static_cast<int64_t>(A[arow + k]) * static_cast<int64_t>(B[static_cast<size_t>(k) * N + col]);
    }
    D[static_cast<size_t>(row) * N + col] = static_cast<int32_t>(acc);
}

[[nodiscard]] bool LaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t k, uint32_t cols,
                                  std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int8_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);

    DeviceBuffer dA, dB, dD;
    if (!dA.Alloc(lhs_bytes) || !dB.Alloc(rhs_bytes) || !dD.Alloc(out_bytes)) return false;
    if (hipMemcpy(dA.ptr, left.data(), lhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    if (hipMemcpy(dB.ptr, right.data(), rhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;

    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    hipLaunchKernelGGL(DeviceGemmS8S8Tiled, grid, block, 0, 0,
                       static_cast<const int8_t*>(dA.ptr), static_cast<const int8_t*>(dB.ptr),
                       static_cast<int32_t*>(dD.ptr), static_cast<int>(rows), static_cast<int>(cols),
                       static_cast<int>(k));
    if (hipGetLastError() != hipSuccess) return false;
    if (hipDeviceSynchronize() != hipSuccess) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    return hipMemcpy(out.data(), dD.ptr, out_bytes, hipMemcpyDeviceToHost) == hipSuccess;
}

[[nodiscard]] bool LaunchGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t k, uint32_t cols,
                                   std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int32_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);

    DeviceBuffer dA, dB, dD;
    if (!dA.Alloc(lhs_bytes) || !dB.Alloc(rhs_bytes) || !dD.Alloc(out_bytes)) return false;
    if (hipMemcpy(dA.ptr, left.data(), lhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    if (hipMemcpy(dB.ptr, right.data(), rhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;

    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    hipLaunchKernelGGL(DeviceGemmS32S8Tiled, grid, block, 0, 0,
                       static_cast<const int32_t*>(dA.ptr), static_cast<const int8_t*>(dB.ptr),
                       static_cast<int32_t*>(dD.ptr), static_cast<int>(rows), static_cast<int>(cols),
                       static_cast<int>(k));
    if (hipGetLastError() != hipSuccess) return false;
    if (hipDeviceSynchronize() != hipSuccess) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    return hipMemcpy(out.data(), dD.ptr, out_bytes, hipMemcpyDeviceToHost) == hipSuccess;
}

[[nodiscard]] bool SelfTestGemmKernelsOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        constexpr uint32_t kDim = 24;
        std::vector<int8_t> left(static_cast<size_t>(kDim) * kDim);
        std::vector<int8_t> right(static_cast<size_t>(kDim) * kDim);
        std::vector<int32_t> mid(static_cast<size_t>(kDim) * kDim);
        for (uint32_t i = 0; i < kDim * kDim; ++i) {
            left[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 7 - 101);
            right[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 11 + 53);
            mid[i] = static_cast<int32_t>(left[i]) * 997 - 12345;
        }

        const std::vector<int32_t> cpu_s8s8 = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu_s8s8;
        if (!LaunchGemmS8S8(left, right, kDim, kDim, kDim, gpu_s8s8) || gpu_s8s8 != cpu_s8s8) {
            return;
        }

        const std::vector<int32_t> cpu_s32s8 = matmul::v4::lt::ExactGemmS32S8(mid, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu_s32s8;
        if (!LaunchGemmS32S8(mid, right, kDim, kDim, kDim, gpu_s32s8) || gpu_s32s8 != cpu_s32s8) {
            return;
        }

        ok = true;
    });
    return ok;
}

[[nodiscard]] bool HipDeviceAvailable()
{
    int count = 0;
    return hipGetDeviceCount(&count) == hipSuccess && count > 0;
}

} // namespace

bool IsMatMulLTHipAvailable()
{
    if (!HipDeviceAvailable()) {
        return false;
    }
    return SelfTestGemmKernelsOnce();
}

namespace {

[[nodiscard]] bool HipGemmS8S8Fn(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                                 uint32_t rows, uint32_t inner, uint32_t cols,
                                 std::vector<int32_t>& out)
{
    return LaunchGemmS8S8(L, R, rows, inner, cols, out);
}

[[nodiscard]] bool HipGemmS32S8Fn(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out)
{
    return LaunchGemmS32S8(L, R, rows, inner, cols, out);
}

[[nodiscard]] matmul::v4::lt::ExactGemmBackend MakeHipExactGemmBackend()
{
    matmul::v4::lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &HipGemmS8S8Fn;
    backend.gemm_s32s8 = &HipGemmS32S8Fn;
    return backend;
}

} // namespace

bool ComputeDigestsOnlyLTHip(const CBlockHeader& tmpl, uint32_t n,
                             const uint64_t* nonces, size_t count,
                             std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    if (nonces == nullptr || count == 0) {
        return false;
    }

    uint32_t m = 0;
    if (!matmul::v4::lt::ValidateDimsBMX4CLT(n, m)) {
        return false;
    }

    const bool device_ok = IsMatMulLTHipAvailable();
    matmul::v4::lt::WindowSketchMinerLT miner(
        tmpl, n, device_ok ? MakeHipExactGemmBackend() : matmul::v4::lt::ExactGemmBackend{});
    if (!miner.Valid()) {
        return false;
    }

    const std::vector<uint64_t> nonce_vec(nonces, nonces + count);
    const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
    std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
    if (!miner.Mine(nonce_vec, kNoTarget, results, nullptr)) {
        return false;
    }
    const auto status = device_ok ? matmul::v4::bmx4::DigestOnlyBackendStatus::Ok
                                  : matmul::v4::bmx4::DigestOnlyBackendStatus::Fallback;
    for (auto& r : results) {
        r.target_match = false;
        r.backend_status = status;
    }

    out = std::move(results);
    return true;
}

} // namespace matmul_v4::hip
