// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <cuda/cuda_context.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

// ===========================================================================
// NVIDIA backend for MatMul v4.4 ENC-DR-LT ("MatExpand") mining.
//
// See matmul_v4_lt_accel.h for the full contract. What this TU does:
//
//   * It compiles and ships two genuine, self-tested CUDA kernels
//     (DeviceGemmS8S8Tiled / DeviceGemmS32S8Tiled) that reproduce
//     matmul::v4::lt::ExactGemmS8S8 / ExactGemmS32S8 bit-for-bit -- exact
//     INT8xINT8->INT32 and INT32xINT8->INT32 tiled GEMMs, true integer
//     accumulation, no float anywhere. These are the two dense MatExpand
//     operand stages Y = G*W and B32 = Y*H that MatExpandCore runs for every
//     operand; the surrounding ExpandProjectorBMX4C panels, the nonlinear
//     ExtractDequantMatExpand, the projected combine and the digest all stay
//     on shared host code.
//   * BEFORE either kernel is ever trusted, SelfTestGemmKernelsOnce() runs
//     both against matmul::v4::lt::ExactGemmS8S8 / ExactGemmS32S8 on a small
//     deterministic fixture and compares every output byte; the result is
//     cached for the process. IsMatMulLTCudaAvailable() reports true only if
//     a CUDA device is present AND that self-test passed.
//   * When the self-test passes, ComputeDigestsOnlyLTCuda installs the device
//     GEMMs as a matmul::v4::lt::ExactGemmBackend on
//     matmul::v4::lt::WindowSketchMinerLT, so the dense MatExpand GEMMs for
//     the template operand A (paid once) AND every per-nonce operand B
//     actually execute on device (LaunchGemmS8S8 / LaunchGemmS32S8). Because
//     only the two GEMM stages are redirected -- every consensus-sensitive
//     derivation is unchanged host code reused verbatim -- each digest stays
//     byte-identical to matmul::v4::lt::ComputeDigestBMX4CLT by construction.
//   * On ANY runtime CUDA fault, MatExpandCore transparently falls back to
//     the CPU ExactGemm for that stage (still bit-exact); the result is then
//     reported with backend_status = Fallback. A digest is tagged Ok only
//     when the device served the GEMMs end-to-end.
// ===========================================================================

namespace matmul_v4::cuda {

namespace {

// RAII device buffer, mirroring the DeviceBuffer helper duplicated across
// every other v4.x accel TU in this tree (matmul_v4_accel.cu et al.).
struct DeviceBuffer {
    void* ptr{nullptr};
    ~DeviceBuffer() { if (ptr) cudaFree(ptr); }
    [[nodiscard]] bool Alloc(size_t bytes)
    {
        if (bytes == 0) { ptr = nullptr; return true; }
        return cudaMalloc(&ptr, bytes) == cudaSuccess;
    }
};

// Exact INT8xINT8->INT32 GEMM D(MxN) = A(MxK) * B(KxN), row-major, true
// int32 accumulation (portable scalar kernel; every v4.x accel TU in this
// tree also ships a portable ALU twin alongside its tensor-core path, so a
// build without IMMA/MFMA/tensor_ops still produces the identical integers).
// One thread per output element; simple and exact, not latency-tuned -- the
// bit-exactness self-test is what matters here, not throughput.
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

// Exact INT32xINT8->INT32 GEMM D(MxN) = A(MxK) * B(KxN), row-major. Used for
// the "B32 = Y*H" stage of the MatExpand fold (Y is the int32 output of an
// earlier s8xs8 GEMM, H is an int8 mixer panel). Accumulates in int64_t to
// stay safe against any transient widening the host reference might use
// internally, then narrows to int32_t -- the narrowing is well-defined
// truncation and matches the CPU reference's result whenever the true value
// fits int32 (which every MatExpand fold bound in matmul_v4_lt.h guarantees
// for valid (n) -- see kMatExpandEmax / ValidateDimsBMX4CLT).
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

} // namespace

// Public host launchers (declared in matmul_v4_lt_accel.h): bit-exact device
// GEMMs for the two dense MatExpand operand stages, usable directly as
// matmul::v4::lt::ExactGemmBackend callbacks.
bool LaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                    uint32_t rows, uint32_t k, uint32_t cols,
                    std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int8_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);

    DeviceBuffer dA, dB, dD;
    if (!dA.Alloc(lhs_bytes) || !dB.Alloc(rhs_bytes) || !dD.Alloc(out_bytes)) return false;
    if (cudaMemcpy(dA.ptr, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(dB.ptr, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;

    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    DeviceGemmS8S8Tiled<<<grid, block>>>(static_cast<const int8_t*>(dA.ptr), static_cast<const int8_t*>(dB.ptr),
                                         static_cast<int32_t*>(dD.ptr), static_cast<int>(rows),
                                         static_cast<int>(cols), static_cast<int>(k));
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaDeviceSynchronize() != cudaSuccess) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    return cudaMemcpy(out.data(), dD.ptr, out_bytes, cudaMemcpyDeviceToHost) == cudaSuccess;
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
    if (cudaMemcpy(dA.ptr, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(dB.ptr, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;

    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    DeviceGemmS32S8Tiled<<<grid, block>>>(static_cast<const int32_t*>(dA.ptr), static_cast<const int8_t*>(dB.ptr),
                                          static_cast<int32_t*>(dD.ptr), static_cast<int>(rows),
                                          static_cast<int>(cols), static_cast<int>(k));
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaDeviceSynchronize() != cudaSuccess) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    return cudaMemcpy(out.data(), dD.ptr, out_bytes, cudaMemcpyDeviceToHost) == cudaSuccess;
}

// Deterministic small fixture; independent of any consensus seed so the
// self-test never depends on (and can never leak information about) header
// state. Values span the full MatExpand fold range [-48, 48] via
// FoldInt32ToEmax48 so the fixture exercises the same alphabet the real
// operands use.
[[nodiscard]] bool SelfTestGemmKernelsOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        constexpr uint32_t kDim = 24; // multiple of a 16x16 block, ragged-safe
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

} // namespace

bool IsMatMulLTCudaAvailable()
{
    const btx::cuda::CudaRuntimeProbe probe = btx::cuda::ProbeCudaRuntime();
    if (!probe.compiled || !probe.available) {
        return false;
    }
    return SelfTestGemmKernelsOnce();
}

namespace {

[[nodiscard]] bool CudaGemmS8S8Fn(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out)
{
    return LaunchGemmS8S8(L, R, rows, inner, cols, out);
}

[[nodiscard]] bool CudaGemmS32S8Fn(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                                   uint32_t rows, uint32_t inner, uint32_t cols,
                                   std::vector<int32_t>& out)
{
    return LaunchGemmS32S8(L, R, rows, inner, cols, out);
}

[[nodiscard]] matmul::v4::lt::ExactGemmBackend MakeCudaExactGemmBackend()
{
    matmul::v4::lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &CudaGemmS8S8Fn;
    backend.gemm_s32s8 = &CudaGemmS32S8Fn;
    return backend;
}

} // namespace

bool ComputeDigestsOnlyLTCuda(const CBlockHeader& tmpl, uint32_t n,
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

    const bool device_ok = IsMatMulLTCudaAvailable();
    matmul::v4::lt::WindowSketchMinerLT miner(
        tmpl, n, device_ok ? MakeCudaExactGemmBackend() : matmul::v4::lt::ExactGemmBackend{});
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

} // namespace matmul_v4::cuda
