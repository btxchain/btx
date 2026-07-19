// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <cuda/cuda_context.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

// ===========================================================================
// NVIDIA backend for MatMul v4.4 ENC-DR-LT ("MatExpand") mining.
//
// Hot path (when a calibrated CUDA device is present):
 //   persistent device-resident loop over MatExpand → project → combine.
 //   When IsLtImmaGemmAvailable(), s8xs8 stages (G*W, U*Ahat, Bhat*V) use
 //   cuBLASLt CUBLAS_COMPUTE_32I IMMA on resident device pointers; s32xs8
 //   (Y*H) stays scalar DeviceGemmS32S8Tiled — TryLaunchLtImmaGemmS32S8 always
 //   declines (no exact s32×s8→s32 cuBLASLt recipe); never labeled IMMA.
 //   When IMMA declines, scalar tiled DeviceGemm* + CUDA-graph replay serve
 //   the same buffers — never labeled IMMA. Digest hashing stays on host after
 //   Chat D2H (honest gap: device-side SHA256d of Chat is not wired yet).
 //
 // Fail-closed fallback:
 //   host ExactGemm* / WindowSketchMinerLT (bit-exact). That host path is the
 //   safety net when the device declines — it is NOT the complete accelerator.
 //
 // Availability requires a one-time bit-identity self-test of the GEMM kernels
 // AND a one-nonce device-resident digest vs ComputeDigestBMX4CLT.
// ===========================================================================

namespace matmul_v4::cuda {

namespace {

// Domain tags MUST match src/matmul/matmul_v4_lt.cpp (anonymous-namespace twins).
constexpr char kMatExpandGTag[] = "BTX_MATEXPAND_G_V44LT";
constexpr char kMatExpandHTag[] = "BTX_MATEXPAND_H_V44LT";
constexpr char kMatExpandWTag[] = "BTX_MATEXPAND_W_V44LT";
constexpr char kMatExpandWATag[] = "BTX_MATEXPAND_WA_V44LT";

uint256 DeriveTaggedSeed(const char* tag, size_t taglen, const uint256& hash)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(hash.data(), uint256::size());
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

// ---------------------------------------------------------------------------
// Device kernels: exact GEMMs + ExtractDequant + F_q combine.
// ---------------------------------------------------------------------------

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

__device__ __forceinline__ uint32_t DeviceRotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__ void DeviceChaChaQuarter(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b; d = DeviceRotl32(d ^ a, 16);
    c += d; b = DeviceRotl32(b ^ c, 12);
    a += b; d = DeviceRotl32(d ^ a, 8);
    c += d; b = DeviceRotl32(b ^ c, 7);
}

// Bit-identical to matmul_v4_lt.cpp MatExpandPrfKeystream first 8 bytes (LE64).
//
// Position salt (i,j) MUST be full-width uint32 — never truncate to 16 bits:
//   nonce_second = (uint64_t{i} << 32) | uint64_t{j}
// Truncation consensus-splits vs CPU and reopens a ~32× low-rank shortcut.
// See doc/btx-matmul-v4.4-lt-matexpand-position-salt.md.
__device__ __forceinline__ uint64_t DeviceMatExpandPrfLE64(const uint32_t key[8], int32_t raw,
                                                          uint32_t i, uint32_t j, uint32_t remix,
                                                          uint32_t lane)
{
    static_assert(sizeof(i) == 4 && sizeof(j) == 4,
                  "DeviceMatExpandPrfLE64: (i,j) must be full-width uint32");
    uint32_t x0 = 0x61707865u, x1 = 0x3320646eu, x2 = 0x79622d32u, x3 = 0x6b206574u;
    uint32_t x4 = key[0], x5 = key[1], x6 = key[2], x7 = key[3];
    uint32_t x8 = key[4], x9 = key[5], x10 = key[6], x11 = key[7];
    uint32_t x12 = remix;
    uint32_t x13 = static_cast<uint32_t>(raw) ^ lane;
    // Full 32-bit i → x15, full 32-bit j → x14. Do not mask to 0xffff.
    const uint64_t nonce_second = (static_cast<uint64_t>(i) << 32) | static_cast<uint64_t>(j);
    uint32_t x14 = static_cast<uint32_t>(nonce_second);
    uint32_t x15 = static_cast<uint32_t>(nonce_second >> 32);

    const uint32_t j4 = x4, j5 = x5, j6 = x6, j7 = x7;
    const uint32_t j8 = x8, j9 = x9, j10 = x10, j11 = x11;
    const uint32_t j12 = x12, j13 = x13, j14 = x14, j15 = x15;

#pragma unroll
    for (int r = 0; r < 10; ++r) {
        DeviceChaChaQuarter(x0, x4, x8, x12);
        DeviceChaChaQuarter(x1, x5, x9, x13);
        DeviceChaChaQuarter(x2, x6, x10, x14);
        DeviceChaChaQuarter(x3, x7, x11, x15);
        DeviceChaChaQuarter(x0, x5, x10, x15);
        DeviceChaChaQuarter(x1, x6, x11, x12);
        DeviceChaChaQuarter(x2, x7, x8, x13);
        DeviceChaChaQuarter(x3, x4, x9, x14);
    }

    x0 += 0x61707865u; x1 += 0x3320646eu; x2 += 0x79622d32u; x3 += 0x6b206574u;
    x4 += j4; x5 += j5; x6 += j6; x7 += j7;
    x8 += j8; x9 += j9; x10 += j10; x11 += j11;
    x12 += j12; x13 += j13; x14 += j14; x15 += j15;

    return static_cast<uint64_t>(x0) | (static_cast<uint64_t>(x1) << 32);
}

// Bit-identical to matmul::v4::bmx4::SampleMantissaNibble (E2M1 M11 table).
__device__ __forceinline__ int8_t DeviceSampleMantissaNibble(uint8_t nibble, bool& accepted)
{
    const uint8_t nib = nibble & 0x0F;
    const uint8_t sign = (nib >> 3) & 1;
    const uint8_t exp = (nib >> 1) & 3;
    const uint8_t man = nib & 1;
    int mag = 0;
    bool integer = true;
    switch (exp) {
    case 0: mag = 0; integer = (man == 0); break;
    case 1: mag = 1; integer = (man == 0); break;
    case 2: mag = (man == 0) ? 2 : 3; break;
    case 3: mag = (man == 0) ? 4 : 6; break;
    default: break;
    }
    if (!integer || (sign && mag == 0)) {
        accepted = false;
        return 0;
    }
    accepted = true;
    return static_cast<int8_t>(sign ? -mag : mag);
}

__device__ __forceinline__ int8_t DeviceExtractDequant(int32_t raw, uint32_t i, uint32_t j,
                                                      const uint32_t key[8])
{
    constexpr uint32_t kLaneMant = 0x4D414E54u;
    constexpr uint32_t kLaneScale = 0x53434C45u;
    uint32_t remix = 0;
    for (;;) {
        const uint64_t mixed = DeviceMatExpandPrfLE64(key, raw, i, j, remix, kLaneMant);
        for (int shift = 0; shift < 64; shift += 4) {
            bool accepted = false;
            const int8_t mu = DeviceSampleMantissaNibble(
                static_cast<uint8_t>((mixed >> shift) & 0x0F), accepted);
            if (!accepted) continue;
            const uint64_t scale_stream =
                DeviceMatExpandPrfLE64(key, raw, i, j, remix, kLaneScale);
            // Exact mul — never signed left-shift (negative mu << e is UB).
            const uint8_t e = static_cast<uint8_t>(scale_stream & 0x3);
            return static_cast<int8_t>(static_cast<int32_t>(mu) * (int32_t{1} << e));
        }
        ++remix;
    }
}

__global__ void DeviceExtractDequantMatExpand(const int32_t* __restrict__ B32,
                                              int8_t* __restrict__ Bhat,
                                              uint32_t n, uint32_t k0, uint32_t k1, uint32_t k2,
                                              uint32_t k3, uint32_t k4, uint32_t k5, uint32_t k6,
                                              uint32_t k7)
{
    const uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    const size_t nn = static_cast<size_t>(n) * n;
    if (idx >= nn) return;
    const uint32_t key[8] = {k0, k1, k2, k3, k4, k5, k6, k7};
    const uint32_t i = idx / n;
    const uint32_t j = idx % n;
    Bhat[idx] = DeviceExtractDequant(B32[idx], i, j, key);
}

// F_q = 2^61-1 helpers (device twin of matmul::int8_field).
__device__ __forceinline__ uint64_t DeviceFqReduce(unsigned __int128 x)
{
    constexpr uint64_t q = (uint64_t{1} << 61) - 1;
    const uint64_t lo = static_cast<uint64_t>(x & q);
    const uint64_t hi = static_cast<uint64_t>(x >> 61);
    uint64_t s = lo + hi;
    s = (s & q) + (s >> 61);
    if (s >= q) s -= q;
    return s;
}

__device__ __forceinline__ uint64_t DeviceFqFromInt64(int64_t x)
{
    constexpr uint64_t q = (uint64_t{1} << 61) - 1;
    if (x >= 0) return DeviceFqReduce(static_cast<unsigned __int128>(static_cast<uint64_t>(x)));
    const uint64_t magnitude = static_cast<uint64_t>(-(x + 1)) + 1;
    const uint64_t r = DeviceFqReduce(static_cast<unsigned __int128>(magnitude));
    return r == 0 ? 0 : (q - r);
}

static_assert(uint64_t{288} * 288 * 29'127 * 29'127 * 29'127 < (uint64_t{1} << 63),
              "BMX4C deferred combine must fit signed int64 at the construction limit");

// Chat[a,c] = sum_k P[a,k]*Q[k,c] (mod q). BMX4C pins
// |P|,|Q| <= 288*n, hence at the largest public n=8192 the entire signed dot
// product is bounded by 288^2*n^3 < 2^56. Accumulate exactly in int64 and do
// one field reduction per output, matching the CPU deferred-combine oracle.
// The previous kernel performed a 128-bit Mersenne reduction on every MAC.
// Shared K tiles also remove the 16-way redundant P/Q global loads in a block.
__global__ void DeviceCombineModQ(const int32_t* __restrict__ P,
                                  const int32_t* __restrict__ Q,
                                  uint64_t* __restrict__ Chat,
                                  int n, int m)
{
    constexpr int kOutputTile = 16;
    constexpr int kReductionTile = 32;
    __shared__ int32_t p_tile[kOutputTile][kReductionTile];
    __shared__ int32_t q_tile[kReductionTile][kOutputTile];

    const int tx = threadIdx.x;
    const int ty = threadIdx.y;
    const int c0 = static_cast<int>(blockIdx.x) * kOutputTile;
    const int a0 = static_cast<int>(blockIdx.y) * kOutputTile;
    const int c = c0 + tx;
    const int a = a0 + ty;
    const int tid = ty * kOutputTile + tx;
    int64_t acc = 0;

    for (int k0 = 0; k0 < n; k0 += kReductionTile) {
        for (int linear = tid; linear < kOutputTile * kReductionTile;
             linear += kOutputTile * kOutputTile) {
            const int row = linear / kReductionTile;
            const int kk = linear % kReductionTile;
            const int ga = a0 + row;
            const int gk = k0 + kk;
            p_tile[row][kk] = (ga < m && gk < n)
                ? P[static_cast<size_t>(ga) * n + gk]
                : 0;
        }
        for (int linear = tid; linear < kReductionTile * kOutputTile;
             linear += kOutputTile * kOutputTile) {
            const int kk = linear / kOutputTile;
            const int col = linear % kOutputTile;
            const int gk = k0 + kk;
            const int gc = c0 + col;
            q_tile[kk][col] = (gk < n && gc < m)
                ? Q[static_cast<size_t>(gk) * m + gc]
                : 0;
        }
        __syncthreads();
        if (a < m && c < m) {
#pragma unroll
            for (int kk = 0; kk < kReductionTile; ++kk) {
                acc += static_cast<int64_t>(p_tile[ty][kk]) *
                       static_cast<int64_t>(q_tile[kk][tx]);
            }
        }
        __syncthreads();
    }
    if (a < m && c < m) Chat[static_cast<size_t>(a) * m + c] = DeviceFqFromInt64(acc);
}

// ---------------------------------------------------------------------------
// Persistent cross-call device pool + CUDA graphs for stable GEMM stages.
// ---------------------------------------------------------------------------

struct LtCudaResidentPool {
    std::mutex mu;
    int device{-1};
    cudaStream_t stream{nullptr};

    uint32_t n{0};
    uint32_t m{0};
    uint32_t w{0};
    uint256 template_hash{};
    bool template_bound{false};
    bool graphs_ready{false};
    bool imma_s8s8{false};

    // Template-resident
    int8_t* dG{nullptr};
    int8_t* dH{nullptr};
    int8_t* dU{nullptr};
    int8_t* dV{nullptr};
    int8_t* dAhat{nullptr};
    int32_t* dP{nullptr};

    // Per-nonce working set (reused across calls)
    int8_t* dW{nullptr};
    int32_t* dY{nullptr};
    int32_t* dB32{nullptr};
    int8_t* dBhat{nullptr};
    int32_t* dQ{nullptr};
    uint64_t* dChat{nullptr};

    // Generic LaunchGemm scratch (cross-call reuse; minimizes alloc churn)
    int8_t* dGemmS8L{nullptr};
    int8_t* dGemmS8R{nullptr};
    int32_t* dGemmS32L{nullptr};
    int32_t* dGemmOut{nullptr};
    size_t gemm_s8l_bytes{0};
    size_t gemm_s8r_bytes{0};
    size_t gemm_s32l_bytes{0};
    size_t gemm_out_bytes{0};

    cudaGraph_t matexpand_graph{nullptr};
    cudaGraphExec_t matexpand_exec{nullptr};
    cudaGraph_t project_right_graph{nullptr};
    cudaGraphExec_t project_right_exec{nullptr};

    ~LtCudaResidentPool() { Release(); }

    void ReleaseGraphs()
    {
        if (matexpand_exec) { cudaGraphExecDestroy(matexpand_exec); matexpand_exec = nullptr; }
        if (matexpand_graph) { cudaGraphDestroy(matexpand_graph); matexpand_graph = nullptr; }
        if (project_right_exec) { cudaGraphExecDestroy(project_right_exec); project_right_exec = nullptr; }
        if (project_right_graph) { cudaGraphDestroy(project_right_graph); project_right_graph = nullptr; }
        graphs_ready = false;
    }

    void Release()
    {
        ReleaseGraphs();
        auto free_p = [](auto*& p) {
            if (p) { cudaFree(p); p = nullptr; }
        };
        free_p(dG); free_p(dH); free_p(dU); free_p(dV); free_p(dAhat); free_p(dP);
        free_p(dW); free_p(dY); free_p(dB32); free_p(dBhat); free_p(dQ); free_p(dChat);
        free_p(dGemmS8L); free_p(dGemmS8R); free_p(dGemmS32L); free_p(dGemmOut);
        gemm_s8l_bytes = gemm_s8r_bytes = gemm_s32l_bytes = gemm_out_bytes = 0;
        if (stream) { cudaStreamDestroy(stream); stream = nullptr; }
        template_bound = false;
        imma_s8s8 = false;
        n = m = w = 0;
        device = -1;
    }

    [[nodiscard]] bool EnsureScratch(size_t s8l, size_t s8r, size_t s32l, size_t out)
    {
        auto grow = [](auto*& p, size_t& have, size_t need) -> bool {
            if (need <= have) return true;
            if (p) { cudaFree(p); p = nullptr; have = 0; }
            if (need == 0) return true;
            if (cudaMalloc(reinterpret_cast<void**>(&p), need) != cudaSuccess) return false;
            have = need;
            return true;
        };
        return grow(dGemmS8L, gemm_s8l_bytes, s8l) &&
               grow(dGemmS8R, gemm_s8r_bytes, s8r) &&
               grow(dGemmS32L, gemm_s32l_bytes, s32l) &&
               grow(dGemmOut, gemm_out_bytes, out);
    }

    [[nodiscard]] bool EnsureDims(uint32_t n_in, uint32_t m_in)
    {
        const uint32_t w_in = matmul::v4::lt::kMatExpandPanelW;
        if (stream != nullptr && n == n_in && m == m_in && w == w_in) {
            return true;
        }
        Release();

        const btx::cuda::CudaRuntimeProbe runtime = btx::cuda::ProbeCudaRuntime();
        if (runtime.device_index >= 0) {
            if (cudaSetDevice(runtime.device_index) != cudaSuccess) return false;
            device = runtime.device_index;
        } else {
            if (cudaGetDevice(&device) != cudaSuccess) return false;
        }
        if (cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking) != cudaSuccess) return false;

        n = n_in;
        m = m_in;
        w = w_in;
        const size_t nn = static_cast<size_t>(n) * n;
        const size_t nw = static_cast<size_t>(n) * w;
        const size_t wn = static_cast<size_t>(w) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t nm = static_cast<size_t>(n) * m;
        const size_t mm = static_cast<size_t>(m) * m;

        auto mall = [](void** p, size_t bytes) {
            return bytes == 0 || cudaMalloc(p, bytes) == cudaSuccess;
        };
        if (!mall(reinterpret_cast<void**>(&dG), nn) ||
            !mall(reinterpret_cast<void**>(&dH), wn) ||
            !mall(reinterpret_cast<void**>(&dU), mn) ||
            !mall(reinterpret_cast<void**>(&dV), nm) ||
            !mall(reinterpret_cast<void**>(&dAhat), nn) ||
            !mall(reinterpret_cast<void**>(&dP), mn * sizeof(int32_t)) ||
            !mall(reinterpret_cast<void**>(&dW), nw) ||
            !mall(reinterpret_cast<void**>(&dY), nw * sizeof(int32_t)) ||
            !mall(reinterpret_cast<void**>(&dB32), nn * sizeof(int32_t)) ||
            !mall(reinterpret_cast<void**>(&dBhat), nn) ||
            !mall(reinterpret_cast<void**>(&dQ), nm * sizeof(int32_t)) ||
            !mall(reinterpret_cast<void**>(&dChat), mm * sizeof(uint64_t))) {
            Release();
            return false;
        }
        return true;
    }

    [[nodiscard]] bool CaptureGraphsScalar()
    {
        ReleaseGraphs();
        const dim3 block(16, 16, 1);
        {
            const dim3 grid_y((w + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            const dim3 grid_b((n + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            if (cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal) != cudaSuccess) return false;
            DeviceGemmS8S8Tiled<<<grid_y, block, 0, stream>>>(dG, dW, dY, (int)n, (int)w, (int)n);
            DeviceGemmS32S8Tiled<<<grid_b, block, 0, stream>>>(dY, dH, dB32, (int)n, (int)n, (int)w);
            if (cudaStreamEndCapture(stream, &matexpand_graph) != cudaSuccess) { matexpand_graph = nullptr; return false; }
            if (cudaGraphInstantiate(&matexpand_exec, matexpand_graph, nullptr, nullptr, 0) != cudaSuccess) { ReleaseGraphs(); return false; }
        }
        {
            const dim3 grid_q((m + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            if (cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal) != cudaSuccess) { ReleaseGraphs(); return false; }
            DeviceGemmS8S8Tiled<<<grid_q, block, 0, stream>>>(dBhat, dV, dQ, (int)n, (int)m, (int)n);
            if (cudaStreamEndCapture(stream, &project_right_graph) != cudaSuccess) { project_right_graph = nullptr; ReleaseGraphs(); return false; }
            if (cudaGraphInstantiate(&project_right_exec, project_right_graph, nullptr, nullptr, 0) != cudaSuccess) { ReleaseGraphs(); return false; }
        }
        graphs_ready = true;
        return true;
    }

    [[nodiscard]] bool LaunchMatExpandImma()
    {
        if (!TryLaunchLtImmaGemmS8S8Device(dG, dW, dY, n, w, n, stream)) return false;
        const dim3 block(16, 16, 1);
        const dim3 grid_b((n + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
        DeviceGemmS32S8Tiled<<<grid_b, block, 0, stream>>>(dY, dH, dB32, (int)n, (int)n, (int)w);
        return cudaGetLastError() == cudaSuccess;
    }

    [[nodiscard]] bool LaunchProjectRightImma()
    {
        return TryLaunchLtImmaGemmS8S8Device(dBhat, dV, dQ, n, m, n, stream);
    }

    [[nodiscard]] bool LaunchProjectLeftImma()
    {
        return TryLaunchLtImmaGemmS8S8Device(dU, dAhat, dP, m, n, n, stream);
    }

    [[nodiscard]] bool BindTemplate(const CBlockHeader& tmpl, uint32_t n_in, uint32_t m_in)
    {
        if (!EnsureDims(n_in, m_in)) return false;
        const uint256 th = matmul::v4::ComputeTemplateHash(tmpl);
        const bool want_imma = IsLtImmaGemmAvailable();
        if (template_bound && template_hash == th && imma_s8s8 == want_imma && (imma_s8s8 || graphs_ready)) return true;

        namespace bx = matmul::v4::bmx4;
        const uint256 seed_g = DeriveTaggedSeed(kMatExpandGTag, sizeof(kMatExpandGTag) - 1, th);
        const uint256 seed_h = DeriveTaggedSeed(kMatExpandHTag, sizeof(kMatExpandHTag) - 1, th);
        const uint256 seed_wa = DeriveTaggedSeed(kMatExpandWATag, sizeof(kMatExpandWATag) - 1, th);
        const auto [seed_u, seed_v] = matmul::v4::lt::DeriveProjectorSeedsBMX4CLT(tmpl);

        const std::vector<int8_t> G = bx::ExpandProjectorBMX4C(seed_g, n, n);
        const std::vector<int8_t> H = bx::ExpandProjectorBMX4C(seed_h, w, n);
        const std::vector<int8_t> W_a = bx::ExpandProjectorBMX4C(seed_wa, n, w);
        const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
        const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);

        const size_t nn = static_cast<size_t>(n) * n;
        const size_t nw = static_cast<size_t>(n) * w;
        const size_t wn = static_cast<size_t>(w) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t nm = static_cast<size_t>(n) * m;

        if (cudaMemcpyAsync(dG, G.data(), nn, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;
        if (cudaMemcpyAsync(dH, H.data(), wn, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;
        if (cudaMemcpyAsync(dW, W_a.data(), nw, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;
        if (cudaMemcpyAsync(dU, U.data(), mn, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;
        if (cudaMemcpyAsync(dV, V.data(), nm, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;

        imma_s8s8 = want_imma;
        if (imma_s8s8) {
            ReleaseGraphs();
            if (!LaunchMatExpandImma()) {
                imma_s8s8 = false;
                if (!CaptureGraphsScalar()) return false;
                if (cudaGraphLaunch(matexpand_exec, stream) != cudaSuccess) return false;
            }
        } else {
            if (!CaptureGraphsScalar()) return false;
            if (cudaGraphLaunch(matexpand_exec, stream) != cudaSuccess) return false;
        }

        const uint256 prf_a = matmul::v4::lt::DeriveMatExpandPrfKey(seed_wa);
        uint32_t kw[8];
        for (int t = 0; t < 8; ++t) kw[t] = ReadLE32(prf_a.data() + static_cast<size_t>(t) * 4);
        const int extract_threads = 256;
        const int extract_blocks = static_cast<int>((nn + extract_threads - 1) / extract_threads);
        DeviceExtractDequantMatExpand<<<extract_blocks, extract_threads, 0, stream>>>(
            dB32, dAhat, n, kw[0], kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7]);
        if (cudaGetLastError() != cudaSuccess) return false;

        if (imma_s8s8) {
            if (!LaunchProjectLeftImma()) {
                imma_s8s8 = false;
                const dim3 block(16, 16, 1);
                const dim3 grid_p((n + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
                DeviceGemmS8S8Tiled<<<grid_p, block, 0, stream>>>(dU, dAhat, dP, (int)m, (int)n, (int)n);
                if (cudaGetLastError() != cudaSuccess) return false;
                if (!graphs_ready && !CaptureGraphsScalar()) return false;
            }
        } else {
            const dim3 block(16, 16, 1);
            const dim3 grid_p((n + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
            DeviceGemmS8S8Tiled<<<grid_p, block, 0, stream>>>(dU, dAhat, dP, (int)m, (int)n, (int)n);
            if (cudaGetLastError() != cudaSuccess) return false;
        }
        if (cudaStreamSynchronize(stream) != cudaSuccess) return false;
        template_hash = th;
        template_bound = true;
        return true;
    }

    [[nodiscard]] bool MineOneNonce(const CBlockHeader& header,
                                    std::vector<matmul::int8_field::Fq>& chat_out)
    {
        if (!template_bound) return false;
        if (!imma_s8s8 && !graphs_ready) return false;
        if (matmul::v4::ComputeTemplateHash(header) != template_hash) return false;

        const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
        const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
        const std::vector<int8_t> W = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_w, n, w);
        const size_t nw = static_cast<size_t>(n) * w;
        if (cudaMemcpyAsync(dW, W.data(), nw, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;

        if (imma_s8s8) {
            if (!LaunchMatExpandImma()) return false;
        } else {
            if (cudaGraphLaunch(matexpand_exec, stream) != cudaSuccess) return false;
        }

        const uint256 prf = matmul::v4::lt::DeriveMatExpandPrfKey(seed_w);
        uint32_t kw[8];
        for (int t = 0; t < 8; ++t) kw[t] = ReadLE32(prf.data() + static_cast<size_t>(t) * 4);
        const size_t nn = static_cast<size_t>(n) * n;
        const int extract_threads = 256;
        const int extract_blocks = static_cast<int>((nn + extract_threads - 1) / extract_threads);
        DeviceExtractDequantMatExpand<<<extract_blocks, extract_threads, 0, stream>>>(
            dB32, dBhat, n, kw[0], kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7]);
        if (cudaGetLastError() != cudaSuccess) return false;

        if (imma_s8s8) {
            if (!LaunchProjectRightImma()) return false;
        } else {
            if (cudaGraphLaunch(project_right_exec, stream) != cudaSuccess) return false;
        }

        const dim3 block(16, 16, 1);
        const dim3 grid_c((m + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
        DeviceCombineModQ<<<grid_c, block, 0, stream>>>(dP, dQ, dChat, (int)n, (int)m);
        if (cudaGetLastError() != cudaSuccess) return false;

        chat_out.assign(static_cast<size_t>(m) * m, 0);
        if (cudaMemcpyAsync(chat_out.data(), dChat, static_cast<size_t>(m) * m * sizeof(uint64_t),
                            cudaMemcpyDeviceToHost, stream) != cudaSuccess) return false;
        return cudaStreamSynchronize(stream) == cudaSuccess;
    }
};

LtCudaResidentPool& Pool()
{
    static LtCudaResidentPool pool;
    return pool;
}

[[nodiscard]] bool CudaOkLaunchGemmS8S8(const std::vector<int8_t>& left,
                                        const std::vector<int8_t>& right,
                                        uint32_t rows, uint32_t k, uint32_t cols,
                                        std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int8_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);

    auto& pool = Pool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.EnsureScratch(lhs_bytes, rhs_bytes, 0, out_bytes)) return false;
    if (cudaMemcpy(pool.dGemmS8L, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        return false;
    }
    if (cudaMemcpy(pool.dGemmS8R, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        return false;
    }

    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    DeviceGemmS8S8Tiled<<<grid, block>>>(pool.dGemmS8L, pool.dGemmS8R, pool.dGemmOut,
                                         static_cast<int>(rows), static_cast<int>(cols),
                                         static_cast<int>(k));
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaDeviceSynchronize() != cudaSuccess) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    return cudaMemcpy(out.data(), pool.dGemmOut, out_bytes, cudaMemcpyDeviceToHost) == cudaSuccess;
}

[[nodiscard]] bool CudaOkLaunchGemmS32S8(const std::vector<int32_t>& left,
                                         const std::vector<int8_t>& right,
                                         uint32_t rows, uint32_t k, uint32_t cols,
                                         std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int32_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);

    auto& pool = Pool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.EnsureScratch(0, rhs_bytes, lhs_bytes, out_bytes)) return false;
    if (cudaMemcpy(pool.dGemmS32L, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        return false;
    }
    if (cudaMemcpy(pool.dGemmS8R, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        return false;
    }

    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    DeviceGemmS32S8Tiled<<<grid, block>>>(pool.dGemmS32L, pool.dGemmS8R, pool.dGemmOut,
                                          static_cast<int>(rows), static_cast<int>(cols),
                                          static_cast<int>(k));
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaDeviceSynchronize() != cudaSuccess) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    return cudaMemcpy(out.data(), pool.dGemmOut, out_bytes, cudaMemcpyDeviceToHost) == cudaSuccess;
}

thread_local bool g_lt_device_gemm_failed = false;
thread_local bool g_lt_last_s8s8_imma = false;

bool BackendGemmS8S8(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                     uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtImmaGemmS8S8(L, R, rows, inner, cols, out)) {
        g_lt_last_s8s8_imma = true;
        return true;
    }
    g_lt_last_s8s8_imma = false;
    if (CudaOkLaunchGemmS8S8(L, R, rows, inner, cols, out)) return true;
    g_lt_device_gemm_failed = true;
    return false;
}

bool BackendGemmS32S8(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                      uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtImmaGemmS32S8(L, R, rows, inner, cols, out)) return true;
    if (CudaOkLaunchGemmS32S8(L, R, rows, inner, cols, out)) return true;
    g_lt_device_gemm_failed = true;
    return false;
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
        bool s8_ok = false;
        if (IsLtImmaGemmAvailable()) {
            s8_ok = TryLaunchLtImmaGemmS8S8(left, right, kDim, kDim, kDim, gpu_s8s8) && gpu_s8s8 == cpu_s8s8;
        }
        if (!s8_ok) {
            if (!CudaOkLaunchGemmS8S8(left, right, kDim, kDim, kDim, gpu_s8s8) || gpu_s8s8 != cpu_s8s8) {
                return;
            }
        }

        const std::vector<int32_t> cpu_s32s8 = matmul::v4::lt::ExactGemmS32S8(mid, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu_s32s8;
        if (!CudaOkLaunchGemmS32S8(mid, right, kDim, kDim, kDim, gpu_s32s8) || gpu_s32s8 != cpu_s32s8) {
            return;
        }

        // Full-pipeline bit-identity: one device-resident digest vs CPU reference.
        constexpr uint32_t kN = 64;
        uint32_t m = 0;
        if (!matmul::v4::lt::ValidateDimsBMX4CLT(kN, m)) return;

        CBlockHeader header;
        header.nVersion = 0x20000004;
        header.nTime = 1'770'000'000;
        header.nBits = 0x207fffff;
        header.nNonce64 = 42;
        header.nNonce = 42;
        header.matmul_dim = static_cast<uint16_t>(kN);
        // Distinct non-zero seeds so DeriveSigma / projectors are well-defined.
        for (int i = 0; i < 32; ++i) {
            header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
            header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
            header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
            header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
        }

        uint256 cpu_digest;
        std::vector<unsigned char> cpu_payload;
        if (!matmul::v4::lt::ComputeDigestBMX4CLT(header, kN, cpu_digest, cpu_payload)) return;

        auto& pool = Pool();
        std::lock_guard<std::mutex> lock(pool.mu);
        if (!pool.BindTemplate(header, kN, m)) return;
        std::vector<matmul::int8_field::Fq> chat;
        if (!pool.MineOneNonce(header, chat)) return;
        const uint256 sigma = matmul::v4::DeriveSigma(header);
        const uint256 gpu_digest = matmul::v4::ComputeSketchDigestFromFq(sigma, chat);
        if (gpu_digest != cpu_digest) return;

        ok = true;
    });
    return ok;
}

[[nodiscard]] bool MineDeviceResident(const CBlockHeader& tmpl, uint32_t n, uint32_t m,
                                      const uint64_t* nonces, size_t count,
                                      std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    auto& pool = Pool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.BindTemplate(tmpl, n, m)) return false;

    out.resize(count);
    for (size_t i = 0; i < count; ++i) {
        CBlockHeader header = tmpl;
        header.nNonce64 = nonces[i];
        header.nNonce = static_cast<uint32_t>(nonces[i]);

        std::vector<matmul::int8_field::Fq> chat;
        if (!pool.MineOneNonce(header, chat)) {
            out.clear();
            return false;
        }
        const uint256 sigma = matmul::v4::DeriveSigma(header);
        out[i].nonce = nonces[i];
        out[i].digest = matmul::v4::ComputeSketchDigestFromFq(sigma, chat);
        out[i].target_match = false;
        out[i].backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
    }
    return true;
}

[[nodiscard]] bool MineHostExactFallback(const CBlockHeader& tmpl, uint32_t n,
                                         const uint64_t* nonces, size_t count,
                                         bool try_device_gemms,
                                         std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    matmul::v4::lt::ExactGemmBackend backend;
    if (try_device_gemms) {
        backend.gemm_s8s8 = &BackendGemmS8S8;
        backend.gemm_s32s8 = &BackendGemmS32S8;
    }
    g_lt_device_gemm_failed = false;

    matmul::v4::lt::WindowSketchMinerLT miner(tmpl, n, backend);
    if (!miner.Valid()) return false;

    const std::vector<uint64_t> nonce_vec(nonces, nonces + count);
    const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
    std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
    if (!miner.Mine(nonce_vec, kNoTarget, results, nullptr)) return false;

    const bool device_served =
        try_device_gemms && miner.UsingDeviceGemms() && !g_lt_device_gemm_failed;
    const auto status = device_served
                            ? matmul::v4::bmx4::DigestOnlyBackendStatus::Ok
                            : matmul::v4::bmx4::DigestOnlyBackendStatus::Fallback;
    for (auto& r : results) {
        r.target_match = false;
        r.backend_status = status;
    }
    out = std::move(results);
    return true;
}

} // namespace

bool LaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                    uint32_t rows, uint32_t k, uint32_t cols,
                    std::vector<int32_t>& out)
{
    if (TryLaunchLtImmaGemmS8S8(left, right, rows, k, cols, out)) {
        g_lt_last_s8s8_imma = true;
        return true;
    }
    g_lt_last_s8s8_imma = false;
    return CudaOkLaunchGemmS8S8(left, right, rows, k, cols, out);
}

bool LaunchGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                     uint32_t rows, uint32_t k, uint32_t cols,
                     std::vector<int32_t>& out)
{
    if (TryLaunchLtImmaGemmS32S8(left, right, rows, k, cols, out)) {
        return true;
    }
    return CudaOkLaunchGemmS32S8(left, right, rows, k, cols, out);
}

bool IsMatMulLTCudaAvailable()
{
    const btx::cuda::CudaRuntimeProbe probe = btx::cuda::ProbeCudaRuntime();
    if (!probe.compiled || !probe.available) {
        return false;
    }
    return SelfTestGemmKernelsOnce();
}

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

    // Prefer the persistent device-resident MatExpand→project→combine loop
    // (CUDA-graph replay of stable GEMMs). Host ExactGemm / WindowSketchMinerLT
    // is fail-closed fallback only — not the complete accelerator.
    if (IsMatMulLTCudaAvailable()) {
        if (MineDeviceResident(tmpl, n, m, nonces, count, out)) {
            return true;
        }
        // Device-resident path declined at runtime: fall back to host ExactGemm
        // (optionally still using per-call device GEMMs via ExactGemmBackend).
        return MineHostExactFallback(tmpl, n, nonces, count, /*try_device_gemms=*/true, out);
    }

    return MineHostExactFallback(tmpl, n, nonces, count, /*try_device_gemms=*/false, out);
}

bool LtLastS8S8UsedImma()
{
    return g_lt_last_s8s8_imma;
}

} // namespace matmul_v4::cuda
