// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_exact_replay_cuda.h>

#include <crypto/common.h>
#include <cuda/cuda_context.h>
#include <cuda/matmul_v4_lt_device_mx.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/matmul_v4_rc.h>

#include <cuda_runtime.h>
#include <cub/cub.cuh>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace matmul_v4::cuda {
namespace {

using matmul::v4::rc::kRCMxBlockLen;
using matmul::v4::rc::kRCWgradExactChunk;

std::mutex g_stats_mu;
RcExactReplayCudaStats g_stats;

// All RC CUDA entry points bind the exact device selected by the common CUDA
// runtime probe. The process-wide LT/IMMA allocation pool is not device-keyed,
// so changing the selected device after the first RC bind is rejected rather
// than allowing a foreign-device pointer or handle to enter ExactReplay.
std::mutex g_rc_device_mu;
int g_rc_bound_device{-1};

[[nodiscard]] bool BindSelectedRcCudaDevice(int* selected = nullptr)
{
    const auto runtime{btx::cuda::ProbeCudaRuntime()};
    if (!runtime.compiled || !runtime.available || runtime.device_index < 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_rc_device_mu);
    if (g_rc_bound_device == -1) {
        g_rc_bound_device = runtime.device_index;
    } else if (g_rc_bound_device != runtime.device_index) {
        return false;
    }
    if (cudaSetDevice(g_rc_bound_device) != cudaSuccess) return false;
    if (selected != nullptr) *selected = g_rc_bound_device;
    return true;
}

void NoteGemm()
{
    std::lock_guard<std::mutex> lock(g_stats_mu);
    ++g_stats.device_gemm_calls;
}

void NoteExtract(uint64_t tiles)
{
    std::lock_guard<std::mutex> lock(g_stats_mu);
    g_stats.device_extract_tiles += tiles;
}

void NoteCpuFallback()
{
    std::lock_guard<std::mutex> lock(g_stats_mu);
    ++g_stats.cpu_gemm_fallbacks;
}

void PackPrfKey8(const uint256& key, uint32_t out[8])
{
    for (int i = 0; i < 8; ++i) {
        out[i] = ReadLE32(key.data() + static_cast<size_t>(i) * 4);
    }
}

[[nodiscard]] bool CudaOk(cudaError_t e) { return e == cudaSuccess; }

[[nodiscard]] size_t CudaFreeBytes()
{
    size_t free_b = 0, total_b = 0;
    if (cudaMemGetInfo(&free_b, &total_b) != cudaSuccess) return 0;
    return free_b;
}

__device__ __forceinline__ uint32_t ErRotl32(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__ void ErChaChaQuarter(uint32_t& a, uint32_t& b, uint32_t& c,
                                                 uint32_t& d)
{
    a += b;
    d = ErRotl32(d ^ a, 16);
    c += d;
    b = ErRotl32(b ^ c, 12);
    a += b;
    d = ErRotl32(d ^ a, 8);
    c += d;
    b = ErRotl32(b ^ c, 7);
}

__device__ __forceinline__ void ErMatExpandMxTileKeystream(const uint32_t key[8], uint32_t i,
                                                            uint32_t bj, uint32_t remix,
                                                            uint8_t out64[64])
{
    constexpr uint32_t kLaneMxBl = 0x4D58424Cu;
    uint32_t x0 = 0x61707865u, x1 = 0x3320646eu, x2 = 0x79622d32u, x3 = 0x6b206574u;
    uint32_t x4 = key[0], x5 = key[1], x6 = key[2], x7 = key[3];
    uint32_t x8 = key[4], x9 = key[5], x10 = key[6], x11 = key[7];
    uint32_t x12 = remix;
    uint32_t x13 = bj ^ kLaneMxBl;
    const uint64_t nonce_second = (static_cast<uint64_t>(i) << 32) | static_cast<uint64_t>(bj);
    uint32_t x14 = static_cast<uint32_t>(nonce_second);
    uint32_t x15 = static_cast<uint32_t>(nonce_second >> 32);
    const uint32_t j4 = x4, j5 = x5, j6 = x6, j7 = x7;
    const uint32_t j8 = x8, j9 = x9, j10 = x10, j11 = x11;
    const uint32_t j12 = x12, j13 = x13, j14 = x14, j15 = x15;
#pragma unroll
    for (int r = 0; r < 10; ++r) {
        ErChaChaQuarter(x0, x4, x8, x12);
        ErChaChaQuarter(x1, x5, x9, x13);
        ErChaChaQuarter(x2, x6, x10, x14);
        ErChaChaQuarter(x3, x7, x11, x15);
        ErChaChaQuarter(x0, x5, x10, x15);
        ErChaChaQuarter(x1, x6, x11, x12);
        ErChaChaQuarter(x2, x7, x8, x13);
        ErChaChaQuarter(x3, x4, x9, x14);
    }
    x0 += 0x61707865u;
    x1 += 0x3320646eu;
    x2 += 0x79622d32u;
    x3 += 0x6b206574u;
    x4 += j4;
    x5 += j5;
    x6 += j6;
    x7 += j7;
    x8 += j8;
    x9 += j9;
    x10 += j10;
    x11 += j11;
    x12 += j12;
    x13 += j13;
    x14 += j14;
    x15 += j15;
    const uint32_t words[16] = {x0, x1, x2,  x3,  x4,  x5,  x6,  x7,
                                x8, x9, x10, x11, x12, x13, x14, x15};
#pragma unroll
    for (int w = 0; w < 16; ++w) {
        out64[w * 4 + 0] = static_cast<uint8_t>(words[w] & 0xff);
        out64[w * 4 + 1] = static_cast<uint8_t>((words[w] >> 8) & 0xff);
        out64[w * 4 + 2] = static_cast<uint8_t>((words[w] >> 16) & 0xff);
        out64[w * 4 + 3] = static_cast<uint8_t>((words[w] >> 24) & 0xff);
    }
}

__device__ __forceinline__ uint32_t ErExtractMixBitsFromInt64(int64_t y)
{
    constexpr int64_t kI32Min = -2147483647LL - 1;
    constexpr int64_t kI32Max = 2147483647LL;
    if (y >= kI32Min && y <= kI32Max) {
        return static_cast<uint32_t>(static_cast<int32_t>(y));
    }
    const uint64_t u = static_cast<uint64_t>(y);
    return static_cast<uint32_t>(u) ^ static_cast<uint32_t>(u >> 32);
}

__device__ __forceinline__ int8_t ErSampleMantissaNibble(uint8_t nibble, bool& accepted)
{
    const uint8_t nib = nibble & 0x0F;
    const uint8_t sign = (nib >> 3) & 1;
    const uint8_t exp = (nib >> 1) & 3;
    const uint8_t man = nib & 1;
    int mag = 0;
    bool integer = true;
    switch (exp) {
    case 0:
        mag = 0;
        integer = (man == 0);
        break;
    case 1:
        mag = 1;
        integer = (man == 0);
        break;
    case 2:
        mag = (man == 0) ? 2 : 3;
        break;
    case 3:
        mag = (man == 0) ? 4 : 6;
        break;
    default:
        break;
    }
    if (!integer || (sign && mag == 0)) {
        accepted = false;
        return 0;
    }
    accepted = true;
    return static_cast<int8_t>(sign ? -mag : mag);
}

template <typename RawT>
__device__ __forceinline__ void ErExtractOneTile(const RawT* raw64_or_32, int8_t* dst,
                                                 const uint32_t key[8], uint32_t i, uint32_t bj)
{
    constexpr uint32_t kBlk = 32;
    int8_t mu[kBlk];
    uint32_t remix = 0;
    uint32_t filled = 0;
    while (filled < kBlk) {
        uint8_t ks[64];
        ErMatExpandMxTileKeystream(key, i, bj, remix, ks);
        for (int b = 0; b < 64 && filled < kBlk; ++b) {
            const uint8_t byte = ks[b];
            for (int shift = 0; shift < 8 && filled < kBlk; shift += 4) {
                const uint8_t nibble = static_cast<uint8_t>((byte >> shift) & 0x0F);
                const int64_t y = static_cast<int64_t>(raw64_or_32[filled]);
                const uint32_t raw_u = ErExtractMixBitsFromInt64(y);
                const uint8_t mixed = static_cast<uint8_t>(
                    (nibble ^ static_cast<uint8_t>((raw_u * 0x9E3779B9u) >> 28)) & 0x0F);
                bool accepted = false;
                const int8_t m = ErSampleMantissaNibble(mixed, accepted);
                if (accepted) mu[filled++] = m;
            }
        }
        ++remix;
    }
    const uint8_t e = matmul_v4::lt_device::DeriveMatExpandMxScale(key, i, bj);
    const int32_t scale = int32_t{1} << e;
    for (uint32_t t = 0; t < kBlk; ++t) {
        dst[t] = static_cast<int8_t>(static_cast<int32_t>(mu[t]) * scale);
    }
}

/** One thread per (row i, local block). bj_abs = bj_base + local_bj.
 *  PRF row is absolute: row_base + i (required for b_seq paneling). */
__global__ void er_extract_mx_matrix_i64(const int64_t* __restrict__ raw,
                                         int8_t* __restrict__ out,
                                         const uint32_t* __restrict__ prf_key8,
                                         uint32_t rows, uint32_t cols, uint32_t bj_base,
                                         uint32_t row_base)
{
    constexpr uint32_t kBlk = 32;
    const uint32_t n_blk = cols / kBlk;
    const uint32_t tile = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t n_tiles = rows * n_blk;
    if (tile >= n_tiles) return;
    const uint32_t i = tile / n_blk;
    const uint32_t local_bj = tile % n_blk;
    const uint32_t bj = bj_base + local_bj;
    const uint32_t key[8] = {prf_key8[0], prf_key8[1], prf_key8[2], prf_key8[3],
                             prf_key8[4], prf_key8[5], prf_key8[6], prf_key8[7]};
    const size_t base = static_cast<size_t>(i) * cols + static_cast<size_t>(local_bj) * kBlk;
    ErExtractOneTile(raw + base, out + base, key, row_base + i, bj);
}

/** Extract directly from int32 GEMM output (RC magnitudes fit int32). */
__global__ void er_extract_mx_matrix_i32(const int32_t* __restrict__ raw,
                                         int8_t* __restrict__ out,
                                         const uint32_t* __restrict__ prf_key8,
                                         uint32_t rows, uint32_t cols, uint32_t bj_base,
                                         uint32_t row_base)
{
    constexpr uint32_t kBlk = 32;
    const uint32_t n_blk = cols / kBlk;
    const uint32_t tile = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t n_tiles = rows * n_blk;
    if (tile >= n_tiles) return;
    const uint32_t i = tile / n_blk;
    const uint32_t local_bj = tile % n_blk;
    const uint32_t bj = bj_base + local_bj;
    const uint32_t key[8] = {prf_key8[0], prf_key8[1], prf_key8[2], prf_key8[3],
                             prf_key8[4], prf_key8[5], prf_key8[6], prf_key8[7]};
    const size_t base = static_cast<size_t>(i) * cols + static_cast<size_t>(local_bj) * kBlk;
    ErExtractOneTile(raw + base, out + base, key, row_base + i, bj);
}

__global__ void er_i32_to_i64(const int32_t* __restrict__ in, int64_t* __restrict__ out,
                              size_t n)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx < n) out[idx] = static_cast<int64_t>(in[idx]);
}

__global__ void er_i64_add_i32(int64_t* __restrict__ acc, const int32_t* __restrict__ add,
                               size_t n)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx < n) acc[idx] += static_cast<int64_t>(add[idx]);
}

/** y64[i] = gemm32[i] + residual_s8[i] (FFN down + X residual). */
__global__ void er_i32_plus_s8_to_i64(const int32_t* __restrict__ gemm,
                                      const int8_t* __restrict__ residual,
                                      int64_t* __restrict__ out, size_t n)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx < n) {
        out[idx] = static_cast<int64_t>(gemm[idx]) + static_cast<int64_t>(residual[idx]);
    }
}

/** acc64[i] += residual_s8[i]. */
__global__ void er_i64_add_s8(int64_t* __restrict__ acc, const int8_t* __restrict__ add,
                              size_t n)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx < n) acc[idx] += static_cast<int64_t>(add[idx]);
}

__global__ void er_pack_k_panel(const int8_t* __restrict__ K, int8_t* __restrict__ K_T,
                                uint32_t t0, uint32_t chunk, uint32_t /*n_ctx*/,
                                uint32_t d_head)
{
    const uint32_t d = blockIdx.y * blockDim.y + threadIdx.y;
    const uint32_t t = blockIdx.x * blockDim.x + threadIdx.x;
    if (d >= d_head || t >= chunk) return;
    K_T[static_cast<size_t>(d) * chunk + t] =
        K[static_cast<size_t>(t0 + t) * d_head + d];
}

/** Device K-panel pack for ExactGemm: Ap[m×len] from A[m×k] cols [k0,k0+len). */
__global__ void er_pack_a_panel(const int8_t* __restrict__ A, int8_t* __restrict__ Ap,
                                uint32_t m, uint32_t k, uint32_t k0, uint32_t len)
{
    const uint32_t col = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= m || col >= len) return;
    Ap[static_cast<size_t>(row) * len + col] =
        A[static_cast<size_t>(row) * k + (k0 + col)];
}

/** Bp[len×n] from B[k×n] rows [k0,k0+len). */
__global__ void er_pack_b_panel(const int8_t* __restrict__ B, int8_t* __restrict__ Bp,
                                uint32_t k, uint32_t n, uint32_t k0, uint32_t len)
{
    const uint32_t col = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= len || col >= n) return;
    Bp[static_cast<size_t>(row) * n + col] =
        B[static_cast<size_t>(k0 + row) * n + col];
    (void)k;
}

// Byte-exact s8×s8→s32 when cuBLASLt offers no IMMA algorithm for the shape.
// Ada (sm_89) self-qual attention is M=32 N=64 K=32: heuristics return only
// SIMT, GetOrCreateShapePlan rejects it, and IMMA-only DeviceGemmS8S8 used to
// return false → Phase1 0 → null episode digest → miner declines the GPU.
// Integer, order-independent; all RC products fit int32 (same contract as IMMA).
__global__ void er_gemm_s8s8_i32(const int8_t* __restrict__ A,
                                 const int8_t* __restrict__ B,
                                 int32_t* __restrict__ C,
                                 uint32_t M, uint32_t N, uint32_t K)
{
    const uint32_t col = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= M || col >= N) return;
    int32_t acc = 0;
    const size_t arow = static_cast<size_t>(row) * K;
    for (uint32_t k = 0; k < K; ++k) {
        acc += static_cast<int32_t>(A[arow + k]) *
               static_cast<int32_t>(B[static_cast<size_t>(k) * N + col]);
    }
    C[static_cast<size_t>(row) * N + col] = acc;
}

struct DeviceBuf {
    void* p{nullptr};
    size_t bytes{0};
    ~DeviceBuf()
    {
        if (p) cudaFree(p);
    }
    [[nodiscard]] bool Alloc(size_t n)
    {
        if (n == 0) {
            if (p) {
                cudaFree(p);
                p = nullptr;
                bytes = 0;
            }
            return true;
        }
        if (n <= bytes && p != nullptr) return true;
        if (p) {
            cudaFree(p);
            p = nullptr;
            bytes = 0;
        }
        if (cudaMalloc(&p, n) != cudaSuccess) {
            p = nullptr;
            return false;
        }
        bytes = n;
        return true;
    }
    template <typename T>
    T* As()
    {
        return static_cast<T*>(p);
    }
};

struct RcExpandSeed32 {
    uint8_t bytes[32];
};

__device__ __forceinline__ void RcExpandXofBlock(
    const RcExpandSeed32& seed, uint8_t domain, uint64_t counter,
    uint8_t out[32])
{
    uint32_t state[8];
    uint32_t block[16]{};
    matmul_v4::lt_device::ShaInit(state);
#pragma unroll
    for (uint32_t i = 0; i < 32; ++i) {
        matmul_v4::lt_device::ShaSetByte(block, i, seed.bytes[i]);
    }
    matmul_v4::lt_device::ShaSetByte(block, 32, domain);
#pragma unroll
    for (uint32_t i = 0; i < 8; ++i) {
        matmul_v4::lt_device::ShaSetByte(
            block, 33 + i,
            static_cast<uint8_t>(counter >> (8 * i)));
    }
    matmul_v4::lt_device::ShaSetByte(block, 41, 0x80u);
    block[15] = 41u * 8u;
    matmul_v4::lt_device::ShaCompress(state, block);
#pragma unroll
    for (uint32_t word = 0; word < 8; ++word) {
        out[word * 4 + 0] = static_cast<uint8_t>(state[word] >> 24);
        out[word * 4 + 1] = static_cast<uint8_t>(state[word] >> 16);
        out[word * 4 + 2] = static_cast<uint8_t>(state[word] >> 8);
        out[word * 4 + 3] = static_cast<uint8_t>(state[word]);
    }
}

__device__ __forceinline__ int8_t RcExpandMantissa(
    uint8_t nibble, bool& accepted)
{
    const uint8_t sign{static_cast<uint8_t>((nibble >> 3) & 1)};
    const uint8_t exponent{static_cast<uint8_t>((nibble >> 1) & 3)};
    const uint8_t mantissa{static_cast<uint8_t>(nibble & 1)};
    int magnitude{0};
    bool integer{true};
    switch (exponent) {
    case 0: magnitude = 0; integer = mantissa == 0; break;
    case 1: magnitude = 1; integer = mantissa == 0; break;
    case 2: magnitude = mantissa == 0 ? 2 : 3; break;
    case 3: magnitude = mantissa == 0 ? 4 : 6; break;
    }
    if (!integer || (sign != 0 && magnitude == 0)) {
        accepted = false;
        return 0;
    }
    accepted = true;
    return static_cast<int8_t>(sign != 0 ? -magnitude : magnitude);
}

__global__ void RcExpandGenerateMantissaBlocks(
    RcExpandSeed32 seed, uint64_t counter_begin, uint32_t blocks,
    uint8_t* hashes, uint32_t* accepted)
{
    const uint32_t block{blockIdx.x * blockDim.x + threadIdx.x};
    if (block >= blocks) return;
    uint8_t digest[32];
    RcExpandXofBlock(seed, 0x6du, counter_begin + block, digest);
    uint32_t count{0};
#pragma unroll
    for (uint32_t i = 0; i < 32; ++i) {
        hashes[static_cast<size_t>(block) * 32 + i] = digest[i];
        bool ok{false};
        (void)RcExpandMantissa(digest[i] & 0x0fu, ok);
        count += ok ? 1u : 0u;
        (void)RcExpandMantissa(digest[i] >> 4, ok);
        count += ok ? 1u : 0u;
    }
    accepted[block] = count;
}

__global__ void RcExpandScatterMantissas(
    const uint8_t* hashes, const uint32_t* offsets, uint32_t blocks,
    size_t wanted, int8_t* output)
{
    const uint32_t block{blockIdx.x * blockDim.x + threadIdx.x};
    if (block >= blocks) return;
    size_t position{offsets[block]};
#pragma unroll
    for (uint32_t i = 0; i < 32; ++i) {
        const uint8_t byte{hashes[static_cast<size_t>(block) * 32 + i]};
        bool ok{false};
        int8_t value{RcExpandMantissa(byte & 0x0fu, ok)};
        if (ok) {
            if (position < wanted) output[position] = value;
            ++position;
        }
        value = RcExpandMantissa(byte >> 4, ok);
        if (ok) {
            if (position < wanted) output[position] = value;
            ++position;
        }
    }
}

__global__ void RcExpandGenerateScales(
    RcExpandSeed32 seed, uint8_t* scales, size_t count)
{
    const size_t block{static_cast<size_t>(blockIdx.x) * blockDim.x +
                       threadIdx.x};
    const size_t blocks{(count + 127) / 128};
    if (block >= blocks) return;
    uint8_t digest[32];
    RcExpandXofBlock(seed, 0x65u, block, digest);
#pragma unroll
    for (uint32_t i = 0; i < 32; ++i) {
#pragma unroll
        for (uint32_t part = 0; part < 4; ++part) {
            const size_t position{block * 128 + i * 4 + part};
            if (position < count) {
                scales[position] =
                    static_cast<uint8_t>((digest[i] >> (2 * part)) & 3u);
            }
        }
    }
}

__global__ void RcExpandDequantize(
    const int8_t* mantissas, const uint8_t* scales, int8_t* output,
    size_t count, uint32_t columns, uint32_t column_blocks)
{
    const size_t index{static_cast<size_t>(blockIdx.x) * blockDim.x +
                       threadIdx.x};
    if (index >= count) return;
    const uint32_t row{static_cast<uint32_t>(index / columns)};
    const uint32_t column{static_cast<uint32_t>(index % columns)};
    const uint32_t block{column / kRCMxBlockLen};
    const int32_t scale{int32_t{1} <<
        scales[static_cast<size_t>(row) * column_blocks + block]};
    output[index] = static_cast<int8_t>(
        static_cast<int32_t>(mantissas[index]) * scale);
}

struct RcExpandContext {
    std::mutex mutex;
    int device_index{-1};
    void* hashes{nullptr};
    size_t hashes_capacity{0};
    void* accepted{nullptr};
    size_t accepted_capacity{0};
    void* offsets{nullptr};
    size_t offsets_capacity{0};
    void* mantissas{nullptr};
    size_t mantissas_capacity{0};
    void* scales{nullptr};
    size_t scales_capacity{0};
    void* output{nullptr};
    size_t output_capacity{0};
    void* scan_temp{nullptr};
    size_t scan_temp_capacity{0};

    [[nodiscard]] bool EnsureDevice(int selected_device)
    {
        if (device_index == selected_device) return true;
        if (device_index != -1) {
            if (cudaSetDevice(device_index) != cudaSuccess) return false;
            void** pointers[]{&hashes, &accepted, &offsets, &mantissas,
                              &scales, &output, &scan_temp};
            size_t* capacities[]{&hashes_capacity, &accepted_capacity,
                                 &offsets_capacity, &mantissas_capacity,
                                 &scales_capacity, &output_capacity,
                                 &scan_temp_capacity};
            for (size_t i = 0; i < std::size(pointers); ++i) {
                if (*pointers[i] != nullptr &&
                    cudaFree(*pointers[i]) != cudaSuccess) {
                    return false;
                }
                *pointers[i] = nullptr;
                *capacities[i] = 0;
            }
        }
        if (cudaSetDevice(selected_device) != cudaSuccess) return false;
        device_index = selected_device;
        return true;
    }

    static bool Grow(void*& pointer, size_t& capacity, size_t required)
    {
        if (capacity >= required) return true;
        if (pointer != nullptr && cudaFree(pointer) != cudaSuccess) return false;
        pointer = nullptr;
        capacity = 0;
        if (required != 0 && cudaMalloc(&pointer, required) != cudaSuccess) {
            pointer = nullptr;
            return false;
        }
        capacity = required;
        return true;
    }
};

RcExpandContext& ExpandContext()
{
    static RcExpandContext context;
    return context;
}

bool RcExpandMxGenerateDevice(const uint256& seed, uint32_t rows,
                              uint32_t columns, int8_t* device_output,
                              cudaStream_t stream,
                              uint32_t max_blocks_override = 0)
{
    if (rows == 0 || columns == 0 || device_output == nullptr ||
        rows % kRCMxBlockLen != 0 || columns % kRCMxBlockLen != 0) {
        return false;
    }
    if (static_cast<size_t>(rows) >
        std::numeric_limits<size_t>::max() / columns) {
        return false;
    }
    const size_t count{static_cast<size_t>(rows) * columns};
    const uint32_t column_blocks{columns / kRCMxBlockLen};
    const size_t scale_count{static_cast<size_t>(rows) * column_blocks};
    auto& context{ExpandContext()};
    int selected_device{-1};
    if (!BindSelectedRcCudaDevice(&selected_device) ||
        !context.EnsureDevice(selected_device)) {
        return false;
    }
    if (!RcExpandContext::Grow(
            context.mantissas, context.mantissas_capacity, count) ||
        !RcExpandContext::Grow(
            context.scales, context.scales_capacity, scale_count)) {
        return false;
    }

    RcExpandSeed32 device_seed{};
    for (uint32_t i = 0; i < 32; ++i) {
        device_seed.bytes[i] = seed.data()[31 - i];
    }
    constexpr uint32_t threads{256};
    size_t filled{0};
    uint64_t counter{0};
    while (filled < count) {
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        const size_t remaining{count - filled};
        const size_t proposed{remaining / 40 + 1024};
        // Each SHA block accepts at most 64 nibbles. Keep every uint32 prefix
        // exact, even for diagnostic shapes larger than the production tuple;
        // additional batches continue at the next canonical counter.
        constexpr uint32_t max_blocks_per_batch{
            std::numeric_limits<uint32_t>::max() / 64u};
        size_t admitted_blocks{
            std::min<size_t>(proposed, max_blocks_per_batch)};
        if (max_blocks_override != 0) {
            admitted_blocks = std::min<size_t>(
                admitted_blocks, max_blocks_override);
        }
        const uint32_t blocks{
            static_cast<uint32_t>(admitted_blocks)};
        if (blocks == 0 ||
            counter > std::numeric_limits<uint64_t>::max() - blocks) {
            return false;
        }
        if (!RcExpandContext::Grow(
                context.hashes, context.hashes_capacity,
                static_cast<size_t>(blocks) * 32) ||
            !RcExpandContext::Grow(
                context.accepted, context.accepted_capacity,
                static_cast<size_t>(blocks) * sizeof(uint32_t)) ||
            !RcExpandContext::Grow(
                context.offsets, context.offsets_capacity,
                static_cast<size_t>(blocks) * sizeof(uint32_t))) {
            return false;
        }
        RcExpandGenerateMantissaBlocks<<<
            (blocks + threads - 1) / threads, threads, 0, stream>>>(
                device_seed, counter, blocks,
                static_cast<uint8_t*>(context.hashes),
                static_cast<uint32_t*>(context.accepted));
        if (cudaGetLastError() != cudaSuccess) return false;
        size_t scan_bytes{0};
        if (cub::DeviceScan::ExclusiveSum(
                nullptr, scan_bytes,
                static_cast<const uint32_t*>(context.accepted),
                static_cast<uint32_t*>(context.offsets),
                static_cast<int>(blocks), stream) != cudaSuccess) {
            return false;
        }
        if (static_cast<uint64_t>(blocks) >
                std::numeric_limits<uint64_t>::max() /
                    matmul::v4::rc::kRCSeededExpandScanTempBytesPerBlock ||
            static_cast<uint64_t>(blocks) *
                    matmul::v4::rc::kRCSeededExpandScanTempBytesPerBlock >
                std::numeric_limits<uint64_t>::max() -
                    matmul::v4::rc::kRCSeededExpandScanTempBaseBytes ||
            scan_bytes > matmul::v4::rc::kRCSeededExpandScanTempBaseBytes +
                static_cast<uint64_t>(blocks) *
                    matmul::v4::rc::kRCSeededExpandScanTempBytesPerBlock ||
            !RcExpandContext::Grow(
                context.scan_temp, context.scan_temp_capacity,
                scan_bytes) ||
            cub::DeviceScan::ExclusiveSum(
                context.scan_temp, scan_bytes,
                static_cast<const uint32_t*>(context.accepted),
                static_cast<uint32_t*>(context.offsets),
                static_cast<int>(blocks), stream) != cudaSuccess) {
            return false;
        }
        uint32_t last_offset{0};
        uint32_t last_accepted{0};
        if (cudaMemcpyAsync(
                &last_offset,
                static_cast<const uint32_t*>(context.offsets) + blocks - 1,
                sizeof(last_offset), cudaMemcpyDeviceToHost, stream) !=
                cudaSuccess ||
            cudaMemcpyAsync(
                &last_accepted,
                static_cast<const uint32_t*>(context.accepted) + blocks - 1,
                sizeof(last_accepted), cudaMemcpyDeviceToHost, stream) !=
                cudaSuccess ||
            cudaStreamSynchronize(stream) != cudaSuccess) {
            return false;
        }
        const size_t available{
            static_cast<size_t>(last_offset) + last_accepted};
        if (available == 0) {
            counter += blocks;
            continue;
        }
        RcExpandScatterMantissas<<<
            (blocks + threads - 1) / threads, threads, 0, stream>>>(
                static_cast<const uint8_t*>(context.hashes),
                static_cast<const uint32_t*>(context.offsets), blocks,
                remaining,
                static_cast<int8_t*>(context.mantissas) + filled);
        if (cudaGetLastError() != cudaSuccess ||
            cudaStreamSynchronize(stream) != cudaSuccess) {
            return false;
        }
        filled += std::min(remaining, available);
        counter += blocks;
    }
    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    const size_t scale_blocks{(scale_count + 127) / 128};
    RcExpandGenerateScales<<<
        static_cast<unsigned>((scale_blocks + threads - 1) / threads),
        threads, 0, stream>>>(
            device_seed, static_cast<uint8_t*>(context.scales),
            scale_count);
    if (cudaGetLastError() != cudaSuccess) return false;
    RcExpandDequantize<<<
        static_cast<unsigned>((count + threads - 1) / threads),
        threads, 0, stream>>>(
            static_cast<const int8_t*>(context.mantissas),
            static_cast<const uint8_t*>(context.scales), device_output,
            count, columns, column_blocks);
    return cudaGetLastError() == cudaSuccess &&
        cudaStreamSynchronize(stream) == cudaSuccess;
}

[[nodiscard]] bool LaunchExtractI64(const int64_t* d_raw, int8_t* d_out, const uint32_t* d_key,
                                    uint32_t rows, uint32_t cols, uint32_t bj_base,
                                    uint32_t row_base = 0)
{
    const uint32_t n_tiles = rows * (cols / kRCMxBlockLen);
    if (n_tiles == 0) return true;
    const uint32_t threads = 256;
    const uint32_t blocks = (n_tiles + threads - 1) / threads;
    er_extract_mx_matrix_i64<<<blocks, threads>>>(d_raw, d_out, d_key, rows, cols, bj_base,
                                                  row_base);
    if (cudaGetLastError() != cudaSuccess) return false;
    NoteExtract(n_tiles);
    return true;
}

[[nodiscard]] bool LaunchExtractI32(const int32_t* d_raw, int8_t* d_out, const uint32_t* d_key,
                                    uint32_t rows, uint32_t cols, uint32_t bj_base,
                                    uint32_t row_base = 0)
{
    const uint32_t n_tiles = rows * (cols / kRCMxBlockLen);
    if (n_tiles == 0) return true;
    const uint32_t threads = 256;
    const uint32_t blocks = (n_tiles + threads - 1) / threads;
    er_extract_mx_matrix_i32<<<blocks, threads>>>(d_raw, d_out, d_key, rows, cols, bj_base,
                                                  row_base);
    if (cudaGetLastError() != cudaSuccess) return false;
    NoteExtract(n_tiles);
    return true;
}

[[nodiscard]] bool DeviceGemmS8S8(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                  uint32_t rows, uint32_t cols, uint32_t inner,
                                  cudaStream_t stream = nullptr)
{
    if (TryLaunchLtImmaGemmS8S8Device(dA, dB, dC, rows, cols, inner, stream)) {
        NoteGemm();
        return true;
    }
    if (rows == 0 || cols == 0) {
        NoteGemm();
        return true;
    }
    const dim3 block(16, 16, 1);
    const dim3 grid((cols + 15u) / 16u, (rows + 15u) / 16u, 1);
    er_gemm_s8s8_i32<<<grid, block, 0, stream>>>(dA, dB, dC, rows, cols, inner);
    if (cudaGetLastError() != cudaSuccess) return false;
    NoteGemm();
    return true;
}

[[nodiscard]] bool LaunchExtractI64Stream(const int64_t* d_raw, int8_t* d_out,
                                          const uint32_t* d_key, uint32_t rows, uint32_t cols,
                                          uint32_t bj_base, cudaStream_t stream,
                                          uint32_t row_base = 0)
{
    const uint32_t n_tiles = rows * (cols / kRCMxBlockLen);
    if (n_tiles == 0) return true;
    const uint32_t threads = 256;
    const uint32_t blocks = (n_tiles + threads - 1) / threads;
    er_extract_mx_matrix_i64<<<blocks, threads, 0, stream>>>(d_raw, d_out, d_key, rows, cols,
                                                            bj_base, row_base);
    if (cudaGetLastError() != cudaSuccess) return false;
    NoteExtract(n_tiles);
    return true;
}

[[nodiscard]] bool LaunchExtractI32Stream(const int32_t* d_raw, int8_t* d_out,
                                          const uint32_t* d_key, uint32_t rows, uint32_t cols,
                                          uint32_t bj_base, cudaStream_t stream,
                                          uint32_t row_base = 0)
{
    const uint32_t n_tiles = rows * (cols / kRCMxBlockLen);
    if (n_tiles == 0) return true;
    const uint32_t threads = 256;
    const uint32_t blocks = (n_tiles + threads - 1) / threads;
    er_extract_mx_matrix_i32<<<blocks, threads, 0, stream>>>(d_raw, d_out, d_key, rows, cols,
                                                            bj_base, row_base);
    if (cudaGetLastError() != cudaSuccess) return false;
    NoteExtract(n_tiles);
    return true;
}

[[nodiscard]] bool LaunchI32PlusS8ToI64Stream(const int32_t* gemm, const int8_t* residual,
                                              int64_t* out, size_t n, cudaStream_t stream)
{
    if (n == 0) return true;
    const uint32_t thr = 256;
    const uint32_t blk = static_cast<uint32_t>((n + thr - 1) / thr);
    er_i32_plus_s8_to_i64<<<blk, thr, 0, stream>>>(gemm, residual, out, n);
    return cudaGetLastError() == cudaSuccess;
}

[[nodiscard]] bool LaunchI64AddS8Stream(int64_t* acc, const int8_t* add, size_t n,
                                        cudaStream_t stream)
{
    if (n == 0) return true;
    const uint32_t thr = 256;
    const uint32_t blk = static_cast<uint32_t>((n + thr - 1) / thr);
    er_i64_add_s8<<<blk, thr, 0, stream>>>(acc, add, n);
    return cudaGetLastError() == cudaSuccess;
}

[[nodiscard]] bool DeviceExactGemmInt64Resident(const int8_t* dA, const int8_t* dB,
                                                uint32_t m, uint32_t k, uint32_t n,
                                                int64_t* d_out, DeviceBuf& d_partial,
                                                DeviceBuf& dAp, DeviceBuf& dBp,
                                                cudaStream_t stream = nullptr);

/** Choose FFN row panel so int32 H + H_s8 + Y32 + Y64 fit in free VRAM. */
[[nodiscard]] uint32_t ChooseFfnPanelRows(uint32_t b_seq, uint32_t d_model, uint32_t d_ff)
{
    // Per-row working set for the int32-preferred path.
    const size_t per_row =
        static_cast<size_t>(d_ff) * sizeof(int32_t) + static_cast<size_t>(d_ff) +
        static_cast<size_t>(d_model) * sizeof(int32_t) +
        static_cast<size_t>(d_model) * sizeof(int64_t);
    const size_t free_b = CudaFreeBytes();
    // Keep ~1.5 GiB headroom for X ping-pong / weights already resident.
    constexpr size_t kHeadroom = 1536ull << 20;
    const size_t budget = free_b > kHeadroom ? free_b - kHeadroom : free_b / 2;
    uint32_t rows = per_row > 0 ? static_cast<uint32_t>(budget / per_row) : b_seq;
    rows = std::min(rows, b_seq);
    // Cap at production profile-1 b_seq (known-good on 16 GiB); floor at 32 (MX).
    rows = std::min(rows, 16384u);
    if (rows < 32) rows = 32;
    rows -= rows % 32;
    if (rows == 0) rows = 32;
    return std::min(rows, b_seq);
}

/** One FFN layer on already-resident device buffers. d_in → d_out (may alias ping-pong).
 *  Row-panels when full b_seq intermediates will not fit (profile-2 datacenter). */
[[nodiscard]] bool DeviceFfnLayerResident(const int8_t* d_in, int8_t* d_out, const int8_t* dWup,
                                          const int8_t* dWdn, const uint32_t* d_keyUp,
                                          const uint32_t* d_keyDn, uint32_t b_seq,
                                          uint32_t d_model, uint32_t d_ff, DeviceBuf& d_h32,
                                          DeviceBuf& dH, DeviceBuf& d_y32, DeviceBuf& d_y64,
                                          DeviceBuf& d_partial, DeviceBuf& dAp, DeviceBuf& dBp,
                                          DeviceBuf& d_h64, cudaStream_t stream)
{
    const uint32_t panel = ChooseFfnPanelRows(b_seq, d_model, d_ff);
    if (!d_h32.Alloc(static_cast<size_t>(panel) * d_ff * sizeof(int32_t))) return false;
    if (!dH.Alloc(static_cast<size_t>(panel) * d_ff)) return false;
    if (!d_y32.Alloc(static_cast<size_t>(panel) * d_model * sizeof(int32_t))) return false;
    if (!d_y64.Alloc(static_cast<size_t>(panel) * d_model * sizeof(int64_t))) return false;

    for (uint32_t r0 = 0; r0 < b_seq; r0 += panel) {
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        const uint32_t rows = std::min(panel, b_seq - r0);
        const int8_t* in_row = d_in + static_cast<size_t>(r0) * d_model;
        int8_t* out_row = d_out + static_cast<size_t>(r0) * d_model;
        const size_t y_n = static_cast<size_t>(rows) * d_model;

        if (DeviceGemmS8S8(in_row, dWup, d_h32.As<int32_t>(), rows, d_ff, d_model, stream)) {
            if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
            if (!LaunchExtractI32Stream(d_h32.As<int32_t>(), dH.As<int8_t>(), d_keyUp, rows, d_ff,
                                        /*bj_base=*/0, stream, /*row_base=*/r0)) {
                return false;
            }
        } else {
            if (!d_h64.Alloc(static_cast<size_t>(rows) * d_ff * sizeof(int64_t))) return false;
            if (!DeviceExactGemmInt64Resident(in_row, dWup, rows, d_model, d_ff,
                                              d_h64.As<int64_t>(), d_partial, dAp, dBp,
                                              stream)) {
                return false;
            }
            if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
            if (!LaunchExtractI64Stream(d_h64.As<int64_t>(), dH.As<int8_t>(), d_keyUp, rows, d_ff,
                                        /*bj_base=*/0, stream, /*row_base=*/r0)) {
                return false;
            }
        }

        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        if (DeviceGemmS8S8(dH.As<int8_t>(), dWdn, d_y32.As<int32_t>(), rows, d_model, d_ff,
                           stream)) {
            if (!LaunchI32PlusS8ToI64Stream(d_y32.As<int32_t>(), in_row, d_y64.As<int64_t>(), y_n,
                                            stream)) {
                return false;
            }
        } else {
            if (!DeviceExactGemmInt64Resident(dH.As<int8_t>(), dWdn, rows, d_ff, d_model,
                                              d_y64.As<int64_t>(), d_partial, dAp, dBp,
                                              stream)) {
                return false;
            }
            if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
            if (!LaunchI64AddS8Stream(d_y64.As<int64_t>(), in_row, y_n, stream)) return false;
        }
        if (!LaunchExtractI64Stream(d_y64.As<int64_t>(), out_row, d_keyDn, rows, d_model,
                                    /*bj_base=*/0, stream, /*row_base=*/r0)) {
            return false;
        }
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_stats_mu);
        if (panel < b_seq) {
            g_stats.detail = "cuda_ffn_row_panels=" + std::to_string(panel);
        }
    }
    return true;
}

[[nodiscard]] bool LaunchI32ToI64(
    const int32_t* in, int64_t* out, size_t n,
    cudaStream_t stream = nullptr)
{
    if (n == 0) return true;
    const uint32_t thr = 256;
    const uint32_t blk = static_cast<uint32_t>((n + thr - 1) / thr);
    er_i32_to_i64<<<blk, thr, 0, stream>>>(in, out, n);
    return cudaGetLastError() == cudaSuccess;
}

[[nodiscard]] bool LaunchI64AddI32(
    int64_t* acc, const int32_t* add, size_t n,
    cudaStream_t stream = nullptr)
{
    if (n == 0) return true;
    const uint32_t thr = 256;
    const uint32_t blk = static_cast<uint32_t>((n + thr - 1) / thr);
    er_i64_add_i32<<<blk, thr, 0, stream>>>(acc, add, n);
    return cudaGetLastError() == cudaSuccess;
}

[[nodiscard]] bool LaunchI32PlusS8ToI64(const int32_t* gemm, const int8_t* residual,
                                        int64_t* out, size_t n)
{
    if (n == 0) return true;
    const uint32_t thr = 256;
    const uint32_t blk = static_cast<uint32_t>((n + thr - 1) / thr);
    er_i32_plus_s8_to_i64<<<blk, thr>>>(gemm, residual, out, n);
    return cudaGetLastError() == cudaSuccess;
}

[[nodiscard]] bool LaunchI64AddS8(int64_t* acc, const int8_t* add, size_t n)
{
    if (n == 0) return true;
    const uint32_t thr = 256;
    const uint32_t blk = static_cast<uint32_t>((n + thr - 1) / thr);
    er_i64_add_s8<<<blk, thr>>>(acc, add, n);
    return cudaGetLastError() == cudaSuccess;
}

/**
 * ExactGemm int64 on already-resident A/B. Prefers one full-K IMMA launch
 * (RC magnitudes fit int32); falls back to device-packed K panels.
 */
[[nodiscard]] bool DeviceExactGemmInt64Resident(const int8_t* dA, const int8_t* dB,
                                                uint32_t m, uint32_t k, uint32_t n,
                                                int64_t* d_out, DeviceBuf& d_partial,
                                                DeviceBuf& dAp, DeviceBuf& dBp,
                                                cudaStream_t stream)
{
    const size_t out_n = static_cast<size_t>(m) * n;
    if (!d_partial.Alloc(out_n * sizeof(int32_t))) return false;

    // Prefer Metal-shaped single launch over full K.
    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    if (DeviceGemmS8S8(
            dA, dB, d_partial.As<int32_t>(), m, n, k, stream)) {
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        return LaunchI32ToI64(
            d_partial.As<int32_t>(), d_out, out_n, stream);
    }

    // Panel fallback (still device-resident — no host re-pack).
    if (!CudaOk(cudaMemsetAsync(
            d_out, 0, out_n * sizeof(int64_t), stream))) return false;
    const dim3 tblock(16, 16);
    for (uint32_t k0 = 0; k0 < k; k0 += kRCWgradExactChunk) {
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        const uint32_t len = std::min(kRCWgradExactChunk, k - k0);
        if (!dAp.Alloc(static_cast<size_t>(m) * len) ||
            !dBp.Alloc(static_cast<size_t>(len) * n)) {
            return false;
        }
        dim3 agrid((len + tblock.x - 1) / tblock.x, (m + tblock.y - 1) / tblock.y);
        dim3 bgrid((n + tblock.x - 1) / tblock.x, (len + tblock.y - 1) / tblock.y);
        er_pack_a_panel<<<agrid, tblock, 0, stream>>>(
            dA, dAp.As<int8_t>(), m, k, k0, len);
        er_pack_b_panel<<<bgrid, tblock, 0, stream>>>(
            dB, dBp.As<int8_t>(), k, n, k0, len);
        if (cudaGetLastError() != cudaSuccess) return false;
        if (!DeviceGemmS8S8(
                dAp.As<int8_t>(), dBp.As<int8_t>(),
                d_partial.As<int32_t>(), m, n, len, stream)) {
            return false;
        }
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        if (!LaunchI64AddI32(
                d_out, d_partial.As<int32_t>(), out_n, stream)) return false;
    }
    return true;
}

[[nodiscard]] bool Phase1Chunked(const int8_t* dQ, const int8_t* dK, const int8_t* dV,
                                 const uint32_t* d_keyS, const uint32_t* d_keyZ, uint32_t n_q,
                                 uint32_t n_ctx, uint32_t d_head, uint32_t chunk, int8_t* dZ,
                                 DeviceBuf& d_scores_i32, DeviceBuf& dS, DeviceBuf& d_partial,
                                 DeviceBuf& d_acc, DeviceBuf& d_KT)
{
    if ((chunk % kRCMxBlockLen) != 0 || chunk == 0) return false;
    if (!d_scores_i32.Alloc(static_cast<size_t>(n_q) * chunk * sizeof(int32_t))) return false;
    if (!dS.Alloc(static_cast<size_t>(n_q) * chunk)) return false;
    if (!d_partial.Alloc(static_cast<size_t>(n_q) * d_head * sizeof(int32_t))) return false;
    if (!d_acc.Alloc(static_cast<size_t>(n_q) * d_head * sizeof(int64_t))) return false;
    if (!d_KT.Alloc(static_cast<size_t>(d_head) * chunk)) return false;
    if (!CudaOk(cudaMemset(d_acc.p, 0, static_cast<size_t>(n_q) * d_head * sizeof(int64_t)))) {
        return false;
    }

    const dim3 tblock(16, 16);
    const size_t z_n = static_cast<size_t>(n_q) * d_head;

    for (uint32_t t0 = 0; t0 < n_ctx; t0 += chunk) {
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        const uint32_t len = std::min(chunk, n_ctx - t0);
        if ((len % kRCMxBlockLen) != 0) return false;

        dim3 tgrid((len + tblock.x - 1) / tblock.x, (d_head + tblock.y - 1) / tblock.y);
        er_pack_k_panel<<<tgrid, tblock>>>(dK, d_KT.As<int8_t>(), t0, len, n_ctx, d_head);
        if (cudaGetLastError() != cudaSuccess) return false;

        if (!DeviceGemmS8S8(dQ, d_KT.As<int8_t>(), d_scores_i32.As<int32_t>(), n_q, len,
                            d_head)) {
            return false;
        }
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        const uint32_t bj0 = t0 / kRCMxBlockLen;
        if (!LaunchExtractI32(d_scores_i32.As<int32_t>(), dS.As<int8_t>(), d_keyS, n_q, len,
                              bj0)) {
            return false;
        }

        const int8_t* dV_panel = dV + static_cast<size_t>(t0) * d_head;
        if (!DeviceGemmS8S8(dS.As<int8_t>(), dV_panel, d_partial.As<int32_t>(), n_q, d_head,
                            len)) {
            return false;
        }
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        if (!LaunchI64AddI32(d_acc.As<int64_t>(), d_partial.As<int32_t>(), z_n)) return false;
    }

    return LaunchExtractI64(d_acc.As<int64_t>(), dZ, d_keyZ, n_q, d_head, /*bj_base=*/0);
}

[[nodiscard]] bool Phase1FullContext(const int8_t* dQ, const int8_t* dK, const int8_t* dV,
                                     const uint32_t* d_keyS, const uint32_t* d_keyZ, uint32_t n_q,
                                     uint32_t n_ctx, uint32_t d_head, int8_t* dZ,
                                     DeviceBuf& d_scores_i32, DeviceBuf& dS, DeviceBuf& d_sv,
                                     DeviceBuf& d_KT)
{
    const size_t scores_bytes = static_cast<size_t>(n_q) * n_ctx * sizeof(int32_t);
    const size_t s_bytes = static_cast<size_t>(n_q) * n_ctx;
    const size_t kt_bytes = static_cast<size_t>(d_head) * n_ctx;
    const size_t sv_bytes = static_cast<size_t>(n_q) * d_head * sizeof(int32_t);
    // Leave headroom for allocator fragmentation / concurrent driver use.
    const size_t need = scores_bytes + s_bytes + kt_bytes + sv_bytes + (64ull << 20);
    if (CudaFreeBytes() < need) return false;

    if (!d_scores_i32.Alloc(scores_bytes) || !dS.Alloc(s_bytes) || !d_KT.Alloc(kt_bytes) ||
        !d_sv.Alloc(sv_bytes)) {
        return false;
    }

    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    const dim3 tblock(16, 16);
    dim3 tgrid((n_ctx + tblock.x - 1) / tblock.x, (d_head + tblock.y - 1) / tblock.y);
    er_pack_k_panel<<<tgrid, tblock>>>(dK, d_KT.As<int8_t>(), /*t0=*/0, n_ctx, n_ctx, d_head);
    if (cudaGetLastError() != cudaSuccess) return false;

    if (!DeviceGemmS8S8(dQ, d_KT.As<int8_t>(), d_scores_i32.As<int32_t>(), n_q, n_ctx,
                        d_head)) {
        return false;
    }
    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    if (!LaunchExtractI32(d_scores_i32.As<int32_t>(), dS.As<int8_t>(), d_keyS, n_q, n_ctx,
                          /*bj_base=*/0)) {
        return false;
    }
    // Free score i32 early — S is enough for SV.
    (void)d_scores_i32.Alloc(0);

    if (!DeviceGemmS8S8(dS.As<int8_t>(), dV, d_sv.As<int32_t>(), n_q, d_head, n_ctx)) {
        return false;
    }
    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    // SV fits int32 at production dims; Extract from i32 (same as host widen).
    return LaunchExtractI32(d_sv.As<int32_t>(), dZ, d_keyZ, n_q, d_head, /*bj_base=*/0);
}

} // namespace

bool IsRcExactReplayCudaAvailable()
{
    int selected_device{-1};
    if (!BindSelectedRcCudaDevice(&selected_device) ||
        !IsLtImmaGemmAvailable()) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_stats_mu);
        g_stats.device_index = selected_device;
    }
    return true;
}

void ResetRcExactReplayCudaStats()
{
    std::lock_guard<std::mutex> lock(g_stats_mu);
    g_stats = {};
}

RcExactReplayCudaStats GetRcExactReplayCudaStats()
{
    std::lock_guard<std::mutex> lock(g_stats_mu);
    return g_stats;
}

bool TryCudaRcExtractMXMatrixInt64(const uint256& prf_key, const std::vector<int64_t>& Y,
                                   uint32_t rows, uint32_t cols, std::vector<int8_t>& out)
{
    if (!IsRcExactReplayCudaAvailable()) return false;
    if (rows == 0 || cols == 0 || (cols % kRCMxBlockLen) != 0) return false;
    if (Y.size() != static_cast<size_t>(rows) * cols) return false;

    DeviceBuf d_y, d_out, d_key;
    const size_t y_bytes = Y.size() * sizeof(int64_t);
    const size_t o_bytes = static_cast<size_t>(rows) * cols;
    if (!d_y.Alloc(y_bytes) || !d_out.Alloc(o_bytes) || !d_key.Alloc(8 * sizeof(uint32_t))) {
        return false;
    }
    uint32_t key8[8];
    PackPrfKey8(prf_key, key8);
    if (!CudaOk(cudaMemcpy(d_y.p, Y.data(), y_bytes, cudaMemcpyHostToDevice))) return false;
    if (!CudaOk(cudaMemcpy(d_key.p, key8, sizeof(key8), cudaMemcpyHostToDevice))) return false;
    if (!LaunchExtractI64(d_y.As<int64_t>(), d_out.As<int8_t>(), d_key.As<uint32_t>(), rows, cols,
                          /*bj_base=*/0)) {
        return false;
    }
    if (!CudaOk(cudaDeviceSynchronize())) return false;
    out.resize(o_bytes);
    if (!CudaOk(cudaMemcpy(out.data(), d_out.p, o_bytes, cudaMemcpyDeviceToHost))) return false;
    {
        std::lock_guard<std::mutex> lock(g_stats_mu);
        g_stats.phase2_extract_device = true;
    }
    return true;
}

bool TryCudaRcFusedExactGemmInt64(const std::vector<int8_t>& A, uint32_t m, uint32_t k,
                                  const std::vector<int8_t>& B, uint32_t n,
                                  std::vector<int64_t>& out)
{
    if (!IsRcExactReplayCudaAvailable()) return false;
    if (m == 0 || k == 0 || n == 0) return false;
    if (A.size() != static_cast<size_t>(m) * k) return false;
    if (B.size() != static_cast<size_t>(k) * n) return false;

    DeviceBuf dA, dB, d_partial, d_acc, dAp, dBp;
    if (!dA.Alloc(A.size()) || !dB.Alloc(B.size())) return false;
    if (!d_acc.Alloc(static_cast<size_t>(m) * n * sizeof(int64_t))) return false;
    if (!CudaOk(cudaMemcpy(dA.p, A.data(), A.size(), cudaMemcpyHostToDevice))) return false;
    if (!CudaOk(cudaMemcpy(dB.p, B.data(), B.size(), cudaMemcpyHostToDevice))) return false;

    if (!DeviceExactGemmInt64Resident(dA.As<int8_t>(), dB.As<int8_t>(), m, k, n,
                                      d_acc.As<int64_t>(), d_partial, dAp, dBp)) {
        NoteCpuFallback();
        return false;
    }
    if (!CudaOk(cudaDeviceSynchronize())) return false;
    out.resize(static_cast<size_t>(m) * n);
    if (!CudaOk(cudaMemcpy(out.data(), d_acc.p, out.size() * sizeof(int64_t),
                           cudaMemcpyDeviceToHost))) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_stats_mu);
        g_stats.phase2_gemm_device = true;
    }
    return true;
}

bool TryCudaRcFusedFfnLayer(const std::vector<int8_t>& X, const std::vector<int8_t>& W_up,
                            const std::vector<int8_t>& W_down, const uint256& prf_up,
                            const uint256& prf_dn, uint32_t b_seq, uint32_t d_model,
                            uint32_t d_ff, std::vector<int8_t>& out)
{
    if (!IsRcExactReplayCudaAvailable()) return false;
    if (b_seq == 0 || d_model == 0 || d_ff == 0) return false;
    if ((d_model % kRCMxBlockLen) != 0 || (d_ff % kRCMxBlockLen) != 0) return false;
    if (X.size() != static_cast<size_t>(b_seq) * d_model) return false;
    if (W_up.size() != static_cast<size_t>(d_model) * d_ff) return false;
    if (W_down.size() != static_cast<size_t>(d_ff) * d_model) return false;

    DeviceBuf dX, dWup, dWdn, d_h32, dH, d_y32, d_y64, dOut, d_keyUp, d_keyDn, d_partial, dAp,
        dBp, d_h64;
    if (!dX.Alloc(X.size()) || !dWup.Alloc(W_up.size()) || !dWdn.Alloc(W_down.size())) {
        return false;
    }
    if (!dOut.Alloc(static_cast<size_t>(b_seq) * d_model)) return false;
    if (!d_keyUp.Alloc(8 * sizeof(uint32_t)) || !d_keyDn.Alloc(8 * sizeof(uint32_t))) {
        return false;
    }

    uint32_t keyUp[8], keyDn[8];
    PackPrfKey8(prf_up, keyUp);
    PackPrfKey8(prf_dn, keyDn);
    if (!CudaOk(cudaMemcpy(dX.p, X.data(), X.size(), cudaMemcpyHostToDevice))) return false;
    if (!CudaOk(cudaMemcpy(dWup.p, W_up.data(), W_up.size(), cudaMemcpyHostToDevice))) {
        return false;
    }
    if (!CudaOk(cudaMemcpy(dWdn.p, W_down.data(), W_down.size(), cudaMemcpyHostToDevice))) {
        return false;
    }
    if (!CudaOk(cudaMemcpy(d_keyUp.p, keyUp, sizeof(keyUp), cudaMemcpyHostToDevice))) {
        return false;
    }
    if (!CudaOk(cudaMemcpy(d_keyDn.p, keyDn, sizeof(keyDn), cudaMemcpyHostToDevice))) {
        return false;
    }

    if (!DeviceFfnLayerResident(dX.As<int8_t>(), dOut.As<int8_t>(), dWup.As<int8_t>(),
                                dWdn.As<int8_t>(), d_keyUp.As<uint32_t>(), d_keyDn.As<uint32_t>(),
                                b_seq, d_model, d_ff, d_h32, dH, d_y32, d_y64, d_partial, dAp,
                                dBp, d_h64, nullptr)) {
        NoteCpuFallback();
        return false;
    }
    if (!CudaOk(cudaDeviceSynchronize())) return false;
    out.resize(static_cast<size_t>(b_seq) * d_model);
    if (!CudaOk(cudaMemcpy(out.data(), dOut.p, out.size(), cudaMemcpyDeviceToHost))) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_stats_mu);
        g_stats.phase2_gemm_device = true;
        g_stats.phase2_extract_device = true;
        g_stats.phase2_ffn_fused_device = true;
        if (g_stats.detail.empty()) {
            g_stats.detail = "cuda_fused_ffn_fullk_imma+device_extract";
        }
    }
    return true;
}

namespace {

/** Test-only state used by the <true> FFN-chain template instantiation below.
 * The production <false> instantiation compiles every probe branch away. */
__global__ void RcSlotReuseOrderingHoldGate(uint32_t* release,
                                            uint32_t* device_expired,
                                            uint64_t max_cycles)
{
    const uint64_t start{clock64()};
    while (atomicAdd(release, 0u) == 0u) {
        if (clock64() - start >= max_cycles) {
            atomicExch(device_expired, 1u);
            return;
        }
    }
}

__global__ void RcSlotReuseOrderingReleaseGate(uint32_t* release)
{
    atomicExch(release, 1u);
}

struct SlotReuseOrderingProbe {
    cudaStream_t gate_stream{nullptr};
    cudaStream_t release_stream{nullptr};
    cudaEvent_t gate_event{nullptr};
    cudaEvent_t pre_wait_event{nullptr};
    cudaEvent_t post_wait_event{nullptr};
    DeviceBuf release_flag;
    DeviceBuf device_watchdog_expired;
    int device_index{-1};
    std::atomic_bool slot_wait_enqueued{false};
    std::atomic_bool watchdog_expired{false};
    std::atomic_bool release_started{false};
    // Assume the seam is supported until a successful property query proves
    // that concurrent kernels are unavailable. Bind/query failures are real
    // initialization errors and must fail the test rather than masquerade as
    // an unsupported-device skip.
    bool interlock_supported{true};

    [[nodiscard]] bool Init()
    {
        cudaDeviceProp properties{};
        if (!BindSelectedRcCudaDevice(&device_index) ||
            cudaGetDeviceProperties(&properties, device_index) != cudaSuccess) {
            return false;
        }
        // The release kernel must be able to run while the single-thread gate
        // is resident. Older CUDA devices that cannot make concurrent-kernel
        // progress skip this test seam; production ExactReplay is unchanged.
        if (!properties.concurrentKernels) {
            interlock_supported = false;
            return false;
        }
        if (
            !release_flag.Alloc(sizeof(uint32_t)) ||
            !device_watchdog_expired.Alloc(sizeof(uint32_t)) ||
            cudaStreamCreateWithFlags(&release_stream, cudaStreamNonBlocking) !=
                cudaSuccess ||
            cudaStreamCreateWithFlags(&gate_stream, cudaStreamNonBlocking) !=
                cudaSuccess ||
            cudaEventCreateWithFlags(&gate_event, cudaEventDisableTiming) !=
                cudaSuccess ||
            cudaEventCreateWithFlags(&pre_wait_event, cudaEventDisableTiming) !=
                cudaSuccess ||
            cudaEventCreateWithFlags(&post_wait_event, cudaEventDisableTiming) !=
                cudaSuccess ||
            cudaMemsetAsync(release_flag.p, 0, sizeof(uint32_t),
                            release_stream) != cudaSuccess ||
            cudaMemsetAsync(device_watchdog_expired.p, 0, sizeof(uint32_t),
                            release_stream) != cudaSuccess ||
            cudaStreamSynchronize(release_stream) != cudaSuccess) {
            return false;
        }
        // Fail open on-device in less than a typical display-GPU watchdog
        // interval. The host normally releases the gate after a 250 ms
        // observation window; this 750 ms ceiling is only the last-resort
        // cleanup path if the release stream cannot make progress.
        // cudaDeviceProp::clockRate was REMOVED in CUDA 13, so reading it off
        // the properties struct does not compile on a 13.x toolkit at all --
        // which is where this gate actually has to run. cudaDevAttrClockRate is
        // the supported query and is available on 12.x and 13.x alike.
        int clock_khz{0};
        if (cudaDeviceGetAttribute(&clock_khz, cudaDevAttrClockRate,
                                   device_index) != cudaSuccess) {
            return false;
        }
        const uint64_t max_cycles{
            static_cast<uint64_t>(std::max(clock_khz, 1)) * 750u};
        RcSlotReuseOrderingHoldGate<<<1, 1, 0, gate_stream>>>(
            release_flag.As<uint32_t>(),
            device_watchdog_expired.As<uint32_t>(), max_cycles);
        if (cudaGetLastError() != cudaSuccess ||
            cudaEventRecord(gate_event, gate_stream) != cudaSuccess) {
            return false;
        }
        return true;
    }

    void Release() noexcept
    {
        if (release_started.exchange(true, std::memory_order_acq_rel)) return;
        bool released{false};
        if (device_index < 0 || cudaSetDevice(device_index) != cudaSuccess ||
            release_stream == nullptr || release_flag.p == nullptr) {
            watchdog_expired.store(true, std::memory_order_release);
        } else {
            RcSlotReuseOrderingReleaseGate<<<1, 1, 0, release_stream>>>(
                release_flag.As<uint32_t>());
            released = cudaGetLastError() == cudaSuccess &&
                cudaStreamSynchronize(release_stream) == cudaSuccess;
            if (!released) {
                watchdog_expired.store(true, std::memory_order_release);
            }
        }
        if (!released) {
            // Permit the main thread or destructor to retry after a transient
            // launch/device-selection failure. The bounded device watchdog
            // still guarantees that teardown cannot spin indefinitely.
            release_started.store(false, std::memory_order_release);
        }
    }

    [[nodiscard]] bool PostWaitReached() const
    {
        return post_wait_event != nullptr &&
            cudaEventQuery(post_wait_event) == cudaSuccess;
    }

    [[nodiscard]] bool PreWaitReached() const
    {
        return pre_wait_event != nullptr &&
            cudaEventQuery(pre_wait_event) == cudaSuccess;
    }

    [[nodiscard]] bool DeviceWatchdogExpired() const
    {
        if (device_watchdog_expired.p == nullptr) return true;
        uint32_t expired{0};
        if (cudaMemcpy(&expired, device_watchdog_expired.p, sizeof(expired),
                       cudaMemcpyDeviceToHost) != cudaSuccess) {
            return true;
        }
        return expired != 0;
    }

    ~SlotReuseOrderingProbe()
    {
        Release();
        if (device_index >= 0) (void)cudaSetDevice(device_index);
        if (gate_stream) (void)cudaStreamSynchronize(gate_stream);
        if (post_wait_event) (void)cudaEventDestroy(post_wait_event);
        if (pre_wait_event) (void)cudaEventDestroy(pre_wait_event);
        if (gate_event) (void)cudaEventDestroy(gate_event);
        if (gate_stream) (void)cudaStreamDestroy(gate_stream);
        if (release_stream) (void)cudaStreamDestroy(release_stream);
    }
};

template <bool TestSlotReuseOrdering>
bool TryCudaRcFusedFfnChainImpl(const std::vector<int8_t>& X0, bool weights_shared,
                            const std::vector<int8_t>& W_up_shared,
                            const std::vector<int8_t>& W_down_shared,
                            const std::vector<std::vector<int8_t>>& W_up_layers,
                            const std::vector<std::vector<int8_t>>& W_down_layers,
                            const std::vector<uint256>& prf_up, const std::vector<uint256>& prf_dn,
                            uint32_t b_seq, uint32_t d_model, uint32_t d_ff, uint32_t L_lyr,
                            std::vector<std::vector<int8_t>>& out_X,
                            const std::vector<uint256>* up_seeds,
                            const std::vector<uint256>* down_seeds,
                            SlotReuseOrderingProbe* ordering_probe)
{
    if constexpr (TestSlotReuseOrdering) {
        if (ordering_probe == nullptr) return false;
    }
    if (!IsRcExactReplayCudaAvailable()) return false;
    if (L_lyr == 0 || b_seq == 0 || d_model == 0 || d_ff == 0) return false;
    if ((d_model % kRCMxBlockLen) != 0 || (d_ff % kRCMxBlockLen) != 0) return false;
    if (X0.size() != static_cast<size_t>(b_seq) * d_model) return false;
    if (prf_up.size() != L_lyr || prf_dn.size() != L_lyr) return false;
    if ((up_seeds == nullptr) != (down_seeds == nullptr)) return false;
    if (up_seeds != nullptr) {
        const size_t expected{weights_shared ? 1u : L_lyr};
        if (up_seeds->size() != expected ||
            down_seeds->size() != expected) return false;
    } else if (weights_shared) {
        if (W_up_shared.size() != static_cast<size_t>(d_model) * d_ff ||
            W_down_shared.size() != static_cast<size_t>(d_ff) * d_model) return false;
    } else if (W_up_layers.size() != L_lyr ||
               W_down_layers.size() != L_lyr) {
        return false;
    }

    const size_t x_bytes = static_cast<size_t>(b_seq) * d_model;
    const size_t wup_bytes = static_cast<size_t>(d_model) * d_ff;
    const size_t wdn_bytes = static_cast<size_t>(d_ff) * d_model;

    // Persistent workspace across rounds/verifies — avoid cudaMalloc storms.
    struct Workspace {
        DeviceBuf dXa, dXb, dWup0, dWup1, dWdn0, dWdn1, d_keyUp, d_keyDn, d_h32, dH, d_y32,
            d_y64, d_partial, dAp, dBp, d_h64;
        cudaStream_t compute{nullptr};
        cudaStream_t h2d{nullptr};
        cudaStream_t d2h{nullptr};
        cudaEvent_t w_ready{nullptr};
        // Per weight SLOT, not one sequence-wide event. The weight pair
        // ping-pongs between slot 0 and slot 1, so the pair generated for layer
        // l+1 lands in the slot layer l-1 read. Regeneration therefore has to be
        // ordered after that slot's previous compute consumer, and that consumer
        // is identified by slot, not by "the last layer".
        cudaEvent_t layer_done[2]{nullptr, nullptr};
        cudaEvent_t d2h_done[2]{nullptr, nullptr};
        size_t x_bytes{0};
        size_t wup_bytes{0};
        size_t wdn_bytes{0};
        int device_index{-1};

        void Reset()
        {
            for (auto& e : d2h_done) {
                if (e) cudaEventDestroy(e);
                e = nullptr;
            }
            for (auto& e : layer_done) {
                if (e) cudaEventDestroy(e);
                e = nullptr;
            }
            if (w_ready) cudaEventDestroy(w_ready);
            if (d2h) cudaStreamDestroy(d2h);
            if (h2d) cudaStreamDestroy(h2d);
            if (compute) cudaStreamDestroy(compute);
            w_ready = nullptr;
            d2h = nullptr;
            h2d = nullptr;
            compute = nullptr;
            DeviceBuf* buffers[]{
                &dXa, &dXb, &dWup0, &dWup1, &dWdn0, &dWdn1,
                &d_keyUp, &d_keyDn, &d_h32, &dH, &d_y32, &d_y64,
                &d_partial, &dAp, &dBp, &d_h64};
            for (DeviceBuf* buffer : buffers) (void)buffer->Alloc(0);
            x_bytes = 0;
            wup_bytes = 0;
            wdn_bytes = 0;
            device_index = -1;
        }
        ~Workspace()
        {
            if (device_index >= 0) (void)cudaSetDevice(device_index);
            Reset();
        }
        [[nodiscard]] bool Ensure(
            size_t xb, size_t wup, size_t wdn, int selected_device)
        {
            if (device_index != selected_device) {
                if (device_index >= 0) {
                    if (cudaSetDevice(device_index) != cudaSuccess) return false;
                    Reset();
                }
                if (cudaSetDevice(selected_device) != cudaSuccess) return false;
                device_index = selected_device;
            }
            DrainStreams();
            if (!compute &&
                cudaStreamCreateWithFlags(&compute, cudaStreamNonBlocking) != cudaSuccess) {
                return false;
            }
            if (!h2d &&
                cudaStreamCreateWithFlags(&h2d, cudaStreamNonBlocking) != cudaSuccess) {
                return false;
            }
            if (!d2h &&
                cudaStreamCreateWithFlags(&d2h, cudaStreamNonBlocking) != cudaSuccess) {
                return false;
            }
            if (!w_ready && cudaEventCreateWithFlags(&w_ready, cudaEventDisableTiming) !=
                                cudaSuccess) {
                return false;
            }
            for (auto& e : layer_done) {
                if (!e && cudaEventCreateWithFlags(&e, cudaEventDisableTiming) != cudaSuccess) {
                    return false;
                }
            }
            for (auto& e : d2h_done) {
                if (!e && cudaEventCreateWithFlags(&e, cudaEventDisableTiming) != cudaSuccess) {
                    return false;
                }
            }
            if (!dXa.Alloc(xb) || !dXb.Alloc(xb)) return false;
            if (!dWup0.Alloc(wup) || !dWdn0.Alloc(wdn)) return false;
            if (!dWup1.Alloc(wup) || !dWdn1.Alloc(wdn)) return false;
            if (!d_keyUp.Alloc(8 * sizeof(uint32_t)) || !d_keyDn.Alloc(8 * sizeof(uint32_t))) {
                return false;
            }
            x_bytes = xb;
            wup_bytes = wup;
            wdn_bytes = wdn;
            return true;
        }
        void DrainStreams()
        {
            if (h2d) (void)cudaStreamSynchronize(h2d);
            if (compute) (void)cudaStreamSynchronize(compute);
            if (d2h) (void)cudaStreamSynchronize(d2h);
        }
    };
    static std::mutex ws_mu;
    static Workspace ws;
    std::lock_guard<std::mutex> ws_lock(ws_mu);
    int selected_device{-1};
    if (!BindSelectedRcCudaDevice(&selected_device) ||
        !ws.Ensure(x_bytes, wup_bytes, wdn_bytes, selected_device)) {
        NoteCpuFallback();
        return false;
    }

    out_X.resize(L_lyr + 1);
    out_X[0] = X0;
    for (uint32_t l = 1; l <= L_lyr; ++l) {
        if (out_X[l].size() != x_bytes) out_X[l].assign(x_bytes, 0);
    }

    // Cancellation/failure must not release ws_mu (and then the outer
    // accelerator-scheduler lease) while nonblocking stream work is still in
    // flight. In particular, d2h may target out_X storage owned by this call.
    // Drain dependency order on every early return after the first enqueue.
    struct WorkspaceStreamDrain {
        Workspace& ws;
        bool armed{true};
        ~WorkspaceStreamDrain()
        {
            if (!armed) return;
            // Shutdown/cancel: do not join() behind an in-flight fused kernel.
            // Static workspace is drained by Ensure() before reuse.
            if (matmul::v4::rc::ExactReplayCancellationRequested()) return;
            if (ws.h2d) (void)cudaStreamSynchronize(ws.h2d);
            if (ws.compute) (void)cudaStreamSynchronize(ws.compute);
            if (ws.d2h) (void)cudaStreamSynchronize(ws.d2h);
        }
        void Disarm() { armed = false; }
    } stream_drain{ws};

    auto select_w = [&](uint32_t l, const std::vector<int8_t>*& up, const std::vector<int8_t>*& dn) {
        if (weights_shared) {
            up = &W_up_shared;
            dn = &W_down_shared;
        } else {
            up = &W_up_layers[l];
            dn = &W_down_layers[l];
        }
    };

    const auto load_weight_pair = [&](DeviceBuf& device_up,
                                      DeviceBuf& device_down,
                                      uint32_t layer) -> bool {
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        if (up_seeds != nullptr) {
            auto& expand{ExpandContext()};
            std::lock_guard<std::mutex> lock(expand.mutex);
            const size_t index{weights_shared ? 0u : layer};
            return RcExpandMxGenerateDevice(
                       (*up_seeds)[index], d_model, d_ff,
                       device_up.As<int8_t>(), ws.h2d) &&
                RcExpandMxGenerateDevice(
                       (*down_seeds)[index], d_ff, d_model,
                       device_down.As<int8_t>(), ws.h2d);
        }
        const std::vector<int8_t>* up = nullptr;
        const std::vector<int8_t>* dn = nullptr;
        select_w(layer, up, dn);
        return CudaOk(cudaMemcpyAsync(
                   device_up.p, up->data(), wup_bytes,
                   cudaMemcpyHostToDevice, ws.h2d)) &&
            CudaOk(cudaMemcpyAsync(
                   device_down.p, dn->data(), wdn_bytes,
                   cudaMemcpyHostToDevice, ws.h2d));
    };

    if (!CudaOk(cudaMemcpyAsync(ws.dXa.p, X0.data(), x_bytes, cudaMemcpyHostToDevice, ws.h2d))) {
        return false;
    }
    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    if (!load_weight_pair(ws.dWup0, ws.dWdn0, 0)) return false;
    if (!CudaOk(cudaEventRecord(ws.w_ready, ws.h2d))) return false;
    if (!CudaOk(cudaStreamWaitEvent(ws.compute, ws.w_ready, 0))) return false;

    int8_t* d_cur = ws.dXa.As<int8_t>();
    int8_t* d_nxt = ws.dXb.As<int8_t>();
    DeviceBuf* dWup_cur = &ws.dWup0;
    DeviceBuf* dWdn_cur = &ws.dWdn0;
    DeviceBuf* dWup_nxt = &ws.dWup1;
    DeviceBuf* dWdn_nxt = &ws.dWdn1;

    for (uint32_t l = 0; l < L_lyr; ++l) {
        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        const uint32_t slot = l % 2;
        // Ping-pong X: d_nxt was D2H source two layers ago — wait before overwrite.
        if (l >= 2) {
            if (!CudaOk(cudaStreamWaitEvent(ws.compute, ws.d2h_done[slot], 0))) return false;
        }

        uint32_t keyUp[8], keyDn[8];
        PackPrfKey8(prf_up[l], keyUp);
        PackPrfKey8(prf_dn[l], keyDn);
        if (!CudaOk(cudaMemcpyAsync(ws.d_keyUp.p, keyUp, sizeof(keyUp), cudaMemcpyHostToDevice,
                                    ws.compute))) {
            return false;
        }
        if (!CudaOk(cudaMemcpyAsync(ws.d_keyDn.p, keyDn, sizeof(keyDn), cudaMemcpyHostToDevice,
                                    ws.compute))) {
            return false;
        }

        if constexpr (TestSlotReuseOrdering) {
            // Delay the first consumer behind a bounded, single-thread device
            // gate. layer_done[0] therefore cannot complete until the host
            // watchdog releases this event, making the later slot-0 overwrite
            // dependency adversarial rather than relying on GEMM timing.
            if (l == 0 && !CudaOk(cudaStreamWaitEvent(
                              ws.compute, ordering_probe->gate_event, 0))) {
                return false;
            }
        }

        if (l + 1 < L_lyr && !weights_shared) {
            // The pair for layer l+1 goes into the slot layer l-1 read. Without
            // this edge the generation kernels on h2d can rewrite W[l-1] while
            // the exact GEMMs for that layer are still reading it: every pointer
            // stays valid, CUDA reports nothing, and the resulting activation --
            // and therefore the ExactReplay digest -- becomes timing-dependent.
            // On a consensus path that is a split, not a performance bug.
            //
            // It has been latent only because the per-layer device-to-PAGEABLE
            // download below happens to block the host long enough for the prior
            // consumer to drain. CUDA explicitly documents that blocking as an
            // implementation detail that must not be relied upon, and pinning
            // that buffer or moving Merkle on-device -- both wanted for
            // utilization -- removes it.
            //
            // l == 0 writes slot 1, which no compute has read yet.
            const uint32_t next_slot{(l + 1) % 2};
            if (l >= 1) {
                if constexpr (TestSlotReuseOrdering) {
                    if (l == 1 && !CudaOk(cudaEventRecord(
                                      ordering_probe->pre_wait_event, ws.h2d))) {
                        return false;
                    }
                }
                if (!CudaOk(cudaStreamWaitEvent(
                        ws.h2d, ws.layer_done[next_slot], 0))) {
                    return false;
                }
                if constexpr (TestSlotReuseOrdering) {
                    if (l == 1) {
                        // This event is ordered immediately after the actual
                        // production wait. If that wait is deleted or points at
                        // the wrong slot, it completes while the compute gate is
                        // still held and the test fails.
                        if (!CudaOk(cudaEventRecord(
                                ordering_probe->post_wait_event, ws.h2d))) {
                            return false;
                        }
                        ordering_probe->slot_wait_enqueued.store(
                            true, std::memory_order_release);
                    }
                }
            }
            if (!load_weight_pair(*dWup_nxt, *dWdn_nxt, l + 1)) return false;
            if (!CudaOk(cudaEventRecord(ws.w_ready, ws.h2d))) return false;
        }

        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        if (!DeviceFfnLayerResident(d_cur, d_nxt, dWup_cur->As<int8_t>(), dWdn_cur->As<int8_t>(),
                                    ws.d_keyUp.As<uint32_t>(), ws.d_keyDn.As<uint32_t>(), b_seq,
                                    d_model, d_ff, ws.d_h32, ws.dH, ws.d_y32, ws.d_y64,
                                    ws.d_partial, ws.dAp, ws.dBp, ws.d_h64, ws.compute)) {
            NoteCpuFallback();
            return false;
        }
        // Records completion of the compute that read WEIGHT slot `slot`; the
        // h2d wait above consumes it before that slot is regenerated.
        if (!CudaOk(cudaEventRecord(ws.layer_done[slot], ws.compute))) return false;

        if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
        if (!CudaOk(cudaStreamWaitEvent(ws.d2h, ws.layer_done[slot], 0))) return false;
        if (!CudaOk(cudaMemcpyAsync(out_X[l + 1].data(), d_nxt, x_bytes, cudaMemcpyDeviceToHost,
                                    ws.d2h))) {
            return false;
        }
        if (!CudaOk(cudaEventRecord(ws.d2h_done[slot], ws.d2h))) return false;

        if (l + 1 < L_lyr && !weights_shared) {
            if (!CudaOk(cudaStreamWaitEvent(ws.compute, ws.w_ready, 0))) return false;
            std::swap(dWup_cur, dWup_nxt);
            std::swap(dWdn_cur, dWdn_nxt);
        }

        std::swap(d_cur, d_nxt);
    }

    if (!CudaOk(cudaStreamSynchronize(ws.h2d))) return false;
    if (!CudaOk(cudaStreamSynchronize(ws.compute))) return false;
    if (!CudaOk(cudaStreamSynchronize(ws.d2h))) return false;
    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    stream_drain.Disarm();
    {
        std::lock_guard<std::mutex> lock(g_stats_mu);
        g_stats.phase2_gemm_device = true;
        g_stats.phase2_extract_device = true;
        g_stats.phase2_ffn_fused_device = true;
        g_stats.phase2_ffn_chain_resident = true;
        g_stats.detail = "cuda_resident_ffn_chain+triple_stream+persistent_ws";
    }
    return true;
}

} // namespace

bool TryCudaRcFusedFfnChain(const std::vector<int8_t>& X0, bool weights_shared,
                            const std::vector<int8_t>& W_up_shared,
                            const std::vector<int8_t>& W_down_shared,
                            const std::vector<std::vector<int8_t>>& W_up_layers,
                            const std::vector<std::vector<int8_t>>& W_down_layers,
                            const std::vector<uint256>& prf_up,
                            const std::vector<uint256>& prf_dn,
                            uint32_t b_seq, uint32_t d_model, uint32_t d_ff,
                            uint32_t L_lyr,
                            std::vector<std::vector<int8_t>>& out_X,
                            const std::vector<uint256>* up_seeds,
                            const std::vector<uint256>* down_seeds)
{
    return TryCudaRcFusedFfnChainImpl<false>(
        X0, weights_shared, W_up_shared, W_down_shared, W_up_layers,
        W_down_layers, prf_up, prf_dn, b_seq, d_model, d_ff, L_lyr,
        out_X, up_seeds, down_seeds, nullptr);
}

RcExactReplaySlotReuseOrderingTestResult
RunRcExactReplaySlotReuseOrderingTest()
{
    RcExactReplaySlotReuseOrderingTestResult result;
    result.device_available = IsRcExactReplayCudaAvailable();
    if (!result.device_available) {
        result.detail = "CUDA ExactReplay unavailable";
        return result;
    }

    SlotReuseOrderingProbe probe;
    if (!probe.Init()) {
        result.interlock_supported = probe.interlock_supported;
        result.detail = result.interlock_supported
            ? "failed to initialize CUDA ordering interlock"
            : "CUDA device lacks concurrent-kernel interlock support";
        return result;
    }
    result.interlock_supported = true;

    constexpr uint32_t rows{32};
    constexpr uint32_t d_model{32};
    constexpr uint32_t d_ff{128};
    constexpr uint32_t layers{3};
    std::vector<int8_t> x0(static_cast<size_t>(rows) * d_model);
    for (size_t i = 0; i < x0.size(); ++i) {
        x0[i] = static_cast<int8_t>(
            static_cast<int>((i * 29u + 11u) % 15u) - 7);
    }
    std::vector<uint256> up_seeds(layers), down_seeds(layers);
    std::vector<uint256> prf_up(layers), prf_down(layers);
    for (uint32_t layer = 0; layer < layers; ++layer) {
        for (uint32_t byte = 0; byte < uint256::size(); ++byte) {
            up_seeds[layer].data()[byte] =
                static_cast<unsigned char>(0x11u + layer * 17u + byte * 3u);
            down_seeds[layer].data()[byte] =
                static_cast<unsigned char>(0x41u + layer * 19u + byte * 5u);
            prf_up[layer].data()[byte] =
                static_cast<unsigned char>(0x71u + layer * 23u + byte * 7u);
            prf_down[layer].data()[byte] =
                static_cast<unsigned char>(0xa1u + layer * 29u + byte * 11u);
        }
    }

    std::atomic_bool call_finished{false};
    bool blocked_before_release{false};
    std::thread watchdog([&] {
        if (cudaSetDevice(probe.device_index) != cudaSuccess) {
            probe.watchdog_expired.store(true, std::memory_order_release);
            probe.Release();
            return;
        }
        const auto admission_deadline{
            std::chrono::steady_clock::now() + std::chrono::seconds{15}};
        while (!probe.slot_wait_enqueued.load(std::memory_order_acquire) &&
               !call_finished.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < admission_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        if (!probe.slot_wait_enqueued.load(std::memory_order_acquire)) {
            probe.watchdog_expired.store(true, std::memory_order_release);
            probe.Release();
            return;
        }

        // Prove that the H2D stream reached the instruction immediately before
        // the production wait. Otherwise unrelated queue delay could make a
        // deleted wait look blocked and produce a false pass on a busy device.
        const auto site_deadline{
            std::chrono::steady_clock::now() + std::chrono::seconds{15}};
        while (!probe.PreWaitReached() &&
               std::chrono::steady_clock::now() < site_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        if (!probe.PreWaitReached()) {
            probe.watchdog_expired.store(true, std::memory_order_release);
            probe.Release();
            return;
        }

        // With the production wait removed, the immediately following event
        // has no outstanding H2D work in front of it and becomes visible here.
        // With the wait intact, the synthetic compute gate keeps it causally
        // blocked. Because the pre-wait event has already completed and the
        // post-wait event is adjacent, a short interval is sufficient and
        // avoids holding a display GPU near its watchdog threshold.
        const auto observation_deadline{
            std::chrono::steady_clock::now() + std::chrono::milliseconds{250}};
        while (!probe.PostWaitReached() &&
               std::chrono::steady_clock::now() < observation_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        blocked_before_release = !probe.PostWaitReached();
        probe.Release();
    });

    static const std::vector<int8_t> empty;
    static const std::vector<std::vector<int8_t>> empty_layers;
    std::vector<std::vector<int8_t>> outputs;
    result.chain_completed = TryCudaRcFusedFfnChainImpl<true>(
        x0, /*weights_shared=*/false, empty, empty, empty_layers,
        empty_layers, prf_up, prf_down, rows, d_model, d_ff, layers,
        outputs, &up_seeds, &down_seeds, &probe);
    call_finished.store(true, std::memory_order_release);
    probe.Release();
    watchdog.join();

    result.slot_wait_enqueued =
        probe.slot_wait_enqueued.load(std::memory_order_acquire);
    result.wait_site_reached = probe.PreWaitReached();
    result.overwrite_blocked_before_release = blocked_before_release;
    result.overwrite_resumed_after_release = probe.PostWaitReached();
    result.watchdog_expired =
        probe.watchdog_expired.load(std::memory_order_acquire) ||
        probe.DeviceWatchdogExpired();
    if (!result.chain_completed) {
        result.detail = "adversarial CUDA FFN chain did not complete";
    } else if (!result.slot_wait_enqueued) {
        result.detail = "production slot-reuse wait was not reached";
    } else if (!result.wait_site_reached) {
        result.detail = "H2D stream did not reach the slot-reuse wait site";
    } else if (!result.overwrite_blocked_before_release) {
        result.detail = "weight overwrite passed the per-slot wait before release";
    } else if (!result.overwrite_resumed_after_release) {
        result.detail = "weight overwrite did not resume after release";
    } else if (result.watchdog_expired) {
        result.detail = "ordering interlock watchdog expired";
    } else {
        result.detail = "per-slot wait blocked overwrite until consumer completion";
    }
    return result;
}

bool TryCudaRcPhase1AssociativeRecall(const std::vector<int8_t>& Q,
                                      const std::vector<int8_t>& K,
                                      const std::vector<int8_t>& V, const uint256& prf_S,
                                      const uint256& prf_Z, uint32_t n_q, uint32_t n_ctx,
                                      uint32_t d_head, std::vector<int8_t>& out_Z,
                                      const uint256* seed_q,
                                      const uint256* seed_k,
                                      const uint256* seed_v)
{
    if (!IsRcExactReplayCudaAvailable()) return false;
    if (n_q == 0 || n_ctx == 0 || d_head == 0) return false;
    if ((n_ctx % kRCMxBlockLen) != 0 || (d_head % kRCMxBlockLen) != 0) return false;
    if ((seed_q == nullptr) != (seed_k == nullptr) ||
        (seed_q == nullptr) != (seed_v == nullptr)) return false;
    const size_t q_elements{static_cast<size_t>(n_q) * d_head};
    const size_t context_elements{static_cast<size_t>(n_ctx) * d_head};
    if (seed_q == nullptr &&
        (Q.size() != q_elements || K.size() != context_elements ||
         V.size() != context_elements)) return false;

    DeviceBuf dQ, dK, dV, d_scores_i32, dS, d_partial, d_acc, d_KT, d_keyS, d_keyZ, dZ, d_sv;
    if (!dQ.Alloc(q_elements) || !dK.Alloc(context_elements) ||
        !dV.Alloc(context_elements)) return false;
    if (!d_keyS.Alloc(8 * sizeof(uint32_t)) || !d_keyZ.Alloc(8 * sizeof(uint32_t))) {
        return false;
    }
    if (!dZ.Alloc(static_cast<size_t>(n_q) * d_head)) return false;

    uint32_t keyS[8], keyZ[8];
    PackPrfKey8(prf_S, keyS);
    PackPrfKey8(prf_Z, keyZ);
    if (seed_q != nullptr) {
        auto& expand{ExpandContext()};
        std::lock_guard<std::mutex> lock(expand.mutex);
        if (!RcExpandMxGenerateDevice(
                *seed_q, n_q, d_head, dQ.As<int8_t>(), nullptr) ||
            !RcExpandMxGenerateDevice(
                *seed_k, n_ctx, d_head, dK.As<int8_t>(), nullptr) ||
            !RcExpandMxGenerateDevice(
                *seed_v, n_ctx, d_head, dV.As<int8_t>(), nullptr)) {
            return false;
        }
    } else {
        if (!CudaOk(cudaMemcpy(dQ.p, Q.data(), Q.size(), cudaMemcpyHostToDevice))) return false;
        if (!CudaOk(cudaMemcpy(dK.p, K.data(), K.size(), cudaMemcpyHostToDevice))) return false;
        if (!CudaOk(cudaMemcpy(dV.p, V.data(), V.size(), cudaMemcpyHostToDevice))) return false;
    }
    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    if (!CudaOk(cudaMemcpy(d_keyS.p, keyS, sizeof(keyS), cudaMemcpyHostToDevice))) return false;
    if (!CudaOk(cudaMemcpy(d_keyZ.p, keyZ, sizeof(keyZ), cudaMemcpyHostToDevice))) return false;

    bool ok = Phase1FullContext(dQ.As<int8_t>(), dK.As<int8_t>(), dV.As<int8_t>(),
                                d_keyS.As<uint32_t>(), d_keyZ.As<uint32_t>(), n_q, n_ctx, d_head,
                                dZ.As<int8_t>(), d_scores_i32, dS, d_sv, d_KT);
    std::string detail = "cuda_phase1_fullctx_imma+device_extract_S_Z";
    if (!ok) {
        // Fall back to large tiles (still Metal-far better than 32-wide).
        uint32_t chunk = std::min(kRcExactReplayPhase1CtxChunk, n_ctx);
        while (chunk >= kRCMxBlockLen) {
            if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
            if ((chunk % kRCMxBlockLen) == 0 &&
                Phase1Chunked(dQ.As<int8_t>(), dK.As<int8_t>(), dV.As<int8_t>(),
                              d_keyS.As<uint32_t>(), d_keyZ.As<uint32_t>(), n_q, n_ctx, d_head,
                              chunk, dZ.As<int8_t>(), d_scores_i32, dS, d_partial, d_acc,
                              d_KT)) {
                ok = true;
                detail = "cuda_phase1_chunk" + std::to_string(chunk) + "_imma+device_extract";
                break;
            }
            chunk /= 2;
            if (chunk < 4096) break;
        }
    }
    if (!ok) {
        NoteCpuFallback();
        return false;
    }
    if (!CudaOk(cudaDeviceSynchronize())) return false;
    if (matmul::v4::rc::ExactReplayCancellationRequested()) return false;
    out_Z.resize(static_cast<size_t>(n_q) * d_head);
    if (!CudaOk(cudaMemcpy(out_Z.data(), dZ.p, out_Z.size(), cudaMemcpyDeviceToHost))) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_stats_mu);
        g_stats.phase1_device = true;
        g_stats.detail = detail;
    }
    return true;
}

bool LaunchRcExactReplayFusedFfn(
    const std::vector<int8_t>& X, const std::vector<int8_t>& W_up,
    const std::vector<int8_t>& W_down, const uint256& prf_up, const uint256& prf_down,
    uint32_t row_begin, uint32_t rows, uint32_t d_model, uint32_t d_ff,
    std::vector<int8_t>& out)
{
    // Device ExtractMX currently indexes PRF rows from 0 within the launched
    // panel. Fail closed on non-zero absolute row_begin until the CUDA Extract
    // twin carries Metal's row_begin offset (production FFN uses 0).
    if (row_begin != 0) {
        out.clear();
        return false;
    }
    return TryCudaRcFusedFfnLayer(X, W_up, W_down, prf_up, prf_down, rows, d_model, d_ff, out);
}

bool LaunchRcExactReplayFusedFfnChain(
    const std::vector<int8_t>& X0, const std::vector<std::vector<int8_t>>& W_up,
    const std::vector<std::vector<int8_t>>& W_down, const std::vector<uint256>& prf_up,
    const std::vector<uint256>& prf_down, uint32_t rows, uint32_t d_model, uint32_t d_ff,
    std::vector<std::vector<int8_t>>& layer_outputs)
{
    layer_outputs.clear();
    if (prf_up.empty() || prf_up.size() != prf_down.size()) return false;
    if (W_up.empty() || W_down.empty() || W_up.size() != W_down.size()) return false;

    const uint32_t L_lyr = static_cast<uint32_t>(prf_up.size());
    // ExactGemmBackend ABI: a single weight pair denotes episode-shared weights.
    const bool weights_shared = (W_up.size() == 1 && W_down.size() == 1);
    if (!weights_shared && W_up.size() != L_lyr) return false;

    std::vector<std::vector<int8_t>> out_X;
    const std::vector<int8_t> empty;
    const std::vector<std::vector<int8_t>> empty_layers;
    if (!TryCudaRcFusedFfnChain(X0, weights_shared, weights_shared ? W_up[0] : empty,
                                weights_shared ? W_down[0] : empty,
                                weights_shared ? empty_layers : W_up,
                                weights_shared ? empty_layers : W_down, prf_up, prf_down, rows,
                                d_model, d_ff, L_lyr, out_X)) {
        return false;
    }
    // Internal chain layout is out_X[0]=X0, out_X[1..L]=layer outputs.
    // ExactGemmBackend returns only the L committed layer outputs.
    if (out_X.size() != static_cast<size_t>(L_lyr) + 1) return false;
    layer_outputs.reserve(L_lyr);
    for (uint32_t l = 1; l <= L_lyr; ++l) {
        layer_outputs.push_back(std::move(out_X[l]));
    }
    return layer_outputs.size() == L_lyr;
}

bool LaunchRcExactReplayPhase1(
    const std::vector<int8_t>& Q, const std::vector<int8_t>& K, const std::vector<int8_t>& V,
    const uint256& prf_s, const uint256& prf_z, uint32_t query_rows, uint32_t context_rows,
    uint32_t d_head, std::vector<int8_t>& out_z)
{
    return TryCudaRcPhase1AssociativeRecall(Q, K, V, prf_s, prf_z, query_rows, context_rows,
                                            d_head, out_z);
}

bool LaunchRcExactReplayFusedFfnChainSeeded(
    const std::vector<int8_t>& X0, const std::vector<uint256>& up_seeds,
    const std::vector<uint256>& down_seeds,
    const std::vector<uint256>& prf_up,
    const std::vector<uint256>& prf_down, uint32_t rows,
    uint32_t d_model, uint32_t d_ff,
    std::vector<std::vector<int8_t>>& layer_outputs)
{
    layer_outputs.clear();
    if (prf_up.empty() || prf_up.size() != prf_down.size() ||
        up_seeds.empty() || up_seeds.size() != down_seeds.size()) {
        return false;
    }
    const uint32_t layers{static_cast<uint32_t>(prf_up.size())};
    const bool weights_shared{up_seeds.size() == 1};
    if (!weights_shared && up_seeds.size() != layers) return false;
    static const std::vector<int8_t> empty;
    static const std::vector<std::vector<int8_t>> empty_layers;
    std::vector<std::vector<int8_t>> outputs;
    if (!TryCudaRcFusedFfnChain(
            X0, weights_shared, empty, empty, empty_layers, empty_layers,
            prf_up, prf_down, rows, d_model, d_ff, layers, outputs,
            &up_seeds, &down_seeds) ||
        outputs.size() != static_cast<size_t>(layers) + 1) {
        return false;
    }
    layer_outputs.reserve(layers);
    for (uint32_t layer = 1; layer <= layers; ++layer) {
        layer_outputs.push_back(std::move(outputs[layer]));
    }
    return layer_outputs.size() == layers;
}

bool LaunchRcExactReplayPhase1Seeded(
    const uint256& seed_q, const uint256& seed_k, const uint256& seed_v,
    const uint256& prf_s, const uint256& prf_z, uint32_t query_rows,
    uint32_t context_rows, uint32_t d_head, std::vector<int8_t>& out_z)
{
    static const std::vector<int8_t> empty;
    return TryCudaRcPhase1AssociativeRecall(
        empty, empty, empty, prf_s, prf_z, query_rows, context_rows,
        d_head, out_z, &seed_q, &seed_k, &seed_v);
}

bool LaunchRcExactReplayExpandMx(
    const uint256& seed, uint32_t rows, uint32_t columns,
    std::vector<int8_t>& output)
{
    output.clear();
    if (!IsRcExactReplayCudaAvailable()) return false;
    if (rows == 0 || columns == 0 ||
        rows % kRCMxBlockLen != 0 || columns % kRCMxBlockLen != 0 ||
        static_cast<size_t>(rows) >
            std::numeric_limits<size_t>::max() / columns) {
        return false;
    }
    const size_t count{static_cast<size_t>(rows) * columns};
    auto& context{ExpandContext()};
    std::lock_guard<std::mutex> lock(context.mutex);
    if (!RcExpandContext::Grow(
            context.output, context.output_capacity, count) ||
        !RcExpandMxGenerateDevice(
            seed, rows, columns,
            static_cast<int8_t*>(context.output), nullptr)) {
        return false;
    }
    output.resize(count);
    if (cudaMemcpy(
            output.data(), context.output, count,
            cudaMemcpyDeviceToHost) != cudaSuccess) {
        output.clear();
        return false;
    }
    return true;
}

bool LaunchRcExactReplayExpandMxForTest(
    const uint256& seed, uint32_t rows, uint32_t columns,
    uint32_t max_blocks_per_batch, std::vector<int8_t>& output)
{
    output.clear();
    if (!IsRcExactReplayCudaAvailable() || max_blocks_per_batch == 0 ||
        rows == 0 || columns == 0 ||
        rows % kRCMxBlockLen != 0 || columns % kRCMxBlockLen != 0 ||
        static_cast<size_t>(rows) >
            std::numeric_limits<size_t>::max() / columns) {
        return false;
    }
    const size_t count{static_cast<size_t>(rows) * columns};
    auto& context{ExpandContext()};
    std::lock_guard<std::mutex> lock(context.mutex);
    if (!RcExpandContext::Grow(
            context.output, context.output_capacity, count) ||
        !RcExpandMxGenerateDevice(
            seed, rows, columns,
            static_cast<int8_t*>(context.output), nullptr,
            max_blocks_per_batch)) {
        return false;
    }
    output.resize(count);
    if (cudaMemcpy(
            output.data(), context.output, count,
            cudaMemcpyDeviceToHost) != cudaSuccess) {
        output.clear();
        return false;
    }
    return true;
}

} // namespace matmul_v4::cuda
