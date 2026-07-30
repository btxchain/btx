// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_exact_replay_cuda.h>

#include <crypto/common.h>
#include <cuda/matmul_v4_lt_device_mx.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/matmul_v4_rc.h>

#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace matmul_v4::cuda {
namespace {

using matmul::v4::rc::kRCMxBlockLen;
using matmul::v4::rc::kRCWgradExactChunk;

std::mutex g_stats_mu;
RcExactReplayCudaStats g_stats;

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
    if (!TryLaunchLtImmaGemmS8S8Device(dA, dB, dC, rows, cols, inner, stream)) {
        return false;
    }
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
                                                DeviceBuf& dAp, DeviceBuf& dBp);

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
        const uint32_t rows = std::min(panel, b_seq - r0);
        const int8_t* in_row = d_in + static_cast<size_t>(r0) * d_model;
        int8_t* out_row = d_out + static_cast<size_t>(r0) * d_model;
        const size_t y_n = static_cast<size_t>(rows) * d_model;

        if (DeviceGemmS8S8(in_row, dWup, d_h32.As<int32_t>(), rows, d_ff, d_model, stream)) {
            if (!LaunchExtractI32Stream(d_h32.As<int32_t>(), dH.As<int8_t>(), d_keyUp, rows, d_ff,
                                        /*bj_base=*/0, stream, /*row_base=*/r0)) {
                return false;
            }
        } else {
            if (!d_h64.Alloc(static_cast<size_t>(rows) * d_ff * sizeof(int64_t))) return false;
            if (!DeviceExactGemmInt64Resident(in_row, dWup, rows, d_model, d_ff,
                                              d_h64.As<int64_t>(), d_partial, dAp, dBp)) {
                return false;
            }
            if (!LaunchExtractI64Stream(d_h64.As<int64_t>(), dH.As<int8_t>(), d_keyUp, rows, d_ff,
                                        /*bj_base=*/0, stream, /*row_base=*/r0)) {
                return false;
            }
        }

        if (DeviceGemmS8S8(dH.As<int8_t>(), dWdn, d_y32.As<int32_t>(), rows, d_model, d_ff,
                           stream)) {
            if (!LaunchI32PlusS8ToI64Stream(d_y32.As<int32_t>(), in_row, d_y64.As<int64_t>(), y_n,
                                            stream)) {
                return false;
            }
        } else {
            if (!DeviceExactGemmInt64Resident(dH.As<int8_t>(), dWdn, rows, d_ff, d_model,
                                              d_y64.As<int64_t>(), d_partial, dAp, dBp)) {
                return false;
            }
            if (!LaunchI64AddS8Stream(d_y64.As<int64_t>(), in_row, y_n, stream)) return false;
        }
        if (!LaunchExtractI64Stream(d_y64.As<int64_t>(), out_row, d_keyDn, rows, d_model,
                                    /*bj_base=*/0, stream, /*row_base=*/r0)) {
            return false;
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_stats_mu);
        if (panel < b_seq) {
            g_stats.detail = "cuda_ffn_row_panels=" + std::to_string(panel);
        }
    }
    return true;
}

[[nodiscard]] bool LaunchI32ToI64(const int32_t* in, int64_t* out, size_t n)
{
    if (n == 0) return true;
    const uint32_t thr = 256;
    const uint32_t blk = static_cast<uint32_t>((n + thr - 1) / thr);
    er_i32_to_i64<<<blk, thr>>>(in, out, n);
    return cudaGetLastError() == cudaSuccess;
}

[[nodiscard]] bool LaunchI64AddI32(int64_t* acc, const int32_t* add, size_t n)
{
    if (n == 0) return true;
    const uint32_t thr = 256;
    const uint32_t blk = static_cast<uint32_t>((n + thr - 1) / thr);
    er_i64_add_i32<<<blk, thr>>>(acc, add, n);
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
                                                DeviceBuf& dAp, DeviceBuf& dBp)
{
    const size_t out_n = static_cast<size_t>(m) * n;
    if (!d_partial.Alloc(out_n * sizeof(int32_t))) return false;

    // Prefer Metal-shaped single launch over full K.
    if (DeviceGemmS8S8(dA, dB, d_partial.As<int32_t>(), m, n, k)) {
        return LaunchI32ToI64(d_partial.As<int32_t>(), d_out, out_n);
    }

    // Panel fallback (still device-resident — no host re-pack).
    if (!CudaOk(cudaMemset(d_out, 0, out_n * sizeof(int64_t)))) return false;
    const dim3 tblock(16, 16);
    for (uint32_t k0 = 0; k0 < k; k0 += kRCWgradExactChunk) {
        const uint32_t len = std::min(kRCWgradExactChunk, k - k0);
        if (!dAp.Alloc(static_cast<size_t>(m) * len) ||
            !dBp.Alloc(static_cast<size_t>(len) * n)) {
            return false;
        }
        dim3 agrid((len + tblock.x - 1) / tblock.x, (m + tblock.y - 1) / tblock.y);
        dim3 bgrid((n + tblock.x - 1) / tblock.x, (len + tblock.y - 1) / tblock.y);
        er_pack_a_panel<<<agrid, tblock>>>(dA, dAp.As<int8_t>(), m, k, k0, len);
        er_pack_b_panel<<<bgrid, tblock>>>(dB, dBp.As<int8_t>(), k, n, k0, len);
        if (cudaGetLastError() != cudaSuccess) return false;
        if (!DeviceGemmS8S8(dAp.As<int8_t>(), dBp.As<int8_t>(), d_partial.As<int32_t>(), m, n,
                            len)) {
            return false;
        }
        if (!LaunchI64AddI32(d_out, d_partial.As<int32_t>(), out_n)) return false;
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
        const uint32_t len = std::min(chunk, n_ctx - t0);
        if ((len % kRCMxBlockLen) != 0) return false;

        dim3 tgrid((len + tblock.x - 1) / tblock.x, (d_head + tblock.y - 1) / tblock.y);
        er_pack_k_panel<<<tgrid, tblock>>>(dK, d_KT.As<int8_t>(), t0, len, n_ctx, d_head);
        if (cudaGetLastError() != cudaSuccess) return false;

        if (!DeviceGemmS8S8(dQ, d_KT.As<int8_t>(), d_scores_i32.As<int32_t>(), n_q, len,
                            d_head)) {
            return false;
        }
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

    const dim3 tblock(16, 16);
    dim3 tgrid((n_ctx + tblock.x - 1) / tblock.x, (d_head + tblock.y - 1) / tblock.y);
    er_pack_k_panel<<<tgrid, tblock>>>(dK, d_KT.As<int8_t>(), /*t0=*/0, n_ctx, n_ctx, d_head);
    if (cudaGetLastError() != cudaSuccess) return false;

    if (!DeviceGemmS8S8(dQ, d_KT.As<int8_t>(), d_scores_i32.As<int32_t>(), n_q, n_ctx,
                        d_head)) {
        return false;
    }
    if (!LaunchExtractI32(d_scores_i32.As<int32_t>(), dS.As<int8_t>(), d_keyS, n_q, n_ctx,
                          /*bj_base=*/0)) {
        return false;
    }
    // Free score i32 early — S is enough for SV.
    (void)d_scores_i32.Alloc(0);

    if (!DeviceGemmS8S8(dS.As<int8_t>(), dV, d_sv.As<int32_t>(), n_q, d_head, n_ctx)) {
        return false;
    }
    // SV fits int32 at production dims; Extract from i32 (same as host widen).
    return LaunchExtractI32(d_sv.As<int32_t>(), dZ, d_keyZ, n_q, d_head, /*bj_base=*/0);
}

} // namespace

bool IsRcExactReplayCudaAvailable()
{
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess || n <= 0) return false;
    return IsLtImmaGemmAvailable();
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

bool TryCudaRcFusedFfnChain(const std::vector<int8_t>& X0, bool weights_shared,
                            const std::vector<int8_t>& W_up_shared,
                            const std::vector<int8_t>& W_down_shared,
                            const std::vector<std::vector<int8_t>>& W_up_layers,
                            const std::vector<std::vector<int8_t>>& W_down_layers,
                            const std::vector<uint256>& prf_up, const std::vector<uint256>& prf_dn,
                            uint32_t b_seq, uint32_t d_model, uint32_t d_ff, uint32_t L_lyr,
                            std::vector<std::vector<int8_t>>& out_X)
{
    if (!IsRcExactReplayCudaAvailable()) return false;
    if (L_lyr == 0 || b_seq == 0 || d_model == 0 || d_ff == 0) return false;
    if ((d_model % kRCMxBlockLen) != 0 || (d_ff % kRCMxBlockLen) != 0) return false;
    if (X0.size() != static_cast<size_t>(b_seq) * d_model) return false;
    if (prf_up.size() != L_lyr || prf_dn.size() != L_lyr) return false;
    if (weights_shared) {
        if (W_up_shared.size() != static_cast<size_t>(d_model) * d_ff) return false;
        if (W_down_shared.size() != static_cast<size_t>(d_ff) * d_model) return false;
    } else if (W_up_layers.size() != L_lyr || W_down_layers.size() != L_lyr) {
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
        cudaEvent_t layer_done{nullptr};
        cudaEvent_t d2h_done[2]{nullptr, nullptr};
        size_t x_bytes{0};
        size_t wup_bytes{0};
        size_t wdn_bytes{0};
        ~Workspace()
        {
            for (auto& e : d2h_done) {
                if (e) cudaEventDestroy(e);
            }
            if (layer_done) cudaEventDestroy(layer_done);
            if (w_ready) cudaEventDestroy(w_ready);
            if (d2h) cudaStreamDestroy(d2h);
            if (h2d) cudaStreamDestroy(h2d);
            if (compute) cudaStreamDestroy(compute);
        }
        [[nodiscard]] bool Ensure(size_t xb, size_t wup, size_t wdn)
        {
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
            if (!layer_done &&
                cudaEventCreateWithFlags(&layer_done, cudaEventDisableTiming) != cudaSuccess) {
                return false;
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
    };
    static std::mutex ws_mu;
    static Workspace ws;
    std::lock_guard<std::mutex> ws_lock(ws_mu);
    if (!ws.Ensure(x_bytes, wup_bytes, wdn_bytes)) {
        NoteCpuFallback();
        return false;
    }

    out_X.resize(L_lyr + 1);
    out_X[0] = X0;
    for (uint32_t l = 1; l <= L_lyr; ++l) {
        if (out_X[l].size() != x_bytes) out_X[l].assign(x_bytes, 0);
    }

    auto select_w = [&](uint32_t l, const std::vector<int8_t>*& up, const std::vector<int8_t>*& dn) {
        if (weights_shared) {
            up = &W_up_shared;
            dn = &W_down_shared;
        } else {
            up = &W_up_layers[l];
            dn = &W_down_layers[l];
        }
    };

    if (!CudaOk(cudaMemcpyAsync(ws.dXa.p, X0.data(), x_bytes, cudaMemcpyHostToDevice, ws.h2d))) {
        return false;
    }
    {
        const std::vector<int8_t>* up = nullptr;
        const std::vector<int8_t>* dn = nullptr;
        select_w(0, up, dn);
        if (!CudaOk(cudaMemcpyAsync(ws.dWup0.p, up->data(), wup_bytes, cudaMemcpyHostToDevice,
                                    ws.h2d))) {
            return false;
        }
        if (!CudaOk(cudaMemcpyAsync(ws.dWdn0.p, dn->data(), wdn_bytes, cudaMemcpyHostToDevice,
                                    ws.h2d))) {
            return false;
        }
    }
    if (!CudaOk(cudaEventRecord(ws.w_ready, ws.h2d))) return false;
    if (!CudaOk(cudaStreamWaitEvent(ws.compute, ws.w_ready, 0))) return false;

    int8_t* d_cur = ws.dXa.As<int8_t>();
    int8_t* d_nxt = ws.dXb.As<int8_t>();
    DeviceBuf* dWup_cur = &ws.dWup0;
    DeviceBuf* dWdn_cur = &ws.dWdn0;
    DeviceBuf* dWup_nxt = &ws.dWup1;
    DeviceBuf* dWdn_nxt = &ws.dWdn1;

    for (uint32_t l = 0; l < L_lyr; ++l) {
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

        if (l + 1 < L_lyr && !weights_shared) {
            const std::vector<int8_t>* up = nullptr;
            const std::vector<int8_t>* dn = nullptr;
            select_w(l + 1, up, dn);
            if (!CudaOk(cudaMemcpyAsync(dWup_nxt->p, up->data(), wup_bytes, cudaMemcpyHostToDevice,
                                        ws.h2d))) {
                return false;
            }
            if (!CudaOk(cudaMemcpyAsync(dWdn_nxt->p, dn->data(), wdn_bytes, cudaMemcpyHostToDevice,
                                        ws.h2d))) {
                return false;
            }
            if (!CudaOk(cudaEventRecord(ws.w_ready, ws.h2d))) return false;
        }

        if (!DeviceFfnLayerResident(d_cur, d_nxt, dWup_cur->As<int8_t>(), dWdn_cur->As<int8_t>(),
                                    ws.d_keyUp.As<uint32_t>(), ws.d_keyDn.As<uint32_t>(), b_seq,
                                    d_model, d_ff, ws.d_h32, ws.dH, ws.d_y32, ws.d_y64,
                                    ws.d_partial, ws.dAp, ws.dBp, ws.d_h64, ws.compute)) {
            NoteCpuFallback();
            return false;
        }
        if (!CudaOk(cudaEventRecord(ws.layer_done, ws.compute))) return false;

        if (!CudaOk(cudaStreamWaitEvent(ws.d2h, ws.layer_done, 0))) return false;
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

    if (!CudaOk(cudaStreamSynchronize(ws.compute))) return false;
    if (!CudaOk(cudaStreamSynchronize(ws.d2h))) return false;
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

bool TryCudaRcPhase1AssociativeRecall(const std::vector<int8_t>& Q,
                                      const std::vector<int8_t>& K,
                                      const std::vector<int8_t>& V, const uint256& prf_S,
                                      const uint256& prf_Z, uint32_t n_q, uint32_t n_ctx,
                                      uint32_t d_head, std::vector<int8_t>& out_Z)
{
    if (!IsRcExactReplayCudaAvailable()) return false;
    if (n_q == 0 || n_ctx == 0 || d_head == 0) return false;
    if ((n_ctx % kRCMxBlockLen) != 0 || (d_head % kRCMxBlockLen) != 0) return false;
    if (Q.size() != static_cast<size_t>(n_q) * d_head) return false;
    if (K.size() != static_cast<size_t>(n_ctx) * d_head) return false;
    if (V.size() != static_cast<size_t>(n_ctx) * d_head) return false;

    DeviceBuf dQ, dK, dV, d_scores_i32, dS, d_partial, d_acc, d_KT, d_keyS, d_keyZ, dZ, d_sv;
    if (!dQ.Alloc(Q.size()) || !dK.Alloc(K.size()) || !dV.Alloc(V.size())) return false;
    if (!d_keyS.Alloc(8 * sizeof(uint32_t)) || !d_keyZ.Alloc(8 * sizeof(uint32_t))) {
        return false;
    }
    if (!dZ.Alloc(static_cast<size_t>(n_q) * d_head)) return false;

    uint32_t keyS[8], keyZ[8];
    PackPrfKey8(prf_S, keyS);
    PackPrfKey8(prf_Z, keyZ);
    if (!CudaOk(cudaMemcpy(dQ.p, Q.data(), Q.size(), cudaMemcpyHostToDevice))) return false;
    if (!CudaOk(cudaMemcpy(dK.p, K.data(), K.size(), cudaMemcpyHostToDevice))) return false;
    if (!CudaOk(cudaMemcpy(dV.p, V.data(), V.size(), cudaMemcpyHostToDevice))) return false;
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

} // namespace matmul_v4::cuda
