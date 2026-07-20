// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HIP_BTX_HIP_MFMA_I8_GEMM_H
#define BITCOIN_HIP_BTX_HIP_MFMA_I8_GEMM_H

// Shared int8→int32 16×16 tiled GEMM body with per-arch MFMA selection
// (Amendment v3 §1.D-MFMA). Include after btx_hip_mfma_guard.h and hip_runtime.

#include <hip/btx_hip_mfma_guard.h>

using btx_hip_int32x4 = int32_t __attribute__((ext_vector_type(4)));

[[nodiscard]] __device__ __forceinline__ int BtxPackI8x4(int8_t v0, int8_t v1, int8_t v2,
                                                         int8_t v3)
{
    return static_cast<int>((static_cast<uint32_t>(static_cast<uint8_t>(v0))) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v1)) << 8) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v2)) << 16) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v3)) << 24));
}

[[nodiscard]] __device__ __forceinline__ long BtxPackI8x8(int8_t v0, int8_t v1, int8_t v2,
                                                          int8_t v3, int8_t v4, int8_t v5,
                                                          int8_t v6, int8_t v7)
{
    const uint32_t lo = static_cast<uint32_t>(BtxPackI8x4(v0, v1, v2, v3));
    const uint32_t hi = static_cast<uint32_t>(BtxPackI8x4(v4, v5, v6, v7));
    return static_cast<long>((static_cast<uint64_t>(hi) << 32) | lo);
}

/** Load up to 8 consecutive K ints from row-major A[row][k..] (zero-pad). */
__device__ __forceinline__ void BtxLoadA8(const int8_t* A, int row, int M, int K, int k0,
                                          int8_t out[8])
{
#pragma unroll
    for (int i = 0; i < 8; ++i) out[i] = 0;
    if (row >= M) return;
    const size_t base = static_cast<size_t>(row) * static_cast<size_t>(K);
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        const int k = k0 + i;
        if (k < K) out[i] = A[base + static_cast<size_t>(k)];
    }
}

/** Load up to 8 consecutive K ints from col-major-along-K B[k][col] (zero-pad). */
__device__ __forceinline__ void BtxLoadB8(const int8_t* B, int col, int N, int K, int k0,
                                          int8_t out[8])
{
#pragma unroll
    for (int i = 0; i < 8; ++i) out[i] = 0;
    if (col >= N) return;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        const int k = k0 + i;
        if (k < K) out[i] = B[static_cast<size_t>(k) * static_cast<size_t>(N) + col];
    }
}

/**
 * Accumulate one 16×16 output tile of D = A·B (row-major) into per-lane
 * D[tileRow+ly*4+i][tileCol+lx]. Uses K16 MFMA, K32 MFMA, or scalar twin.
 * Callers pass threadIdx lx∈[0,16), ly∈[0,4).
 */
__device__ __forceinline__ void BtxI8GemmTileAccum(const int8_t* A, const int8_t* B, int32_t* D,
                                                    int M, int N, int K, int tileRow, int tileCol,
                                                    int lx, int ly, int ldD, int colOffset)
{
#if defined(BTX_HIP_MFMA_I8_K16)
    btx_hip_int32x4 acc = {0, 0, 0, 0};
    const int aRow = tileRow + lx;
    const int bCol = tileCol + lx;
    const int kTiles = (K + 15) / 16;
    for (int kt = 0; kt < kTiles; ++kt) {
        const int kBase = kt * 16 + ly * 4;
        int8_t a[8], b[8];
        BtxLoadA8(A, aRow, M, K, kBase, a);
        BtxLoadB8(B, bCol, N, K, kBase, b);
        const int a_pack = BtxPackI8x4(a[0], a[1], a[2], a[3]);
        const int b_pack = BtxPackI8x4(b[0], b[1], b[2], b[3]);
        acc = __builtin_amdgcn_mfma_i32_16x16x16i8(a_pack, b_pack, acc, 0, 0, 0);
    }
    for (int i = 0; i < 4; ++i) {
        const int row = tileRow + ly * 4 + i;
        const int col = tileCol + lx;
        if (row < M && col < N) {
            D[static_cast<size_t>(row) * static_cast<size_t>(ldD) +
              static_cast<size_t>(colOffset + col)] = acc[i];
        }
    }
#elif defined(BTX_HIP_MFMA_I8_K32)
    // CDNA3/4: K=16 int8 MFMA removed — use 16×16×32 with i64 packs (8×i8).
    btx_hip_int32x4 acc = {0, 0, 0, 0};
    const int aRow = tileRow + lx;
    const int bCol = tileCol + lx;
    const int kTiles = (K + 31) / 32;
    for (int kt = 0; kt < kTiles; ++kt) {
        const int kBase = kt * 32 + ly * 8;
        int8_t a[8], b[8];
        BtxLoadA8(A, aRow, M, K, kBase, a);
        BtxLoadB8(B, bCol, N, K, kBase, b);
        const long a_pack = BtxPackI8x8(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
        const long b_pack = BtxPackI8x8(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        acc = __builtin_amdgcn_mfma_i32_16x16x32_i8(a_pack, b_pack, acc, 0, 0, 0);
    }
    for (int i = 0; i < 4; ++i) {
        const int row = tileRow + ly * 4 + i;
        const int col = tileCol + lx;
        if (row < M && col < N) {
            D[static_cast<size_t>(row) * static_cast<size_t>(ldD) +
              static_cast<size_t>(colOffset + col)] = acc[i];
        }
    }
#else
    // RDNA4 / host / non-MFMA: exact scalar twin (never labeled MFMA).
    const int col = tileCol + lx;
    if (col < N) {
        for (int i = 0; i < 4; ++i) {
            const int row = tileRow + ly * 4 + i;
            if (row >= M) continue;
            int32_t s = 0;
            const size_t arow = static_cast<size_t>(row) * static_cast<size_t>(K);
            for (int k = 0; k < K; ++k) {
                s += static_cast<int32_t>(A[arow + static_cast<size_t>(k)]) *
                     static_cast<int32_t>(B[static_cast<size_t>(k) * static_cast<size_t>(N) + col]);
            }
            D[static_cast<size_t>(row) * static_cast<size_t>(ldD) +
              static_cast<size_t>(colOffset + col)] = s;
        }
    }
#endif
}

#endif // BITCOIN_HIP_BTX_HIP_MFMA_I8_GEMM_H
