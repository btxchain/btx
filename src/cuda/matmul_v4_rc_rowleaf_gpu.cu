// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license.
//
// PR-89 GPU splice #1 — Poseidon2 ROW-LEAF sponge on CUDA (implementation).
// See src/matmul/matmul_v4_rc_rowleaf_gpu.h for the contract.
//
// Field + permutation bodies are the CANONICAL (post lazy-reduction-bugfix)
// forms from the validated gpu-integ harnesses (gl_fix.cuh / p2_fix.cuh):
// every gl_add/gl_sub/gl_mul returns a value in [0, P). The earlier lazy
// variants produced a FALSE-POSITIVE bit-parity on uniform random data and
// diverged on structured data — do not relax the canonicalization.
//
// Round constants are uploaded at runtime from GetAlgHashConstants() by the
// caller (BtxGpuRowLeafSetConstants); nothing hash-related is baked in here.

#include <matmul/matmul_v4_rc_rowleaf_gpu.h>

#include <cuda_runtime.h>

#include <cstdint>
#include <cstdio>
#include <mutex>

namespace {

using u64 = uint64_t;
using u32 = uint32_t;

#define GL_P 0xFFFFFFFF00000001ull
#define GL_NEGP 0xFFFFFFFFull /* 2^64 mod p = 2^32 - 1 */

__device__ __forceinline__ u64 gl_mul(u64 a, u64 b)
{
    u64 lo = a * b;
    u64 hi = __umul64hi(a, b);
    u32 hh = (u32)(hi >> 32);
    u32 hl = (u32)hi;
    u64 t0 = lo - hh;
    if (lo < (u64)hh) t0 -= GL_NEGP;
    u64 t1 = (u64)hl * GL_NEGP;
    u64 r = t0 + t1;
    if (r < t1) r += GL_NEGP;
    if (r >= GL_P) r -= GL_P; // CANONICAL [0,P)
    return r;
}
__device__ __forceinline__ u64 gl_add(u64 a, u64 b)
{
    u64 s = a + b;
    if (s < a) s += GL_NEGP;
    if (s >= GL_P) s -= GL_P; // CANONICAL [0,P)
    return s;
}
__device__ __forceinline__ u64 gl_dbl(u64 a) { return gl_add(a, a); }
// Exact for any u64 input: x < 2^64 implies x - P < 2^32 - 1 < P.
__device__ __forceinline__ u64 gl_canon(u64 a) { return a >= GL_P ? a - GL_P : a; }
__device__ __forceinline__ u64 gl_pow7(u64 x)
{
    u64 x2 = gl_mul(x, x);
    u64 x4 = gl_mul(x2, x2);
    u64 x6 = gl_mul(x4, x2);
    return gl_mul(x6, x);
}

#define P2_T 12
#define P2_RF 8
#define P2_RP 22
#define P2_RATE 8

__constant__ u64 cr_rc_ext[P2_RF][P2_T];
__constant__ u64 cr_rc_int[P2_RP];
__constant__ u64 cr_mu[P2_T];

// M_E = circ(2*M4, M4, M4); optimized M4 chain (== literal [5 7 1 3; 4 6 1 1;
// 1 3 5 7; 1 1 4 6]) — byte-validated against the CPU ApplyExternalMatrix.
__device__ __forceinline__ void pr_m4(u64& x0, u64& x1, u64& x2, u64& x3)
{
    u64 t0 = gl_add(x0, x1);
    u64 t1 = gl_add(x2, x3);
    u64 t2 = gl_add(gl_dbl(x1), t1);
    u64 t3 = gl_add(gl_dbl(x3), t0);
    u64 t4 = gl_add(gl_dbl(gl_dbl(t1)), t3);
    u64 t5 = gl_add(gl_dbl(gl_dbl(t0)), t2);
    x0 = gl_add(t3, t5);
    x1 = t5;
    x2 = gl_add(t2, t4);
    x3 = t4;
}
__device__ __forceinline__ void pr_external(u64 s[P2_T])
{
    pr_m4(s[0], s[1], s[2], s[3]);
    pr_m4(s[4], s[5], s[6], s[7]);
    pr_m4(s[8], s[9], s[10], s[11]);
#pragma unroll
    for (int i = 0; i < 4; i++) {
        u64 sum = gl_add(gl_add(s[i], s[4 + i]), s[8 + i]);
        s[i] = gl_add(s[i], sum);
        s[4 + i] = gl_add(s[4 + i], sum);
        s[8 + i] = gl_add(s[8 + i], sum);
    }
}
__device__ __forceinline__ void pr_internal(u64 s[P2_T])
{
    u64 sum = s[0];
#pragma unroll
    for (int i = 1; i < P2_T; i++) sum = gl_add(sum, s[i]);
#pragma unroll
    for (int i = 0; i < P2_T; i++) s[i] = gl_add(sum, gl_mul(s[i], cr_mu[i]));
}
__device__ __forceinline__ void pr_permute(u64 s[P2_T])
{
    pr_external(s); // external layer once up front (matches CPU Permute)
#pragma unroll
    for (int r = 0; r < 4; r++) {
#pragma unroll
        for (int i = 0; i < P2_T; i++) s[i] = gl_pow7(gl_add(s[i], cr_rc_ext[r][i]));
        pr_external(s);
    }
#pragma unroll
    for (int r = 0; r < P2_RP; r++) {
        s[0] = gl_pow7(gl_add(s[0], cr_rc_int[r]));
        pr_internal(s);
    }
#pragma unroll
    for (int r = 4; r < 8; r++) {
#pragma unroll
        for (int i = 0; i < P2_T; i++) s[i] = gl_pow7(gl_add(s[i], cr_rc_ext[r][i]));
        pr_external(s);
    }
}

// One thread per LDE row i. Absorb lanes [0, n_lanes) of a lane-major block:
// value = blk[k * n_lde + i], absorb position = base_pos + k.
// Add-absorb into rate lane (pos & 7); Permute whenever lane 7 is filled —
// exactly StreamingRowHasher::AbsorbColumn semantics for any block width.
__global__ void k_absorb_block(u64* __restrict__ state,
                               const u64* __restrict__ blk,
                               u32 n_lde, u32 n_lanes, u64 base_pos)
{
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n_lde) return;
    u64 s[P2_T];
#pragma unroll
    for (int j = 0; j < P2_T; j++) s[j] = state[(u64)i * P2_T + j];
    for (u32 k = 0; k < n_lanes; k++) {
        const u64 pos = base_pos + k;
        const int lane = (int)(pos & 7u);
        s[lane] = gl_add(s[lane], gl_canon(blk[(u64)k * n_lde + i]));
        if (lane == 7) pr_permute(s);
    }
#pragma unroll
    for (int j = 0; j < P2_T; j++) state[(u64)i * P2_T + j] = s[j];
}

// Finalize: absorb Fp(i) at position total_vals, then the 10* pad `1`, then
// zero-fill (a no-op on the additive rate lanes) to the next rate-8 multiple
// — i.e. one final Permute iff the pad did not land on lane 7.
// Digest = canonical state[0..4).
__global__ void k_finalize(u64* __restrict__ state, u64* __restrict__ dig,
                           u32 n_lde, u64 total_vals)
{
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n_lde) return;
    u64 s[P2_T];
#pragma unroll
    for (int j = 0; j < P2_T; j++) s[j] = state[(u64)i * P2_T + j];
    // index lane (i < n_lde << P, already canonical)
    {
        const int lane = (int)(total_vals & 7u);
        s[lane] = gl_add(s[lane], (u64)i);
        if (lane == 7) pr_permute(s);
    }
    // 10* pad start
    {
        const int lane = (int)((total_vals + 1) & 7u);
        s[lane] = gl_add(s[lane], 1ull);
        if (lane == 7) pr_permute(s);
    }
    // zero-fill to the rate boundary: zeros do not change the state, so the
    // only effect is the block-closing Permute (absent iff the `1` closed it).
    if (((total_vals + 2) & 7u) != 0u) pr_permute(s);
#pragma unroll
    for (int j = 0; j < 4; j++) dig[(u64)i * 4 + j] = gl_canon(s[j]);
}

struct RowLeafCtx {
    u64* d_state = nullptr; // [n_lde][12]
    u64* d_blk = nullptr;   // staging, lane-major [max_lanes][n_lde]
    u64* d_dig = nullptr;   // [n_lde][4]
    u32 n_lde = 0;
    u32 max_lanes = 0;
    u64 absorbed = 0; // total values absorbed so far (== next base_pos)
};

std::mutex g_mutex; // serialize context lifecycle (prover calls are serial)
bool g_constants_set = false;

int MapErr(cudaError_t e, const char* what)
{
    if (e == cudaSuccess) return 0;
    std::fprintf(stderr, "[BTX_GPU_ROWLEAF] CUDA error in %s: %s\n", what,
                 cudaGetErrorString(e));
    return -2;
}

constexpr u32 kMaxLanesPerAbsorb = 3072; // 3 * 1024 columns per block

} // namespace

extern "C" int BtxGpuRowLeafAvailable(void)
{
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess) return 0;
    return n > 0 ? 1 : 0;
}

extern "C" int BtxGpuRowLeafSetConstants(const uint64_t* rc_ext_8x12,
                                         const uint64_t* rc_int_22,
                                         const uint64_t* mu_12)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (rc_ext_8x12 == nullptr || rc_int_22 == nullptr || mu_12 == nullptr) return -1;
    int rc = 0;
    rc = MapErr(cudaMemcpyToSymbol(cr_rc_ext, rc_ext_8x12, sizeof(u64) * P2_RF * P2_T), "SetConstants(rc_ext)");
    if (rc != 0) return rc;
    rc = MapErr(cudaMemcpyToSymbol(cr_rc_int, rc_int_22, sizeof(u64) * P2_RP), "SetConstants(rc_int)");
    if (rc != 0) return rc;
    rc = MapErr(cudaMemcpyToSymbol(cr_mu, mu_12, sizeof(u64) * P2_T), "SetConstants(mu)");
    if (rc != 0) return rc;
    g_constants_set = true;
    return 0;
}

extern "C" int BtxGpuRowLeafBegin(uint32_t n_lde, void** ctx_out)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (ctx_out == nullptr || n_lde == 0 || (n_lde & (n_lde - 1)) != 0) return -1;
    if (!g_constants_set) {
        std::fprintf(stderr, "[BTX_GPU_ROWLEAF] Begin before SetConstants\n");
        return -1;
    }
    *ctx_out = nullptr;
    RowLeafCtx* ctx = new RowLeafCtx();
    ctx->n_lde = n_lde;
    // Device staging budget ~256 MiB (min 3 lanes = one Fp3 column).
    {
        u64 lanes = (u64{1} << 28) / ((u64)n_lde * sizeof(u64));
        if (lanes < 3) lanes = 3;
        if (lanes > kMaxLanesPerAbsorb) lanes = kMaxLanesPerAbsorb;
        ctx->max_lanes = (u32)lanes;
    }
    int rc = 0;
    rc = MapErr(cudaMalloc(&ctx->d_state, (u64)n_lde * P2_T * sizeof(u64)), "Begin(cudaMalloc state)");
    if (rc == 0) rc = MapErr(cudaMalloc(&ctx->d_blk, (u64)ctx->max_lanes * n_lde * sizeof(u64)), "Begin(cudaMalloc blk)");
    if (rc == 0) rc = MapErr(cudaMalloc(&ctx->d_dig, (u64)n_lde * 4 * sizeof(u64)), "Begin(cudaMalloc dig)");
    if (rc == 0) rc = MapErr(cudaMemset(ctx->d_state, 0, (u64)n_lde * P2_T * sizeof(u64)), "Begin(memset state)");
    if (rc != 0) {
        BtxGpuRowLeafRelease(ctx);
        return rc;
    }
    *ctx_out = ctx;
    return 0;
}

extern "C" int BtxGpuRowLeafAbsorb(void* vctx, const uint64_t* blk,
                                   uint32_t n_lanes, uint64_t base_pos)
{
    RowLeafCtx* ctx = static_cast<RowLeafCtx*>(vctx);
    if (ctx == nullptr || blk == nullptr || n_lanes == 0) return -1;
    if (base_pos != ctx->absorbed) {
        std::fprintf(stderr,
                     "[BTX_GPU_ROWLEAF] Absorb out of order: base_pos=%llu expected=%llu\n",
                     (unsigned long long)base_pos, (unsigned long long)ctx->absorbed);
        return -1;
    }
    const u32 n_lde = ctx->n_lde;
    for (u32 off = 0; off < n_lanes; off += ctx->max_lanes) {
        const u32 nl = (n_lanes - off < ctx->max_lanes) ? (n_lanes - off) : ctx->max_lanes;
        int rc = MapErr(cudaMemcpy(ctx->d_blk, blk + (u64)off * n_lde,
                                   (u64)nl * n_lde * sizeof(u64), cudaMemcpyHostToDevice),
                        "Absorb(memcpy blk)");
        if (rc != 0) return rc;
        const u32 tpb = 256;
        const u32 nblk = (n_lde + tpb - 1) / tpb;
        k_absorb_block<<<nblk, tpb>>>(ctx->d_state, ctx->d_blk, n_lde, nl,
                                      base_pos + off);
        rc = MapErr(cudaGetLastError(), "Absorb(launch)");
        if (rc != 0) return rc;
        rc = MapErr(cudaDeviceSynchronize(), "Absorb(sync)");
        if (rc != 0) return rc;
    }
    ctx->absorbed += n_lanes;
    return 0;
}

extern "C" int BtxGpuRowLeafFinalize(void* vctx, uint64_t total_vals,
                                     uint64_t* out_digests)
{
    RowLeafCtx* ctx = static_cast<RowLeafCtx*>(vctx);
    if (ctx == nullptr || out_digests == nullptr) return -1;
    if (total_vals != ctx->absorbed || total_vals == 0) {
        std::fprintf(stderr,
                     "[BTX_GPU_ROWLEAF] Finalize count mismatch: total=%llu absorbed=%llu\n",
                     (unsigned long long)total_vals, (unsigned long long)ctx->absorbed);
        BtxGpuRowLeafRelease(ctx);
        return -1;
    }
    const u32 n_lde = ctx->n_lde;
    const u32 tpb = 256;
    const u32 nblk = (n_lde + tpb - 1) / tpb;
    k_finalize<<<nblk, tpb>>>(ctx->d_state, ctx->d_dig, n_lde, total_vals);
    int rc = MapErr(cudaGetLastError(), "Finalize(launch)");
    if (rc == 0) rc = MapErr(cudaDeviceSynchronize(), "Finalize(sync)");
    if (rc == 0) {
        rc = MapErr(cudaMemcpy(out_digests, ctx->d_dig,
                               (u64)n_lde * 4 * sizeof(u64), cudaMemcpyDeviceToHost),
                    "Finalize(memcpy dig)");
    }
    BtxGpuRowLeafRelease(ctx);
    return rc;
}

extern "C" void BtxGpuRowLeafRelease(void* vctx)
{
    RowLeafCtx* ctx = static_cast<RowLeafCtx*>(vctx);
    if (ctx == nullptr) return;
    if (ctx->d_state != nullptr) cudaFree(ctx->d_state);
    if (ctx->d_blk != nullptr) cudaFree(ctx->d_blk);
    if (ctx->d_dig != nullptr) cudaFree(ctx->d_dig);
    delete ctx;
}
