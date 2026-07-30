// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// CUDA Stage-3 Fp3 NTT/LDE provider (BtxGpuFp3Lde*). Bit-identical to the
// Metal shader in metal/matmul_v4_rc_fp3_lde_gpu.metal and to the CPU
// LdeFromCoeffs path when fed the same root tables. Uses canonical
// Goldilocks arithmetic (same as cuda/matmul_v4_rc_rowleaf_gpu.cu).

#include <matmul/matmul_v4_rc_fp3_lde_gpu.h>

#include <cuda_runtime.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace {

using u64 = uint64_t;
using u32 = uint32_t;

#define GL_P 0xFFFFFFFF00000001ull
#define GL_NEGP 0xFFFFFFFFull

__device__ __forceinline__ u64 gl_canon(u64 a)
{
    return a >= GL_P ? a - GL_P : a;
}

__device__ __forceinline__ u64 gl_add(u64 a, u64 b)
{
    a = gl_canon(a);
    b = gl_canon(b);
    u64 s = a + b;
    if (s < a) s += GL_NEGP;
    if (s >= GL_P) s -= GL_P;
    return s;
}

__device__ __forceinline__ u64 gl_sub(u64 a, u64 b)
{
    a = gl_canon(a);
    b = gl_canon(b);
    return a >= b ? a - b : GL_P - (b - a);
}

__device__ __forceinline__ u64 gl_mul(u64 a, u64 b)
{
    a = gl_canon(a);
    b = gl_canon(b);
    const u64 lo = a * b;
    const u64 hi = __umul64hi(a, b);
    const u32 hh = (u32)(hi >> 32);
    const u32 hl = (u32)hi;
    u64 t0 = lo - (u64)hh;
    if (lo < (u64)hh) t0 -= GL_NEGP;
    const u64 t1 = (u64)hl * GL_NEGP;
    u64 r = t0 + t1;
    if (r < t1) r += GL_NEGP;
    if (r >= GL_P) r -= GL_P;
    return r;
}

__device__ __forceinline__ u32 reverse_low_bits(u32 value, u32 count)
{
    u32 reversed = 0;
    for (u32 i = 0; i < count; ++i) {
        reversed = (reversed << 1) | ((value >> i) & 1u);
    }
    return reversed;
}

__global__ void btx_rc_fp3_ntt_bit_reverse(u32 n, u32 log_n, u64* values)
{
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    const u32 j = reverse_low_bits(i, log_n);
    if (i > j) return;
    const u64 i3 = (u64)i * 3ULL;
    const u64 j3 = (u64)j * 3ULL;
    if (i == j) {
        values[i3] = gl_canon(values[i3]);
        values[i3 + 1] = gl_canon(values[i3 + 1]);
        values[i3 + 2] = gl_canon(values[i3 + 2]);
        return;
    }
    for (u32 limb = 0; limb < 3; ++limb) {
        const u64 a = gl_canon(values[i3 + limb]);
        const u64 b = gl_canon(values[j3 + limb]);
        values[i3 + limb] = b;
        values[j3 + limb] = a;
    }
}

__global__ void btx_rc_fp3_ntt_stage(u32 n, u32 len, u32 root_stride,
                                     u64* values, const u64* roots)
{
    const u32 half_len = len >> 1;
    const u32 butterfly_count = n >> 1;
    const u32 butterfly = blockIdx.x * blockDim.x + threadIdx.x;
    if (butterfly >= butterfly_count) return;
    const u32 group = butterfly / half_len;
    const u32 j = butterfly - group * half_len;
    const u32 lo_index = group * len + j;
    const u32 hi_index = lo_index + half_len;
    const u64 lo3 = (u64)lo_index * 3ULL;
    const u64 hi3 = (u64)hi_index * 3ULL;
    const u64 w = gl_canon(roots[(u64)j * root_stride]);
    for (u32 limb = 0; limb < 3; ++limb) {
        const u64 u = values[lo3 + limb];
        const u64 v = gl_mul(values[hi3 + limb], w);
        values[lo3 + limb] = gl_add(u, v);
        values[hi3 + limb] = gl_sub(u, v);
    }
}

__global__ void btx_rc_fp3_ntt_scale(u32 n, u64 scale, u64* values)
{
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    const u64 i3 = (u64)i * 3ULL;
    for (u32 limb = 0; limb < 3; ++limb) {
        values[i3 + limb] = gl_mul(values[i3 + limb], scale);
    }
}

constexpr int kThreads = 256;

inline int MapErr(cudaError_t err, const char* where)
{
    if (err == cudaSuccess) return 0;
    std::fprintf(stderr, "[BTX_GPU_LDE] CUDA %s: %s\n", where,
                 cudaGetErrorString(err));
    std::fflush(stderr);
    return -2;
}

inline bool IsPowerOfTwo(u32 n) { return n != 0 && (n & (n - 1)) == 0; }

inline u32 Log2Exact(u32 n)
{
    u32 log_n = 0;
    while (n > 1) {
        n >>= 1;
        ++log_n;
    }
    return log_n;
}

struct Fp3LdeCtx {
    u32 n{0};
    u32 log_n{0};
    u64 inverse_n{1};
    u64* d_work{nullptr};
    u64* d_forward_roots{nullptr};
    u64* d_inverse_roots{nullptr};
    size_t work_bytes{0};
    size_t root_bytes{0};
    bool busy{false};
    std::mutex mutex;
};

void FreeCtx(Fp3LdeCtx* ctx)
{
    if (ctx == nullptr) return;
    if (ctx->d_work != nullptr) cudaFree(ctx->d_work);
    if (ctx->d_forward_roots != nullptr) cudaFree(ctx->d_forward_roots);
    if (ctx->d_inverse_roots != nullptr) cudaFree(ctx->d_inverse_roots);
    delete ctx;
}

int LaunchTransform(Fp3LdeCtx& ctx, bool inverse)
{
    const u32 n = ctx.n;
    const int blocks_n = static_cast<int>((n + kThreads - 1) / kThreads);
    const int blocks_half =
        static_cast<int>(((n >> 1) + kThreads - 1) / kThreads);
    btx_rc_fp3_ntt_bit_reverse<<<blocks_n, kThreads>>>(n, ctx.log_n,
                                                       ctx.d_work);
    if (MapErr(cudaGetLastError(), "bit_reverse") != 0) return -2;

    const u64* roots = inverse ? ctx.d_inverse_roots : ctx.d_forward_roots;
    for (u64 len64 = 2; len64 <= n; len64 <<= 1) {
        const u32 len = static_cast<u32>(len64);
        btx_rc_fp3_ntt_stage<<<blocks_half, kThreads>>>(
            n, len, n / len, ctx.d_work, roots);
        if (MapErr(cudaGetLastError(), "stage") != 0) return -2;
    }
    if (inverse) {
        btx_rc_fp3_ntt_scale<<<blocks_n, kThreads>>>(n, ctx.inverse_n,
                                                     ctx.d_work);
        if (MapErr(cudaGetLastError(), "scale") != 0) return -2;
    }
    return MapErr(cudaDeviceSynchronize(), "sync");
}

int Transform(Fp3LdeCtx* ctx, const u64* input, u32 input_count, bool inverse,
              u64* output)
{
    if (ctx == nullptr || output == nullptr || input_count > ctx->n ||
        (input_count != 0 && input == nullptr)) {
        return -1;
    }
    std::unique_lock<std::mutex> lock(ctx->mutex, std::try_to_lock);
    if (!lock.owns_lock() || ctx->busy) {
        std::fprintf(stderr,
                     "[BTX_GPU_LDE] concurrent use of one transform context "
                     "is not allowed\n");
        std::fflush(stderr);
        return -1;
    }
    ctx->busy = true;
    struct BusyGuard {
        Fp3LdeCtx& c;
        ~BusyGuard() { c.busy = false; }
    } guard{*ctx};

    if (MapErr(cudaMemset(ctx->d_work, 0, ctx->work_bytes), "memset") != 0) {
        return -2;
    }
    if (input_count != 0) {
        const size_t input_bytes =
            static_cast<size_t>(input_count) * 3 * sizeof(u64);
        if (MapErr(cudaMemcpy(ctx->d_work, input, input_bytes,
                              cudaMemcpyHostToDevice),
                   "H2D") != 0) {
            return -2;
        }
    }
    if (LaunchTransform(*ctx, inverse) != 0) return -2;
    if (MapErr(cudaMemcpy(output, ctx->d_work, ctx->work_bytes,
                          cudaMemcpyDeviceToHost),
               "D2H") != 0) {
        return -2;
    }
    return 0;
}

} // namespace

extern "C" int BtxGpuFp3LdeAvailable(void)
{
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess) return 0;
    if (n <= 0) return 0;
    static bool logged = false;
    if (!logged) {
        logged = true;
        std::fprintf(stderr,
                     "[BTX_GPU_LDE] CUDA provider available (devices=%d)\n",
                     n);
        std::fflush(stderr);
    }
    return 1;
}

extern "C" int BtxGpuFp3LdeBegin(u32 domain_size, const u64* forward_roots,
                                 u32 forward_root_count,
                                 const u64* inverse_roots,
                                 u32 inverse_root_count, u64 inverse_n,
                                 void** ctx_out)
{
    if (ctx_out == nullptr || !IsPowerOfTwo(domain_size)) return -1;
    *ctx_out = nullptr;
    const u32 required_roots = domain_size / 2;
    if (forward_root_count != required_roots ||
        inverse_root_count != required_roots ||
        (required_roots != 0 &&
         (forward_roots == nullptr || inverse_roots == nullptr))) {
        return -1;
    }
    if (BtxGpuFp3LdeAvailable() != 1) return -2;

    Fp3LdeCtx* ctx = new (std::nothrow) Fp3LdeCtx();
    if (ctx == nullptr) return -2;
    ctx->n = domain_size;
    ctx->log_n = Log2Exact(domain_size);
    ctx->inverse_n = inverse_n;
    ctx->work_bytes =
        static_cast<size_t>(domain_size) * 3 * sizeof(u64);
    ctx->root_bytes = static_cast<size_t>(required_roots) * sizeof(u64);

    if (MapErr(cudaMalloc(&ctx->d_work, ctx->work_bytes), "malloc work") !=
        0) {
        FreeCtx(ctx);
        return -2;
    }
    if (required_roots != 0) {
        if (MapErr(cudaMalloc(&ctx->d_forward_roots, ctx->root_bytes),
                   "malloc fwd") != 0 ||
            MapErr(cudaMalloc(&ctx->d_inverse_roots, ctx->root_bytes),
                   "malloc inv") != 0 ||
            MapErr(cudaMemcpy(ctx->d_forward_roots, forward_roots,
                              ctx->root_bytes, cudaMemcpyHostToDevice),
                   "H2D fwd") != 0 ||
            MapErr(cudaMemcpy(ctx->d_inverse_roots, inverse_roots,
                              ctx->root_bytes, cudaMemcpyHostToDevice),
                   "H2D inv") != 0) {
            FreeCtx(ctx);
            return -2;
        }
    }
    *ctx_out = ctx;
    return 0;
}

extern "C" int BtxGpuFp3LdeForward(void* opaque, const u64* coeffs_aos,
                                   u32 coeff_count, u64* out_evals_aos)
{
    return Transform(static_cast<Fp3LdeCtx*>(opaque), coeffs_aos, coeff_count,
                     /*inverse=*/false, out_evals_aos);
}

extern "C" int BtxGpuFp3LdeInverse(void* opaque, const u64* evals_aos,
                                   u64* out_coeffs_aos)
{
    Fp3LdeCtx* ctx = static_cast<Fp3LdeCtx*>(opaque);
    if (ctx == nullptr) return -1;
    return Transform(ctx, evals_aos, ctx->n, /*inverse=*/true, out_coeffs_aos);
}

extern "C" void BtxGpuFp3LdeRelease(void* opaque)
{
    FreeCtx(static_cast<Fp3LdeCtx*>(opaque));
}
