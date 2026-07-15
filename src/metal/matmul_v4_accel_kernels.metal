// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// MatMul v4 Metal device kernels: exact INT8 -> INT32 GEMM plus the m x m
// sketch combine reduced mod q = 2^61 - 1.
//
// IMPORTANT: this file must stay byte-identical to the KERNEL_SOURCE raw
// string embedded in metal/matmul_v4_accel.mm (the inline-compile fallback
// used when no precompiled metallib is found), mirroring the v3 convention in
// metal/matmul_accel_kernels.metal / metal/matmul_accel.mm.
//
// DETERMINISM CONTRACT (design spec §B.6, matmul/pow_v4.h):
//   * Every arithmetic operation below is integer arithmetic. There is no
//     floating point anywhere in this file, and there must never be: the v4
//     compute path is exact s8 x s8 -> s32 (|C_ij| <= n*125^2 < 2^30, §B.4)
//     and the soundness field is q = 2^61 - 1 in exact 64-bit ALU math.
//   * Integer addition is associative and commutative, so any tiling or
//     accumulation order produces the same INT32 / F_q result bit-for-bit.
//     Canonical residues mod q are unique, so matching the CPU reference
//     (matmul/int8_field.cpp) reduces to computing the same exact integers.
//
// TWO GEMM PATHS:
//   * matmul_v4_s8_gemm_s32          - portable integer-ALU tiled GEMM.
//     Compiles under any Metal Shading Language version and runs bit-exactly
//     on every Metal GPU family (pre-M5 and M5). MSL `simdgroup_matrix` is
//     float/half only, so on pre-M5 hardware the scalar integer ALU is the
//     only conforming (exact) matmul engine.
//   * matmul_v4_s8_gemm_s32_tensor   - Metal 4 / M5-class path using
//     mpp::tensor_ops::matmul2d from Metal Performance Primitives, which
//     drives the per-core GPU neural accelerators with INT8 inputs and an
//     INT32 accumulator (the only accumulator type offered for INT8, i.e.
//     exact by construction). Guarded so this file still compiles with
//     pre-Metal-4 toolchains; the host additionally runs a bit-exactness
//     self-test against the CPU reference before ever trusting this path.

#include <metal_stdlib>

#if defined(__METAL_VERSION__) && (__METAL_VERSION__ >= 400) && \
    __has_include(<MetalPerformancePrimitives/MetalPerformancePrimitives.h>)
#include <MetalPerformancePrimitives/MetalPerformancePrimitives.h>
#define BTX_MATMUL_V4_HAVE_TENSOR_OPS 1
#endif

using namespace metal;

// Mersenne prime q = 2^61 - 1 (matmul::int8_field::kFieldPrime).
constant ulong FIELD_Q = 0x1fffffffffffffffUL;

// Tile edge for the portable integer GEMM (16x16 threads per threadgroup).
constant uint GEMM_TILE = 16u;

// Output tile computed by one simdgroup on the Metal 4 tensor-ops path.
#define BTX_V4_TENSOR_TILE_M 32
#define BTX_V4_TENSOR_TILE_N 32

// D (m x n, row-major s32) = X (m x k, row-major s8) * Y (k x n, row-major s8).
// Used for both stages of the sketch:
//   UA = U * A  with (m_rows, k, n_cols) = (m, n, n)
//   BV = B * V  with (m_rows, k, n_cols) = (n, n, m)
struct GemmParams {
    uint m_rows;
    uint k;
    uint n_cols;
};

// Chat (m x m, row-major u64 canonical mod q) = (UA * BV) mod q.
struct CombineParams {
    uint m;
    uint n;
};

// ---------------------------------------------------------------------------
// Portable exact INT8 -> INT32 GEMM (all Metal GPU families).
//
// Threadgroup-tiled: each 16x16 threadgroup stages 16x16 s8 tiles of X and Y
// through threadgroup memory and accumulates the exact 32-bit dot product.
// Out-of-range lanes load 0 (additive identity), so edge tiles contribute
// exactly the in-range terms; every thread reaches both barriers.
//
// Exactness: |x|,|y| <= 125 and k <= 65535, so |acc| <= k * 125^2 < 2^30
// (§B.4, CheckAccumulationBound) -- the s32 accumulator can never wrap and the
// result is the exact mathematical integer dot product, independent of order.
// ---------------------------------------------------------------------------
kernel void matmul_v4_s8_gemm_s32(
    constant GemmParams& p [[buffer(0)]],
    device const char* x [[buffer(1)]],
    device const char* y [[buffer(2)]],
    device int* d [[buffer(3)]],
    uint2 gid [[thread_position_in_grid]],
    uint2 tid [[thread_position_in_threadgroup]])
{
    threadgroup char tile_x[16][16];
    threadgroup char tile_y[16][16];

    const uint row = gid.y;
    const uint col = gid.x;

    int acc = 0;
    const uint k_tiles = (p.k + GEMM_TILE - 1u) / GEMM_TILE;
    for (uint t = 0; t < k_tiles; ++t) {
        const uint kx = t * GEMM_TILE + tid.x;
        const uint ky = t * GEMM_TILE + tid.y;
        tile_x[tid.y][tid.x] = (row < p.m_rows && kx < p.k)
            ? x[(ulong)row * p.k + kx]
            : (char)0;
        tile_y[tid.y][tid.x] = (ky < p.k && col < p.n_cols)
            ? y[(ulong)ky * p.n_cols + col]
            : (char)0;
        threadgroup_barrier(mem_flags::mem_threadgroup);

        for (uint kk = 0; kk < GEMM_TILE; ++kk) {
            acc += (int)tile_x[tid.y][kk] * (int)tile_y[kk][tid.x];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < p.m_rows && col < p.n_cols) {
        d[(ulong)row * p.n_cols + col] = acc;
    }
}

// ---------------------------------------------------------------------------
// Sketch combine: Chat = (UA * BV) mod q, exact 64-bit integer arithmetic.
//
// Equivalence with the CPU reference (matmul/matmul_v4.cpp ComputeSketch):
// the CPU computes T = U*C mod q then Chat = T*V mod q with C = A*B. Over the
// integers U*(A*B)*V == (U*A)*(B*V) (matrix multiplication is associative),
// and reduction mod q is a ring homomorphism, so both sides land on the SAME
// element of F_q. Canonical representatives in [0, q) are unique, therefore
// the u64 emitted here is bit-identical to the CPU's FqAdd/FqMul chain.
//
// Per-term exactness: |UA|,|BV| <= n*125^2 < 2^30 (§B.4), so each product
// fits in a signed 64-bit value with |prod| < 2^60 < q. Its canonical residue
// is prod >= 0 ? prod : prod + q (single lift, exact). The running sum is kept
// canonical with one conditional subtract per step (acc + term < 2q < 2^62,
// so the u64 accumulator can never wrap). This reproduces
// matmul::int8_field::FqAdd / FqFromInt32 semantics exactly.
// ---------------------------------------------------------------------------
kernel void matmul_v4_combine_mod_q(
    constant CombineParams& p [[buffer(0)]],
    device const int* ua [[buffer(1)]],
    device const int* bv [[buffer(2)]],
    device ulong* chat [[buffer(3)]],
    uint2 gid [[thread_position_in_grid]])
{
    const uint a = gid.y;
    const uint c = gid.x;
    if (a >= p.m || c >= p.m) {
        return;
    }

    ulong acc = 0;
    for (uint k = 0; k < p.n; ++k) {
        const long prod = (long)ua[(ulong)a * p.n + k] * (long)bv[(ulong)k * p.m + c];
        const ulong term = prod >= 0 ? (ulong)prod : (ulong)(prod + (long)FIELD_Q);
        acc += term;
        acc = acc >= FIELD_Q ? acc - FIELD_Q : acc;
    }
    chat[(ulong)a * p.m + c] = acc;
}

#if defined(BTX_MATMUL_V4_HAVE_TENSOR_OPS)
// ---------------------------------------------------------------------------
// Metal 4 / M5-class tensor-ops GEMM (GPU neural accelerators).
//
// Uses mpp::tensor_ops::matmul2d exactly as documented in Apple's "Metal
// Performance Primitives (MPP) Programming Guide" (2026): one simdgroup per
// threadgroup computes a BTX_V4_TENSOR_TILE_M x BTX_V4_TENSOR_TILE_N output
// tile, accumulating over the full K extent of the input tensors. Inputs are
// INT8 tensors; the destination is an INT32 tensor -- INT32 is the only
// accumulator type the hardware offers for INT8 operands, so the MACs are
// exact integers and the result is order-independent and bit-identical to
// the scalar path (same |acc| < 2^30 bound as above).
//
// Tensor extents follow the MPP convention (innermost extent first):
//   X (m_rows x k, row-major):  dextents {k, m_rows},  strides {1, k}
//   Y (k x n_cols, row-major):  dextents {n_cols, k},  strides {1, n_cols}
//   D (m_rows x n_cols, s32):   dextents {n_cols, m_rows}, strides {1, n_cols}
// Edge tiles rely on the slice-derived extents: mpp bounds-checks loads and
// stores against the tensor extents, so partial tiles read/write exactly the
// in-range elements.
// ---------------------------------------------------------------------------
kernel void matmul_v4_s8_gemm_s32_tensor(
    constant GemmParams& p [[buffer(0)]],
    device const char* x [[buffer(1)]],
    device const char* y [[buffer(2)]],
    device int* d [[buffer(3)]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    using namespace mpp;
    using namespace mpp::tensor_ops;

    constexpr auto desc = matmul2d_descriptor(BTX_V4_TENSOR_TILE_M, BTX_V4_TENSOR_TILE_N);
    matmul2d<desc, execution_simdgroup> op;

    auto mX = tensor(x, dextents<int, 2>{(int)p.k, (int)p.m_rows}, array<int, 2>{1, (int)p.k});
    auto mY = tensor(y, dextents<int, 2>{(int)p.n_cols, (int)p.k}, array<int, 2>{1, (int)p.n_cols});
    auto mD = tensor(d, dextents<int, 2>{(int)p.n_cols, (int)p.m_rows}, array<int, 2>{1, (int)p.n_cols});

    const int row0 = (int)(tgid.y * BTX_V4_TENSOR_TILE_M);
    const int col0 = (int)(tgid.x * BTX_V4_TENSOR_TILE_N);

    auto tX = mX.slice(0, row0);
    auto tY = mY.slice(col0, 0);
    auto tD = mD.slice(col0, row0);

    op.run(tX, tY, tD);
}
#endif // BTX_MATMUL_V4_HAVE_TENSOR_OPS
