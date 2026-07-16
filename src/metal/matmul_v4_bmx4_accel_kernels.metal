// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// MatMul v4.2 ENC-BMX4C (BMX4-C) Metal device kernels: exact INT8 -> INT32
// GEMM plus the balanced base-2^6 remainder-top limb split and the shifted
// mod-q fold, q = 2^61 - 1.
//
// IMPORTANT: this file must stay byte-identical to the KERNEL_SOURCE raw
// string embedded in metal/matmul_v4_bmx4_accel.mm (the inline-compile
// fallback used when no precompiled metallib is found), mirroring the
// convention of metal/matmul_v4_accel_kernels.metal / metal/matmul_v4_accel.mm.
//
// DETERMINISM CONTRACT (doc/btx-matmul-v4.2-bmx4c-spec.md §5, the C-1'
// no-rounding gate; matmul/matmul_v4_bmx4.h):
//   * Every arithmetic operation below is integer arithmetic. There is no
//     floating point anywhere in this file, and there must never be: Apple
//     silicon has no MXFP4 tensor unit, so BMX4-C on Apple runs as an
//     EXACT-INTEGER matmul over HOST-dequantized operands (the E8M0 scale is
//     applied on the host as an exact power-of-two shift, |Ahat|,|Bhat| <=
//     E_max = 48 fit s8; the M11 projectors satisfy |U|,|V| <= 6), and the
//     soundness field is q = 2^61 - 1 in exact 64-bit ALU math.
//   * Integer addition is associative and commutative, so any tiling or
//     accumulation order produces the same INT32 / F_q result bit-for-bit.
//     Canonical residues mod q are unique, so matching the CPU reference
//     (matmul/matmul_v4_bmx4.cpp) reduces to computing the same exact
//     integers.
//   * Magnitude envelope (spec §2.4): the projections P = U*Ahat and
//     Q = Bhat*V accumulate to |.| <= 288*n; the base-2^6 limb-pair GEMMs
//     (|digit| <= 32) accumulate to |.| <= 1024*n. ValidateDimsBMX4C accepts
//     only n <= 8589 (v4 accumulation bound) with 288*n <= 2^23 - 1 (the
//     remainder-top totality bound), so every accumulator stays < 2^24 --
//     far inside the exact range of a true int32 accumulator.
//
// TWO GEMM PATHS (the same two tiers as the v4.1 backend in
// metal/matmul_v4_accel_kernels.metal):
//   * matmul_v4_bmx4_s8_gemm_s32        - portable integer-ALU tiled GEMM.
//     Compiles under any Metal Shading Language version and runs bit-exactly
//     on every Metal GPU family (pre-M5 and M5). MSL `simdgroup_matrix` is
//     float/half only, so on pre-M5 hardware the scalar integer ALU is the
//     only conforming (exact) matmul engine.
//   * matmul_v4_bmx4_s8_gemm_s32_tensor - Metal 4 / M5-class path using
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
#define BTX_MATMUL_V4_BMX4_HAVE_TENSOR_OPS 1
#endif

using namespace metal;

// Mersenne prime q = 2^61 - 1 (matmul::int8_field::kFieldPrime).
constant ulong FIELD_Q = 0x1fffffffffffffffUL;

// Tile edge for the portable integer GEMM (16x16 threads per threadgroup).
constant uint GEMM_TILE = 16u;

// Output tile computed by one simdgroup on the Metal 4 tensor-ops path.
#define BTX_BMX4_TENSOR_TILE_M 32
#define BTX_BMX4_TENSOR_TILE_N 32

// D (m x n, row-major s32) = X (m x k, row-major s8) * Y (k x n, row-major s8).
// Used for every GEMM of the BMX4-C sketch:
//   P     = U * Ahat            (m_rows, k, n_cols) = (m, n, n)
//   Qvert = [B_1; ...; B_Q] * V (m_rows, k, n_cols) = (Q*n, n, m)
//   S_ij  = P_i * Qstack_j      (m_rows, k, n_cols) = (m, n, Q*m)
struct GemmParams {
    uint m_rows;
    uint k;
    uint n_cols;
};

// ---------------------------------------------------------------------------
// Portable exact INT8 -> INT32 GEMM (all Metal GPU families; the pre-M5 tier).
//
// Threadgroup-tiled: each 16x16 threadgroup stages 16x16 s8 tiles of X and Y
// through threadgroup memory and accumulates the exact 32-bit dot product.
// Out-of-range lanes load 0 (additive identity), so edge tiles contribute
// exactly the in-range terms; every thread reaches both barriers.
//
// Exactness: |x|,|y| <= 48 (host-dequantized operands / M11 projectors) or
// <= 32 (base-2^6 digit planes), so |acc| <= n * 1024 < 2^24 for every
// accepted n (spec §2.4) -- the s32 accumulator can never wrap and the result
// is the exact mathematical integer dot product, independent of order.
// ---------------------------------------------------------------------------
kernel void matmul_v4_bmx4_s8_gemm_s32(
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
// Balanced base-2^6 remainder-top digit decomposition (spec §3, C-13').
//
// MUST match the CPU reference DecomposeLimbPlanesBMX4C
// (matmul/matmul_v4_bmx4.cpp, used by ComputeCombineLimbTensorBMX4C)
// digit-for-digit:
//     low 3 digits:  d_l = ((x + 32) & 63) - 32;   x = (x - d_l) / 64;
//     top digit:     d_3 = x   (the exact remainder, in [-32, +32])
// The bitwise AND acts on the 32-bit two's-complement value exactly as on the
// host (C++20 mandates two's complement; MSL int is 32-bit two's complement),
// and (x - d_l) is an exact multiple of 64, so the truncating division is the
// exact quotient. Under the remainder-top rule the decomposition is TOTAL and
// UNIQUE for every |x| <= 2^23 - 1, which CheckCombineLimbBoundBMX4C
// guarantees for every P/Q entry (288*n <= 2^23 - 1 for all accepted n).
// Every digit satisfies |d| <= 32, a valid s8 GEMM operand.
// ---------------------------------------------------------------------------
inline void btx_bmx4_limb_digits(int x, thread int* d)
{
    for (uint l = 0; l < 3u; ++l) {
        d[l] = ((x + 32) & 63) - 32;
        x = (x - d[l]) / 64;
    }
    d[3] = x;
}

// P (rows x cols, row-major exact s32) -> four s8 digit planes, same layout.
struct LimbSplitParams {
    uint rows;
    uint cols;
};

kernel void matmul_v4_bmx4_limb_split(
    constant LimbSplitParams& p [[buffer(0)]],
    device const int* src [[buffer(1)]],
    device char* plane0 [[buffer(2)]],
    device char* plane1 [[buffer(3)]],
    device char* plane2 [[buffer(4)]],
    device char* plane3 [[buffer(5)]],
    uint2 gid [[thread_position_in_grid]])
{
    if (gid.y >= p.rows || gid.x >= p.cols) {
        return;
    }
    const ulong idx = (ulong)gid.y * p.cols + gid.x;
    int d[4];
    btx_bmx4_limb_digits(src[idx], d);
    plane0[idx] = (char)d[0];
    plane1[idx] = (char)d[1];
    plane2[idx] = (char)d[2];
    plane3[idx] = (char)d[3];
}

// Qvert ((Q*n) x m, row-major exact s32 -- the output of the stacked GEMM
// [B_1; ...; B_Q] * V) -> four s8 digit planes in the HORIZONTAL-stack layout
// n x q_cols (q_cols = Q*m, column block i = the digits of Q_i = Bhat_i*V).
// Column block i of the folded output is then byte-identical to
// ComputeCombineLimbTensorBMX4C(P, Q_i, n, m): every output entry depends only
// on its own P row and Qstack column, and the digit arithmetic is entrywise,
// so relocating an entry changes no digit.
struct LimbSplitQParams {
    uint n;      // rows of each Q_i
    uint m;      // columns of each Q_i (sketch dimension)
    uint q_cols; // Q * m
};

kernel void matmul_v4_bmx4_limb_split_qstack(
    constant LimbSplitQParams& p [[buffer(0)]],
    device const int* qvert [[buffer(1)]],
    device char* plane0 [[buffer(2)]],
    device char* plane1 [[buffer(3)]],
    device char* plane2 [[buffer(4)]],
    device char* plane3 [[buffer(5)]],
    uint2 gid [[thread_position_in_grid]])
{
    const uint k = gid.y;   // row in [0, n)
    const uint col = gid.x; // column in [0, q_cols)
    if (k >= p.n || col >= p.q_cols) {
        return;
    }
    const uint i = col / p.m;
    const uint c = col - i * p.m;
    const ulong src_idx = ((ulong)i * p.n + k) * p.m + c;
    const ulong dst_idx = (ulong)k * p.q_cols + col;
    int d[4];
    btx_bmx4_limb_digits(qvert[src_idx], d);
    plane0[dst_idx] = (char)d[0];
    plane1[dst_idx] = (char)d[1];
    plane2[dst_idx] = (char)d[2];
    plane3[dst_idx] = (char)d[3];
}

// Shifted mod-q fold of one limb-pair product S_ij into the running Chat:
//     chat[idx] = FqAdd(chat[idx], FqMul(2^shift, FqFromSigned(s[idx])))
// with shift = 6*(i+j) in {0, 6, ..., 36} (base-2^6 weights; the v4.1 backend
// uses 7*(i+j) -- this is the one arithmetic difference in the fold).
//
// Equivalence with the CPU chain (matmul/int8_field.cpp, as composed by
// ComputeCombineLimbTensorBMX4C), term by term:
//   * FqFromSigned(s32 v): |v| <= 1024*n < 2^24 < q, so the canonical residue
//     is v >= 0 ? v : v + q -- one exact lift, bit-identical to the host
//     FqReduce/FqNeg composition on the same value.
//   * FqMul(2^shift, r) for canonical r < q = 2^61 - 1: multiplying by a
//     power of two mod a Mersenne prime is a left ROTATION of the 61-bit
//     word. Split r = hi*2^(61-shift) + lo; then 2^shift * r = hi*2^61 +
//     lo*2^shift == hi + lo*2^shift (mod q). hi < 2^shift and lo*2^shift <
//     2^61 occupy disjoint bit ranges, so the sum is < 2^61 and could equal
//     q only if every one of the 61 bits were set, i.e. r = q -- excluded
//     (r is canonical). The rotation therefore IS the unique canonical
//     residue, identical to the host FqMul's FqReduce fold on the same
//     operands (the host weight 64^(i+j) = 2^shift with shift <= 36 < 61).
//   * FqAdd: chat, term < q so chat + term < 2^62 never wraps the u64
//     accumulator; one conditional subtract restores canonical form --
//     exactly the host FqAdd.
struct LimbFoldParams {
    uint rows;  // m
    uint cols;  // q_cols
    uint shift; // 6 * (limb_i + limb_j), in {0, 6, ..., 36}
};

kernel void matmul_v4_bmx4_limb_fold_mod_q(
    constant LimbFoldParams& p [[buffer(0)]],
    device const int* s [[buffer(1)]],
    device ulong* chat [[buffer(2)]],
    uint2 gid [[thread_position_in_grid]])
{
    if (gid.y >= p.rows || gid.x >= p.cols) {
        return;
    }
    const ulong idx = (ulong)gid.y * p.cols + gid.x;
    const int v = s[idx];
    const ulong residue = v >= 0 ? (ulong)v : (ulong)((long)v + (long)FIELD_Q);
    const ulong hi = residue >> (61u - p.shift);
    const ulong lo = residue & ((1UL << (61u - p.shift)) - 1UL);
    const ulong term = (lo << p.shift) | hi;
    ulong acc = chat[idx] + term;
    acc = acc >= FIELD_Q ? acc - FIELD_Q : acc;
    chat[idx] = acc;
}

#if defined(BTX_MATMUL_V4_BMX4_HAVE_TENSOR_OPS)
// ---------------------------------------------------------------------------
// Metal 4 / M5-class tensor-ops GEMM (GPU neural accelerators; the M5 tier).
//
// Uses mpp::tensor_ops::matmul2d exactly as documented in Apple's "Metal
// Performance Primitives (MPP) Programming Guide" (2026): one simdgroup per
// threadgroup computes a BTX_BMX4_TENSOR_TILE_M x BTX_BMX4_TENSOR_TILE_N
// output tile, accumulating over the full K extent of the input tensors.
// Inputs are INT8 tensors; the destination is an INT32 tensor -- INT32 is the
// only accumulator type the hardware offers for INT8 operands, so the MACs
// are exact integers and the result is order-independent and bit-identical
// to the scalar path (same |acc| < 2^24 bound as above).
//
// Tensor extents follow the MPP convention (innermost extent first):
//   X (m_rows x k, row-major):  dextents {k, m_rows},  strides {1, k}
//   Y (k x n_cols, row-major):  dextents {n_cols, k},  strides {1, n_cols}
//   D (m_rows x n_cols, s32):   dextents {n_cols, m_rows}, strides {1, n_cols}
// Edge tiles rely on the slice-derived extents: mpp bounds-checks loads and
// stores against the tensor extents, so partial tiles read/write exactly the
// in-range elements.
// ---------------------------------------------------------------------------
kernel void matmul_v4_bmx4_s8_gemm_s32_tensor(
    constant GemmParams& p [[buffer(0)]],
    device const char* x [[buffer(1)]],
    device const char* y [[buffer(2)]],
    device int* d [[buffer(3)]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    using namespace mpp;
    using namespace mpp::tensor_ops;

    constexpr auto desc = matmul2d_descriptor(BTX_BMX4_TENSOR_TILE_M, BTX_BMX4_TENSOR_TILE_N);
    matmul2d<desc, execution_simdgroup> op;

    auto mX = tensor(x, dextents<int, 2>{(int)p.k, (int)p.m_rows}, array<int, 2>{1, (int)p.k});
    auto mY = tensor(y, dextents<int, 2>{(int)p.n_cols, (int)p.k}, array<int, 2>{1, (int)p.n_cols});
    auto mD = tensor(d, dextents<int, 2>{(int)p.n_cols, (int)p.m_rows}, array<int, 2>{1, (int)p.n_cols});

    const int row0 = (int)(tgid.y * BTX_BMX4_TENSOR_TILE_M);
    const int col0 = (int)(tgid.x * BTX_BMX4_TENSOR_TILE_N);

    auto tX = mX.slice(0, row0);
    auto tY = mY.slice(col0, 0);
    auto tD = mD.slice(col0, row0);

    op.run(tX, tY, tD);
}
#endif // BTX_MATMUL_V4_BMX4_HAVE_TENSOR_OPS
