// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal host glue for the MatMul v4.2 ENC-BMX4C (BMX4-C) miner backend.
//
// Pipeline (mirrors matmul::v4::bmx4::ComputeDigestBMX4C in
// matmul/matmul_v4_bmx4.cpp exactly; structural template: the v4.1 batched
// backend in metal/matmul_v4_accel.mm):
//   1. HOST  : derive sigma (UNCHANGED SHA256d) and the V4.2-tagged seeds,
//              expand the M11 mantissa + E8M0 scale planes and DEQUANTIZE on
//              the host with the consensus CPU code (matmul::v4::bmx4::
//              ExpandOperandA/B -- the E8M0 scale is an exact power-of-two
//              shift, |Ahat|,|Bhat| <= E_max = 48 <= 127 so the dequantized
//              operands are s8-native exact integers), plus the scale-free
//              M11 projectors (ExpandProjectorBMX4C, |U|,|V| <= 6). Sharing
//              the host expansion code with the CPU reference removes any
//              possibility of oracle divergence. Apple has no MXFP4 tensor
//              unit, so this is the spec's INT8 fallback rung (§5.2): the
//              whole committed object as an exact-integer matmul. The shared
//              expansion now blocks A rows for U*A and B columns for B*V;
//              Metal needs no separate scale-indexing implementation.
//   2. GPU   : P = U*Ahat (template-cached) and the stacked
//              Qvert = [Bhat_1; ...; Bhat_Q]*V as exact INT8 -> INT32 integer
//              GEMMs (portable integer-ALU kernel everywhere; Metal 4
//              mpp::tensor_ops::matmul2d INT8/INT32 on M5-class devices).
//   3. GPU   : the combine Chat = P*Q mod q, q = 2^61 - 1, as the 16 balanced
//              base-2^6 REMAINDER-TOP limb-pair GEMMs (spec §3, C-13'): the
//              entrywise digit split replicates the CPU
//              DecomposeLimbPlanesBMX4C digit-for-digit and the shifted fold
//              Chat = sum_ij 2^(6(i+j)) * S_ij runs in exact 64-bit integer
//              mod-q arithmetic (see matmul_v4_bmx4_accel_kernels.metal for
//              the proof of bit-equivalence with the reference
//              ComputeCombineModQ / ComputeCombineLimbTensorBMX4C).
//   4. HOST  : canonicality-check the returned words (< q), serialize with
//              matmul::v4::SerializeSketch and digest with
//              matmul::v4::ComputeSketchDigest -- the identical consensus
//              byte path used by the CPU reference.
//
// BIT-EXACTNESS GATE: on first use this backend replays full small-n batched
// digests through the GPU and compares digest AND payload byte-for-byte
// against matmul::v4::bmx4::ComputeDigestBMX4C for every header. The
// tensor-ops path is only enabled if it passes on this device; if even the
// ALU path fails, the backend reports itself unavailable and every call
// returns false (CPU fallback). No float, no approximation, ever (v4.2 spec
// §5 C-1': no operation on the committed path may ever round).

#include <metal/matmul_v4_bmx4_accel.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_batch.h>
#include <matmul/matmul_v4_bmx4.h>
#include <primitives/block.h>
#include <logging.h>
#include <uint256.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <limits.h>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include <mach-o/dyld.h>

namespace {

// Must stay byte-identical to metal/matmul_v4_bmx4_accel_kernels.metal
// (inline compile fallback when no precompiled metallib is found; same
// convention as the v4.1 backend in metal/matmul_v4_accel.mm).
constexpr const char* KERNEL_SOURCE = R"METAL(
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
    // G3 (macOS 26 MPP fix): the mpp::tensor_ops::matmul2d INT8 specialization
    // matches MUTABLE `int8_t x int8_t -> int32_t` tensor operands; a
    // `device const` operand pointer makes tensor(x, ...) deduce a const
    // element type that the template rejects at compile time. These are pure
    // INPUTS (matmul2d never writes x/y), so dropping const is a compile fix
    // only -- it changes no memory access and no result byte. Types are the
    // template's exact int8_t/int32_t spellings (== the file's char/int, but
    // matched to the MPP signature to avoid a char-vs-int8_t deduction miss).
    // COMPILE-UNVERIFIED (no Metal toolchain here).
    device int8_t* x [[buffer(1)]],
    device int8_t* y [[buffer(2)]],
    device int32_t* d [[buffer(3)]],
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
)METAL";

// Host mirrors of the kernel parameter blocks.
struct GemmParams {
    uint32_t m_rows{0};
    uint32_t k{0};
    uint32_t n_cols{0};
};

struct LimbSplitParams {
    uint32_t rows{0};
    uint32_t cols{0};
};

struct LimbSplitQParams {
    uint32_t n{0};
    uint32_t m{0};
    uint32_t q_cols{0};
};

struct LimbFoldParams {
    uint32_t rows{0};
    uint32_t cols{0};
    uint32_t shift{0};
};

constexpr uint32_t kGemmTile = 16;
constexpr uint32_t kTensorTileM = 32;
constexpr uint32_t kTensorTileN = 32;

// Self-test dimensions. ENC-BMX4C requires n % 32 == 0 (E8M0 block scales),
// so unlike the v4.1 backend there is no 32-misaligned shape to test; instead:
//   * n = 32 (m = 8):  partial 16x16 ALU tiles in the m extent and partial
//     32x32 tensor tiles in BOTH output extents (P is 8 x 32, Chat 8 x Q*8);
//   * n = 64 (m = 16): a second multiple-of-32 reduction extent, full tensor
//     K coverage over two ALU k-tiles.
// Both satisfy ValidateDimsBMX4C (n % 32 == 0, 288*n <= 2^23-1, v4 bounds).
constexpr uint32_t kSelfTestSmallN = 32;
constexpr uint32_t kSelfTestTensorN = 64;

/** Default nonce-window size Q for the batched path, overridable with
 *  BTX_MATMUL_V4_BMX4_METAL_BATCH (clamped to [1, matmul::v4::kMaxMinerBatch]
 *  and then to what the device's buffer limits / working set can hold). The
 *  BMX4-C device shapes are byte-for-byte the same sizes as the v4.1 backend
 *  at equal (n, m) (same s8/s32/u64 buffers; only the digit base differs), so
 *  the v4.1 sizing rationale carries over: ~60.5 MiB per in-flight nonce at
 *  n=4096 (m=1024), Q=8 ~ 484 MiB of window buffers plus ~20 MiB of
 *  template-scoped state -- comfortable on an 8 GB unified-memory Mac while
 *  already making the stacked combine GEMM dense and square-ish. */
constexpr uint32_t kDefaultBatchWindow = 8;

void AppendUniquePath(std::vector<std::string>& paths, const char* path)
{
    if (path == nullptr || path[0] == '\0') return;
    if (std::find(paths.begin(), paths.end(), path) == paths.end()) {
        paths.emplace_back(path);
    }
}

std::optional<std::string> ExecutableDirectory()
{
    uint32_t size = PATH_MAX;
    std::vector<char> buffer(size);
    if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
        buffer.resize(size);
        if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
            return std::nullopt;
        }
    }

    char resolved[PATH_MAX];
    const char* executable_path = realpath(buffer.data(), resolved) != nullptr ? resolved : buffer.data();
    std::string path{executable_path};
    const auto separator = path.find_last_of('/');
    if (separator == std::string::npos) {
        return std::nullopt;
    }
    return path.substr(0, separator);
}

std::vector<std::string> MatMulBmx4MetallibCandidatePaths()
{
    std::vector<std::string> paths;
    AppendUniquePath(paths, std::getenv("BTX_MATMUL_V4_BMX4_METALLIB_PATH"));

    if (const auto executable_dir = ExecutableDirectory()) {
        const std::string packaged_path = *executable_dir + "/metal/matmul_v4_bmx4_accel_kernels.metallib";
        AppendUniquePath(paths, packaged_path.c_str());
    }

#if defined(BTX_MATMUL_V4_BMX4_METALLIB_PATH)
    AppendUniquePath(paths, BTX_MATMUL_V4_BMX4_METALLIB_PATH);
#endif
    return paths;
}

bool EnvFlagDisabled(const char* name)
{
    const char* env = std::getenv(name);
    return env != nullptr && env[0] == '0';
}

// Singleton Metal state for the BMX4-C backend. Command queues and pipeline
// state objects are documented thread-safe in Metal; the batched path
// serializes on batch_mutex because it shares the template-scoped cache.
struct MetalBmx4Context {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> gemm_alu_pipeline{nil};
    id<MTLComputePipelineState> limb_split_pipeline{nil};
    id<MTLComputePipelineState> limb_split_qstack_pipeline{nil};
    id<MTLComputePipelineState> limb_fold_pipeline{nil};
    // Metal 4 / M5-class GPU-neural-accelerator GEMM; nil when the runtime
    // compiler, OS, or device does not support mpp::tensor_ops, or when the
    // path failed the bit-exactness self-test.
    id<MTLComputePipelineState> gemm_tensor_pipeline{nil};
    std::string tensor_path_reason;
    std::string error;
    std::string device_name;

    // One-time full-pipeline batched self-test vs the CPU reference
    // matmul::v4::bmx4::ComputeDigestBMX4C (see RunSelfTest()).
    std::once_flag self_test_once;
    bool self_test_passed{false};
    std::string self_test_error;

    // Template-scoped cache for the batched miner (guarded by batch_mutex):
    // V (s8 n x m) and the four balanced base-2^6 digit planes of P = U*Ahat
    // (s8 m x n each), keyed by (template hash, n). Mirrors the v4.1 batched
    // backend's amortization across successive nonce windows.
    std::mutex batch_mutex;
    bool batch_template_valid{false};
    uint256 batch_template_hash;
    uint32_t batch_template_n{0};
    id<MTLBuffer> batch_buf_v{nil};
    id<MTLBuffer> batch_p_plane[4]{nil, nil, nil, nil};

    MetalBmx4Context()
    {
        @autoreleasepool {
            // MTLCreateSystemDefaultDevice() is restricted to interactive apps
            // on macOS 14+; MTLCopyAllDevices() works from CLI/daemon contexts
            // (same rationale as the v3/v4.1 backends).
            NSArray<id<MTLDevice>>* all_devices = MTLCopyAllDevices();
            if (all_devices == nil || all_devices.count == 0) {
                error = "No Metal-compatible GPU device found";
                return;
            }
            device = all_devices[0];
            device_name = device.name != nil ? std::string{[device.name UTF8String]} : "unknown";

            queue = [device newCommandQueue];
            if (queue == nil) {
                error = "Failed to create Metal command queue";
                return;
            }

            // Portable pipelines: prefer the precompiled metallib, fall back
            // to inline runtime compilation of KERNEL_SOURCE.
            NSError* library_error = nil;
            id<MTLLibrary> library = nil;
            for (const auto& candidate_path : MatMulBmx4MetallibCandidatePaths()) {
                NSString* precompiled_path = [NSString stringWithUTF8String:candidate_path.c_str()];
                if (![[NSFileManager defaultManager] fileExistsAtPath:precompiled_path]) {
                    continue;
                }
                library_error = nil;
                NSURL* precompiled_url = [NSURL fileURLWithPath:precompiled_path];
                library = [device newLibraryWithURL:precompiled_url error:&library_error];
                if (library != nil) {
                    break;
                }
            }
            if (library == nil) {
                library_error = nil;
                library = [device newLibraryWithSource:[NSString stringWithUTF8String:KERNEL_SOURCE]
                                               options:nil
                                                 error:&library_error];
            }
            if (library == nil) {
                error = library_error != nil ? [[library_error localizedDescription] UTF8String]
                                             : "Failed to compile Metal MatMul BMX4-C kernel source";
                return;
            }

            gemm_alu_pipeline = MakePipeline(library, @"matmul_v4_bmx4_s8_gemm_s32", error);
            if (gemm_alu_pipeline == nil) return;
            limb_split_pipeline = MakePipeline(library, @"matmul_v4_bmx4_limb_split", error);
            if (limb_split_pipeline == nil) return;
            limb_split_qstack_pipeline = MakePipeline(library, @"matmul_v4_bmx4_limb_split_qstack", error);
            if (limb_split_qstack_pipeline == nil) return;
            limb_fold_pipeline = MakePipeline(library, @"matmul_v4_bmx4_limb_fold_mod_q", error);
            if (limb_fold_pipeline == nil) return;

            InitTensorPipeline();
        }
    }

    id<MTLComputePipelineState> MakePipeline(id<MTLLibrary> library, NSString* name, std::string& out_error)
    {
        id<MTLFunction> function = [library newFunctionWithName:name];
        if (function == nil) {
            out_error = std::string{"Failed to load Metal kernel function: "} + [name UTF8String];
            return nil;
        }
        NSError* pipeline_error = nil;
        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:function error:&pipeline_error];
        if (pipeline == nil) {
            out_error = pipeline_error != nil
                ? [[pipeline_error localizedDescription] UTF8String]
                : (std::string{"Failed to create pipeline: "} + [name UTF8String]);
        }
        return pipeline;
    }

    void InitTensorPipeline()
    {
        // The Metal 4 tensor-ops GEMM is always compiled at runtime with an
        // explicit metal4.0 language version so the precompiled (portable)
        // metallib never needs a Metal 4 toolchain. On pre-Metal-4 OSes,
        // toolchains, or devices this compile simply fails and we stay on the
        // (equally bit-exact) integer-ALU path. BTX_MATMUL_V4_BMX4_TENSOR_OPS=0
        // forces the ALU path.
        if (EnvFlagDisabled("BTX_MATMUL_V4_BMX4_TENSOR_OPS")) {
            tensor_path_reason = "disabled_by_environment";
            return;
        }

        MTLCompileOptions* options = [MTLCompileOptions new];
        // MTLLanguageVersion4_0 == (4 << 16); spelled numerically so this file
        // also builds against pre-macOS-26 SDKs, where the runtime compile
        // then fails cleanly below.
        options.languageVersion = static_cast<MTLLanguageVersion>(4 << 16);

        NSError* library_error = nil;
        id<MTLLibrary> tensor_library =
            [device newLibraryWithSource:[NSString stringWithUTF8String:KERNEL_SOURCE]
                                 options:options
                                   error:&library_error];
        if (tensor_library == nil) {
            tensor_path_reason = library_error != nil
                ? std::string{"metal4_compile_failed:"} + [[library_error localizedDescription] UTF8String]
                : "metal4_compile_failed";
            return;
        }

        std::string pipeline_error;
        id<MTLComputePipelineState> pipeline =
            MakePipeline(tensor_library, @"matmul_v4_bmx4_s8_gemm_s32_tensor", pipeline_error);
        if (pipeline == nil) {
            // Function absent (BTX_MATMUL_V4_BMX4_HAVE_TENSOR_OPS not defined
            // by the runtime compiler) or pipeline creation failed on this GPU
            // family: no tensor path on this device.
            tensor_path_reason = pipeline_error;
            return;
        }
        gemm_tensor_pipeline = pipeline;
        tensor_path_reason = "ok";
    }
};

MetalBmx4Context& GetContext()
{
    static MetalBmx4Context context;
    return context;
}

std::atomic_bool g_logged_unavailable{false};
std::atomic_bool g_logged_tensor_self_test{false};

void LogUnavailableOnce(const std::string& reason)
{
    bool expected{false};
    if (g_logged_unavailable.compare_exchange_strong(expected, true)) {
        LogPrintf("MATMUL v4.2 BMX4-C WARNING: Metal backend unavailable (%s); falling back to CPU\n", reason);
    }
}

bool EncodeGemm(id<MTLCommandBuffer> command,
                id<MTLComputePipelineState> pipeline,
                bool tensor_path,
                const GemmParams& params,
                id<MTLBuffer> params_buffer,
                id<MTLBuffer> x,
                id<MTLBuffer> y,
                id<MTLBuffer> d,
                std::string& error)
{
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (encoder == nil) {
        error = "Failed to create Metal compute encoder";
        return false;
    }
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:params_buffer offset:0 atIndex:0];
    [encoder setBuffer:x offset:0 atIndex:1];
    [encoder setBuffer:y offset:0 atIndex:2];
    [encoder setBuffer:d offset:0 atIndex:3];

    if (tensor_path) {
        // One simdgroup (32 threads) per threadgroup computes one
        // kTensorTileM x kTensorTileN output tile via mpp::tensor_ops.
        const MTLSize groups = MTLSizeMake((params.n_cols + kTensorTileN - 1) / kTensorTileN,
                                           (params.m_rows + kTensorTileM - 1) / kTensorTileM, 1);
        const MTLSize group_size = MTLSizeMake(32, 1, 1);
        [encoder dispatchThreadgroups:groups threadsPerThreadgroup:group_size];
    } else {
        const MTLSize groups = MTLSizeMake((params.n_cols + kGemmTile - 1) / kGemmTile,
                                           (params.m_rows + kGemmTile - 1) / kGemmTile, 1);
        const MTLSize group_size = MTLSizeMake(kGemmTile, kGemmTile, 1);
        [encoder dispatchThreadgroups:groups threadsPerThreadgroup:group_size];
    }
    [encoder endEncoding];
    return true;
}

// Encode a 2D elementwise kernel (limb split / fold) over a cols x rows grid.
bool EncodeGrid2D(id<MTLCommandBuffer> command,
                  id<MTLComputePipelineState> pipeline,
                  id<MTLBuffer> params_buffer,
                  std::initializer_list<id<MTLBuffer>> buffers,
                  uint32_t grid_cols, uint32_t grid_rows,
                  std::string& error)
{
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (encoder == nil) {
        error = "Failed to create Metal compute encoder";
        return false;
    }
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:params_buffer offset:0 atIndex:0];
    NSUInteger index = 1;
    for (id<MTLBuffer> buffer : buffers) {
        [encoder setBuffer:buffer offset:0 atIndex:index++];
    }
    const MTLSize groups = MTLSizeMake((grid_cols + kGemmTile - 1) / kGemmTile,
                                       (grid_rows + kGemmTile - 1) / kGemmTile, 1);
    const MTLSize group_size = MTLSizeMake(kGemmTile, kGemmTile, 1);
    [encoder dispatchThreadgroups:groups threadsPerThreadgroup:group_size];
    [encoder endEncoding];
    return true;
}

uint32_t RequestedBatchWindow()
{
    const char* env = std::getenv("BTX_MATMUL_V4_BMX4_METAL_BATCH");
    if (env != nullptr && env[0] != '\0') {
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(env, &end, 10);
        if (end != nullptr && *end == '\0' && parsed >= 1) {
            return static_cast<uint32_t>(
                std::min<unsigned long>(parsed, matmul::v4::kMaxMinerBatch));
        }
    }
    return kDefaultBatchWindow;
}

// Largest per-window buffer sizes for a window of `w` nonces (bytes). Same
// shapes as the v4.1 batched backend at equal (n, m).
struct BatchWindowBytes {
    uint64_t bstack;  // [Bhat_1; ...; Bhat_Q], s8, w*n*n
    uint64_t qvert;   // stacked GEMM output, s32, w*n*m
    uint64_t plane;   // one Qstack digit plane, s8, n*(w*m) (x4 allocated)
    uint64_t s;       // one limb-pair product, s32, m*(w*m)
    uint64_t chat;    // wide sketch, u64, m*(w*m)

    BatchWindowBytes(uint32_t w, uint32_t n, uint32_t m)
        : bstack{static_cast<uint64_t>(w) * n * n},
          qvert{static_cast<uint64_t>(w) * n * m * sizeof(int32_t)},
          plane{static_cast<uint64_t>(n) * w * m},
          s{static_cast<uint64_t>(m) * w * m * sizeof(int32_t)},
          chat{static_cast<uint64_t>(m) * w * m * sizeof(uint64_t)} {}

    uint64_t Total() const { return bstack + qvert + 4 * plane + s + chat; }
};

// Clamp the requested window to what this device can hold: every buffer must
// fit maxBufferLength, and the window total (plus a 1/4 headroom margin) must
// fit the recommended working set on unified-memory parts. Returns 0 if even
// a single-nonce window does not fit (caller fails closed).
uint32_t ResolveBatchWindowSize(MetalBmx4Context& ctx, uint32_t requested, uint32_t n, uint32_t m)
{
    uint32_t window = std::clamp<uint32_t>(requested, 1, matmul::v4::kMaxMinerBatch);
    const uint64_t max_len = ctx.device.maxBufferLength;
    const uint64_t working_set = ctx.device.recommendedMaxWorkingSetSize;
    const auto fits = [&](uint32_t w) {
        const BatchWindowBytes bytes(w, n, m);
        if (bytes.bstack > max_len || bytes.qvert > max_len || bytes.plane > max_len ||
            bytes.s > max_len || bytes.chat > max_len) {
            return false;
        }
        if (working_set > 0 && bytes.Total() > working_set - working_set / 4) {
            return false;
        }
        return true;
    };
    while (window > 1 && !fits(window)) {
        window /= 2;
    }
    return fits(window) ? window : 0;
}

// Build (or reuse) the template-scoped device state: V and the four base-2^6
// digit planes of P = U*Ahat. Host derivations are the exact consensus
// routines of matmul::v4::bmx4 (ExpandOperandA dequantizes with the E8M0
// power-of-two shift on the host; ExpandProjectorBMX4C is scale-free M11);
// P itself is one exact INT8->INT32 GEMM on device (the same integers as the
// CPU ComputeProjectedLeft by exactness + associativity of integer addition),
// then split with the base-2^6 remainder-top digit recurrence on device.
// Caller holds ctx.batch_mutex.
bool PrepareBatchTemplate(MetalBmx4Context& ctx, const CBlockHeader& header,
                          const uint256& template_hash, uint32_t n, uint32_t m,
                          bool use_tensor_gemm, std::string& error)
{
    if (ctx.batch_template_valid && ctx.batch_template_hash == template_hash &&
        ctx.batch_template_n == n) {
        return true;
    }
    ctx.batch_template_valid = false;
    ctx.batch_buf_v = nil;
    for (auto& plane : ctx.batch_p_plane) {
        plane = nil;
    }

    @autoreleasepool {
        // Template-scoped consensus derivations (I1', v4.2 domain tags):
        // Ahat, U, V bind the template hash only, so any header of the window
        // yields the identical seeds (DeriveOperandSeedBMX4C /
        // DeriveProjectorSeedsBMX4C project onto ComputeTemplateHash
        // internally).
        const uint256 seed_a = matmul::v4::bmx4::DeriveOperandSeedBMX4C(header, matmul::v4::Operand::A);
        const auto [seed_u, seed_v] = matmul::v4::bmx4::DeriveProjectorSeedsBMX4C(header);
        const std::vector<int8_t> Ahat = matmul::v4::bmx4::ExpandOperandA(seed_a, n);
        const std::vector<int8_t> U = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_u, m, n);
        const std::vector<int8_t> V = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_v, n, m);

        const size_t nn = static_cast<size_t>(n) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const NSUInteger max_len = ctx.device.maxBufferLength;
        if (nn > max_len || mn * sizeof(int32_t) > max_len) {
            error = "requested dimension exceeds Metal device buffer limits";
            return false;
        }

        id<MTLBuffer> buf_a = [ctx.device newBufferWithBytes:Ahat.data() length:nn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_u = [ctx.device newBufferWithBytes:U.data() length:mn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_v = [ctx.device newBufferWithBytes:V.data() length:mn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_p = [ctx.device newBufferWithLength:mn * sizeof(int32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> p_planes[4];
        bool alloc_failed = buf_a == nil || buf_u == nil || buf_v == nil || buf_p == nil;
        for (uint32_t l = 0; l < 4; ++l) {
            p_planes[l] = [ctx.device newBufferWithLength:mn options:MTLResourceStorageModeShared];
            alloc_failed = alloc_failed || p_planes[l] == nil;
        }

        const GemmParams p_params{.m_rows = m, .k = n, .n_cols = n};
        const LimbSplitParams split_params{.rows = m, .cols = n};
        id<MTLBuffer> buf_p_params = [ctx.device newBufferWithBytes:&p_params length:sizeof(p_params) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_split_params = [ctx.device newBufferWithBytes:&split_params length:sizeof(split_params) options:MTLResourceStorageModeShared];
        alloc_failed = alloc_failed || buf_p_params == nil || buf_split_params == nil;
        if (alloc_failed) {
            error = "Failed to allocate Metal buffers";
            return false;
        }

        id<MTLCommandBuffer> command = [ctx.queue commandBuffer];
        if (command == nil) {
            error = "Failed to create Metal command buffer";
            return false;
        }
        id<MTLComputePipelineState> gemm_pipeline =
            use_tensor_gemm ? ctx.gemm_tensor_pipeline : ctx.gemm_alu_pipeline;
        if (!EncodeGemm(command, gemm_pipeline, use_tensor_gemm, p_params, buf_p_params,
                        buf_u, buf_a, buf_p, error)) {
            return false;
        }
        if (!EncodeGrid2D(command, ctx.limb_split_pipeline, buf_split_params,
                          {buf_p, p_planes[0], p_planes[1], p_planes[2], p_planes[3]},
                          /*grid_cols=*/n, /*grid_rows=*/m, error)) {
            return false;
        }
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            error = command.error != nil
                ? std::string{"Metal command buffer failed: "} + [[command.error localizedDescription] UTF8String]
                : "Metal command buffer did not complete";
            return false;
        }

        ctx.batch_buf_v = buf_v;
        for (uint32_t l = 0; l < 4; ++l) {
            ctx.batch_p_plane[l] = p_planes[l];
        }
        ctx.batch_template_hash = template_hash;
        ctx.batch_template_n = n;
        ctx.batch_template_valid = true;
        return true;
    }
}

// Compute one window of `window` nonces (headers[first .. first+window)).
// Caller holds ctx.batch_mutex and has validated/prepared the template.
bool ComputeBatchWindow(MetalBmx4Context& ctx,
                        const std::vector<CBlockHeader>& headers,
                        size_t first, uint32_t window,
                        uint32_t n, uint32_t m, bool use_tensor_gemm,
                        std::vector<uint256>& digests_out,
                        std::vector<std::vector<unsigned char>>& payloads_out,
                        std::string& error)
{
    @autoreleasepool {
        const uint32_t q_cols = window * m;
        const size_t nn = static_cast<size_t>(n) * n;
        const BatchWindowBytes bytes(window, n, m);
        const uint64_t max_len = ctx.device.maxBufferLength;
        if (bytes.bstack > max_len || bytes.qvert > max_len || bytes.plane > max_len ||
            bytes.s > max_len || bytes.chat > max_len) {
            error = "batched window exceeds Metal device buffer limits";
            return false;
        }

        id<MTLBuffer> buf_bstack = [ctx.device newBufferWithLength:bytes.bstack options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_qvert = [ctx.device newBufferWithLength:bytes.qvert options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_s = [ctx.device newBufferWithLength:bytes.s options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_chat = [ctx.device newBufferWithLength:bytes.chat options:MTLResourceStorageModeShared];
        id<MTLBuffer> q_planes[4];
        bool alloc_failed = buf_bstack == nil || buf_qvert == nil || buf_s == nil || buf_chat == nil;
        for (uint32_t l = 0; l < 4; ++l) {
            q_planes[l] = [ctx.device newBufferWithLength:bytes.plane options:MTLResourceStorageModeShared];
            alloc_failed = alloc_failed || q_planes[l] == nil;
        }

        const GemmParams qv_params{.m_rows = window * n, .k = n, .n_cols = m};
        const LimbSplitQParams split_params{.n = n, .m = m, .q_cols = q_cols};
        const GemmParams limb_params{.m_rows = m, .k = n, .n_cols = q_cols};
        id<MTLBuffer> buf_qv_params = [ctx.device newBufferWithBytes:&qv_params length:sizeof(qv_params) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_split_params = [ctx.device newBufferWithBytes:&split_params length:sizeof(split_params) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_limb_params = [ctx.device newBufferWithBytes:&limb_params length:sizeof(limb_params) options:MTLResourceStorageModeShared];
        alloc_failed = alloc_failed || buf_qv_params == nil || buf_split_params == nil || buf_limb_params == nil;

        // Each fold encoder reads its parameters at GPU execution time, so
        // every (i, j) pair needs its own little params buffer. shift =
        // 6*(i+j): the base-2^6 weight 64^(i+j) mod q (v4.1 uses 7*(i+j)).
        id<MTLBuffer> fold_params[16];
        for (uint32_t i = 0; i < 4; ++i) {
            for (uint32_t j = 0; j < 4; ++j) {
                const LimbFoldParams fp{.rows = m, .cols = q_cols, .shift = 6u * (i + j)};
                fold_params[i * 4 + j] =
                    [ctx.device newBufferWithBytes:&fp length:sizeof(fp) options:MTLResourceStorageModeShared];
                alloc_failed = alloc_failed || fold_params[i * 4 + j] == nil;
            }
        }
        if (alloc_failed) {
            error = "Failed to allocate Metal buffers";
            return false;
        }

        // Host-side consensus derivation per candidate: sigma binds the nonce
        // (nonce-fresh, I1'); Bhat is the nonce-fresh operand, dequantized on
        // the host by ExpandOperandB (exact E8M0 power-of-two shift, fits
        // int8). Identical routines -- not re-implementations -- to the CPU
        // reference ComputeDigestBMX4C.
        std::vector<uint256> sigmas(window);
        int8_t* bstack_ptr = static_cast<int8_t*>([buf_bstack contents]);
        for (uint32_t w = 0; w < window; ++w) {
            const CBlockHeader& header = headers[first + w];
            sigmas[w] = matmul::v4::DeriveSigma(header);
            const uint256 seed_b = matmul::v4::bmx4::DeriveOperandSeedBMX4C(header, matmul::v4::Operand::B);
            const std::vector<int8_t> Bhat = matmul::v4::bmx4::ExpandOperandB(seed_b, n);
            std::memcpy(bstack_ptr + static_cast<size_t>(w) * nn, Bhat.data(), nn);
        }
        // Chat accumulates across the 16 shifted folds; start from zero.
        std::memset([buf_chat contents], 0, bytes.chat);

        id<MTLCommandBuffer> command = [ctx.queue commandBuffer];
        if (command == nil) {
            error = "Failed to create Metal command buffer";
            return false;
        }
        id<MTLComputePipelineState> gemm_pipeline =
            use_tensor_gemm ? ctx.gemm_tensor_pipeline : ctx.gemm_alu_pipeline;

        // Qvert = [Bhat_1; ...; Bhat_Q] * V, one stacked exact GEMM
        // (Q*n x n x m).
        if (!EncodeGemm(command, gemm_pipeline, use_tensor_gemm, qv_params, buf_qv_params,
                        buf_bstack, ctx.batch_buf_v, buf_qvert, error)) {
            return false;
        }
        // Base-2^6 digit planes of Qstack = [Q_1 | ... | Q_Q] (n x q_cols).
        if (!EncodeGrid2D(command, ctx.limb_split_qstack_pipeline, buf_split_params,
                          {buf_qvert, q_planes[0], q_planes[1], q_planes[2], q_planes[3]},
                          /*grid_cols=*/q_cols, /*grid_rows=*/n, error)) {
            return false;
        }
        // ONE LARGE DENSE COMBINE: 16 limb-pair GEMMs S_ij = P_i * Q_j
        // (m x q_cols x n), each folded into Chat with weight 2^(6(i+j)) mod
        // q. Encoders in one command buffer execute in order, so reusing the
        // one S buffer across pairs is race-free.
        for (uint32_t i = 0; i < 4; ++i) {
            for (uint32_t j = 0; j < 4; ++j) {
                if (!EncodeGemm(command, gemm_pipeline, use_tensor_gemm, limb_params, buf_limb_params,
                                ctx.batch_p_plane[i], q_planes[j], buf_s, error)) {
                    return false;
                }
                if (!EncodeGrid2D(command, ctx.limb_fold_pipeline, fold_params[i * 4 + j],
                                  {buf_s, buf_chat},
                                  /*grid_cols=*/q_cols, /*grid_rows=*/m, error)) {
                    return false;
                }
            }
        }

        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            error = command.error != nil
                ? std::string{"Metal command buffer failed: "} + [[command.error localizedDescription] UTF8String]
                : "Metal command buffer did not complete";
            return false;
        }

        // Slice column block w = Chat_w (m x m), canonicality-check, and run
        // the identical consensus serialization/digest path on the host.
        const uint64_t* chat_words = static_cast<const uint64_t*>([buf_chat contents]);
        std::vector<matmul::v4::Fq> chat_i(static_cast<size_t>(m) * m);
        for (uint32_t w = 0; w < window; ++w) {
            for (uint32_t a = 0; a < m; ++a) {
                const uint64_t* src = chat_words + static_cast<size_t>(a) * q_cols + static_cast<size_t>(w) * m;
                matmul::v4::Fq* dst = &chat_i[static_cast<size_t>(a) * m];
                for (uint32_t c = 0; c < m; ++c) {
                    if (src[c] >= matmul::int8_field::kFieldPrime) {
                        // Defense in depth: the fold kernel proves words < q,
                        // so a non-canonical word means a malfunctioning
                        // device/driver.
                        error = "Metal produced a non-canonical F_q word";
                        return false;
                    }
                    dst[c] = src[c];
                }
            }
            payloads_out[first + w] = matmul::v4::SerializeSketch(chat_i);
            digests_out[first + w] = matmul::v4::ComputeSketchDigest(sigmas[w], payloads_out[first + w]);
        }
        return true;
    }
}

// Full batched pipeline for one header vector. Caller holds ctx.batch_mutex.
// `window_override` != 0 pins the window size (self-test); 0 resolves the
// environment/default request against device limits.
bool ComputeDigestsImpl(MetalBmx4Context& ctx,
                        const std::vector<CBlockHeader>& headers,
                        uint32_t n, uint32_t m, bool use_tensor_gemm,
                        uint32_t window_override,
                        std::vector<uint256>& digests_out,
                        std::vector<std::vector<unsigned char>>& payloads_out,
                        std::string& error)
{
    // Fail closed on a template mismatch: combining a stale template's cached
    // Ahat/U/V/P with a fresh header would produce digests that are NOT the
    // consensus ComputeDigestBMX4C digests for that header.
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(headers[0]);
    for (const CBlockHeader& header : headers) {
        if (matmul::v4::ComputeTemplateHash(header) != template_hash) {
            error = "candidate header does not project onto the window template";
            return false;
        }
    }
    if (!PrepareBatchTemplate(ctx, headers[0], template_hash, n, m, use_tensor_gemm, error)) {
        return false;
    }

    const uint32_t requested = window_override != 0 ? window_override : RequestedBatchWindow();
    const uint32_t window = ResolveBatchWindowSize(ctx, requested, n, m);
    if (window == 0) {
        error = "batched window exceeds Metal device buffer limits";
        return false;
    }

    const size_t count = headers.size();
    digests_out.resize(count);
    payloads_out.resize(count);
    for (size_t first = 0; first < count; first += window) {
        const uint32_t this_window = static_cast<uint32_t>(std::min<size_t>(window, count - first));
        if (!ComputeBatchWindow(ctx, headers, first, this_window, n, m, use_tensor_gemm,
                                digests_out, payloads_out, error)) {
            return false;
        }
    }
    return true;
}

// Replay a small batched window through the GPU and require byte-identical
// digests AND payloads vs the CPU consensus reference
// matmul::v4::bmx4::ComputeDigestBMX4C for EVERY header (there is no separate
// batched CPU BMX4-C miner: the per-header reference IS the contract). Caller
// holds ctx.batch_mutex.
bool SelfTestCase(MetalBmx4Context& ctx, uint32_t n, uint32_t count,
                  uint32_t window_override, bool use_tensor_gemm, std::string& error)
{
    uint32_t m = 0;
    if (!matmul::v4::bmx4::ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) {
        error = "self-test dimensions invalid";
        return false;
    }

    // Deterministic non-trivial template: all-default fields still yield
    // pseudorandom operands because seeds are SHA256 derivations of the
    // header hash. Every node runs the identical vector. Distinct nonces
    // exercise the nonce-fresh Bhat/sigma while sharing one template.
    const CBlockHeader tmpl{};
    std::vector<CBlockHeader> headers(count, tmpl);
    for (uint32_t i = 0; i < count; ++i) {
        headers[i].nNonce64 = 1 + i;
        headers[i].nNonce = static_cast<uint32_t>(headers[i].nNonce64);
    }

    std::vector<uint256> cpu_digests(count);
    std::vector<std::vector<unsigned char>> cpu_payloads(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (!matmul::v4::bmx4::ComputeDigestBMX4C(headers[i], n, cpu_digests[i], cpu_payloads[i])) {
            error = "self-test CPU reference failed";
            return false;
        }
    }

    // Drop any cached template so THIS tier's GEMM also computes P = U*Ahat
    // (a cache built by the other tier would mask an inexact P path).
    ctx.batch_template_valid = false;
    ctx.batch_buf_v = nil;
    for (auto& plane : ctx.batch_p_plane) {
        plane = nil;
    }

    std::vector<uint256> digests;
    std::vector<std::vector<unsigned char>> payloads;
    if (!ComputeDigestsImpl(ctx, headers, n, m, use_tensor_gemm, window_override,
                            digests, payloads, error)) {
        return false;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (digests[i] != cpu_digests[i] || payloads[i] != cpu_payloads[i]) {
            error = "self-test digest/payload mismatch vs CPU BMX4-C reference";
            return false;
        }
    }
    return true;
}

// One-time bit-exactness gate, mirroring the v4.1 batched gate: the ALU path
// must reproduce ComputeDigestBMX4C on both self-test shapes (count = 3 with
// window_override = 2 exercises the window loop plus a remainder window) or
// the whole backend is reported unavailable. The tensor-ops path must
// additionally pass on both shapes or it is dropped (silently falling back to
// the ALU tier), satisfying the C-1' "no conforming exact path => no GPU
// path" rule without ever emitting an unverified digest.
void RunSelfTest(MetalBmx4Context& ctx)
{
    std::lock_guard<std::mutex> lock(ctx.batch_mutex);
    std::string error;
    if (!SelfTestCase(ctx, kSelfTestSmallN, /*count=*/3, /*window_override=*/2,
                      /*use_tensor_gemm=*/false, error) ||
        !SelfTestCase(ctx, kSelfTestTensorN, /*count=*/3, /*window_override=*/0,
                      /*use_tensor_gemm=*/false, error)) {
        ctx.self_test_passed = false;
        ctx.self_test_error = "alu:" + error;
        ctx.gemm_tensor_pipeline = nil;
        return;
    }
    ctx.self_test_passed = true;

    if (ctx.gemm_tensor_pipeline != nil) {
        if (!SelfTestCase(ctx, kSelfTestSmallN, /*count=*/3, /*window_override=*/2,
                          /*use_tensor_gemm=*/true, error) ||
            !SelfTestCase(ctx, kSelfTestTensorN, /*count=*/3, /*window_override=*/2,
                          /*use_tensor_gemm=*/true, error)) {
            ctx.gemm_tensor_pipeline = nil;
            ctx.tensor_path_reason = "self_test_failed:" + error;
            bool expected{false};
            if (g_logged_tensor_self_test.compare_exchange_strong(expected, true)) {
                LogPrintf("MATMUL v4.2 BMX4-C WARNING: Metal tensor-ops GEMM failed bit-exactness self-test (%s); using integer-ALU kernels\n", error);
            }
        }
    }

    // The self-test cache holds tiny self-test dimensions; drop it so the
    // first production call builds its own template state.
    ctx.batch_template_valid = false;
    ctx.batch_buf_v = nil;
    for (auto& plane : ctx.batch_p_plane) {
        plane = nil;
    }
}

bool EnsureReady(MetalBmx4Context& ctx, std::string& reason)
{
    if (!ctx.error.empty()) {
        reason = ctx.error;
        return false;
    }
    std::call_once(ctx.self_test_once, [&ctx] { RunSelfTest(ctx); });
    if (!ctx.self_test_passed) {
        reason = ctx.self_test_error.empty() ? "self-test failed" : ctx.self_test_error;
        return false;
    }
    return true;
}

} // namespace

namespace matmul_v4::bmx4::metal {

AccelProbe ProbeAcceleration()
{
    AccelProbe probe;
    if (EnvFlagDisabled("BTX_MATMUL_V4_BMX4_METAL")) {
        probe.reason = "disabled_by_environment";
        return probe;
    }
    auto& ctx = GetContext();
    std::string reason;
    if (!EnsureReady(ctx, reason)) {
        probe.reason = reason;
        return probe;
    }
    probe.available = true;
    probe.device_name = ctx.device_name;
    probe.gemm_path = ctx.gemm_tensor_pipeline != nil ? "tensor_ops" : "alu";
    probe.reason = ctx.gemm_tensor_pipeline != nil
        ? "metal4_tensor_ops_self_test_passed"
        : ("alu_self_test_passed(tensor:" + ctx.tensor_path_reason + ")");
    return probe;
}

} // namespace matmul_v4::bmx4::metal

namespace matmul_v4::metal {

bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
    std::vector<uint256>& digests_out, std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();
    if (EnvFlagDisabled("BTX_MATMUL_V4_BMX4_METAL")) {
        return false;
    }
    if (headers.empty()) {
        return false;
    }

    // ENC-BMX4C dimension gate: the v4.1 ValidateDims checks PLUS n % 32 == 0
    // (E8M0 block scales) and 288*n <= 2^23-1 (remainder-top totality) --
    // exactly what the CPU reference ComputeDigestBMX4C validates.
    uint32_t m = 0;
    if (!matmul::v4::bmx4::ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) {
        return false;
    }
    if (rounds == 0) {
        // API symmetry with the reference entry points (the miner runs no
        // Freivalds rounds, but rounds must be a valid parameter).
        return false;
    }

    auto& ctx = GetContext();
    std::string reason;
    if (!EnsureReady(ctx, reason)) {
        LogUnavailableOnce(reason);
        return false;
    }

    // The tensor-ops GEMM accumulates over K = n; ValidateDimsBMX4C already
    // pins n % 32 == 0, so every accepted shape is tensor-eligible. The check
    // is kept for defense in depth / symmetry with the v4.1 backend.
    const bool use_tensor_gemm = ctx.gemm_tensor_pipeline != nil && (n % 32u) == 0u;

    std::lock_guard<std::mutex> lock(ctx.batch_mutex);
    std::string error;
    if (!ComputeDigestsImpl(ctx, headers, n, m, use_tensor_gemm, /*window_override=*/0,
                            digests_out, payloads_out, error)) {
        LogUnavailableOnce(error);
        digests_out.clear();
        payloads_out.clear();
        return false;
    }
    return true;
}

} // namespace matmul_v4::metal
