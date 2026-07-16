// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal host glue for the MatMul v4 miner backend.
//
// Pipeline (mirrors matmul_v4::ComputeDigest in matmul/pow_v4.cpp exactly):
//   1. HOST  : derive sigma / operand / projector seeds and expand A, B, U, V
//              with the consensus CPU code (matmul::v4::ExpandOperand /
//              ExpandProjector). Sharing the host expansion code with the CPU
//              reference removes any possibility of oracle divergence.
//   2. GPU   : UA = U*A and BV = B*V as exact INT8 -> INT32 integer GEMMs
//              (portable integer-ALU kernel everywhere; Metal 4
//              mpp::tensor_ops::matmul2d INT8/INT32 on M5-class devices).
//   3. GPU   : Chat = (UA * BV) mod q, q = 2^61 - 1, in exact 64-bit integer
//              arithmetic (see matmul_v4_accel_kernels.metal for the proof of
//              bit-equivalence with matmul::v4::ComputeSketch).
//   4. HOST  : canonicality-check the returned words (< q), serialize with
//              matmul::v4::SerializeSketch and digest with
//              matmul::v4::ComputeSketchDigest -- the identical consensus
//              byte path used by the CPU miner.
//
// BIT-EXACTNESS GATE: on first use this backend replays a full small-n digest
// through the GPU and compares digest AND payload byte-for-byte against
// matmul_v4::ComputeDigest. The tensor-ops path is only enabled if it passes
// on this device; if even the ALU path fails, the backend reports itself
// unavailable and every call returns false (CPU fallback). No float, no
// approximation, ever (design spec §B.6).
//
// BATCHED-SKETCH PATH (§K.2b, Appendix C-13; ComputeDigestsBatchedAccel): the
// cross-nonce miner mirror of matmul::v4::BatchedSketchMiner::Mine. Template-
// scoped A/U/V are expanded ONCE on the host and P = U*A is one device GEMM
// (cached across calls by template hash); per window the nonce-fresh B_i are
// expanded on the host, Q_i = B_i*V runs as ONE stacked GEMM, and the per-
// nonce combines fuse into ONE LARGE DENSE GEMM P * [Q_1 | ... | Q_Q]
// evaluated as the 16 limb-pair INT8->INT32 GEMMs of Appendix C-13 (device
// limb split replicates the CPU digit recurrence bit-for-bit) with the
// shifted mod-q recombine on the integer ALU. Gated by its own one-time
// bit-exactness self-test against the CPU batched reference.

#include <metal/matmul_v4_accel.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_batch.h>
#include <matmul/pow_v4.h>
#include <primitives/block.h>
#include <logging.h>
#include <uint256.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <limits.h>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include <mach-o/dyld.h>

namespace {

// Must stay byte-identical to metal/matmul_v4_accel_kernels.metal (inline
// compile fallback when no precompiled metallib is found; same convention as
// the v3 backend in metal/matmul_accel.mm).
constexpr const char* KERNEL_SOURCE = R"METAL(
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

// ---------------------------------------------------------------------------
// Batched-sketch miner kernels (design spec §K.2b, Appendix C-13).
//
// The batched miner evaluates the ONE LARGE DENSE COMBINE
//     Chat_wide = P * Qstack   (m x n by n x q_cols, q_cols = Q*m)
// through the limb-tensor path: P and Qstack are split ENTRYWISE into 4
// balanced base-2^7 digit planes (each plane a valid s8 GEMM operand), the 16
// limb-pair products S_ij = P_i * Q_j run on the exact INT8 -> INT32 GEMM
// kernels above (integer-ALU everywhere, tensor-ops on M5-class parts), and
// the shifted mod-q recombine
//     Chat = sum_ij 2^(7*(i+j)) * S_ij   (mod q)
// folds every S_ij into the running canonical residue on the integer ALU.
// All kernels below are portable integer MSL (no Metal 4 features) and run
// bit-exactly on every Metal GPU family.
// ---------------------------------------------------------------------------

// Entrywise balanced base-2^7 digit decomposition. MUST match the CPU
// reference DecomposeLimbPlanes (matmul/matmul_v4.cpp, used by
// ComputeCombineLimbTensorStacked) digit-for-digit:
//     d_l = ((x + 64) & 127) - 64;   x = (x - d_l) / 128;
// The bitwise AND acts on the 32-bit two's-complement value exactly as on the
// host (C++20 mandates two's complement; MSL int is 32-bit two's complement),
// and (x - d_l) is an exact multiple of 128, so the truncating division is
// the exact quotient. The decomposition is total for |x| < 128^4/2 = 2^27,
// which CheckCombineLimbBound guarantees for every P/Q entry
// (15,625*n < 2^27 for all n <= 8589).
inline void btx_v4_limb_digits(int x, thread int* d)
{
    for (uint l = 0; l < 4u; ++l) {
        d[l] = ((x + 64) & 127) - 64;
        x = (x - d[l]) / 128;
    }
}

// P (rows x cols, row-major exact s32) -> four s8 digit planes, same layout.
struct LimbSplitParams {
    uint rows;
    uint cols;
};

kernel void matmul_v4_limb_split(
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
    btx_v4_limb_digits(src[idx], d);
    plane0[idx] = (char)d[0];
    plane1[idx] = (char)d[1];
    plane2[idx] = (char)d[2];
    plane3[idx] = (char)d[3];
}

// Qvert ((Q*n) x m, row-major exact s32 -- the output of the stacked GEMM
// [B_1; ...; B_Q] * V) -> four s8 digit planes in the HORIZONTAL-stack layout
// n x q_cols (q_cols = Q*m, column block i = the digits of Q_i = B_i*V).
// This is exactly the Qstack operand layout the CPU reference
// ComputeCombineLimbTensorStacked consumes; the digit arithmetic is
// entrywise, so relocating an entry changes no digit.
struct LimbSplitQParams {
    uint n;      // rows of each Q_i
    uint m;      // columns of each Q_i (sketch dimension)
    uint q_cols; // Q * m
};

kernel void matmul_v4_limb_split_qstack(
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
    btx_v4_limb_digits(qvert[src_idx], d);
    plane0[dst_idx] = (char)d[0];
    plane1[dst_idx] = (char)d[1];
    plane2[dst_idx] = (char)d[2];
    plane3[dst_idx] = (char)d[3];
}

// Shifted mod-q fold of one limb-pair product S_ij into the running Chat:
//     chat[idx] = FqAdd(chat[idx], FqMul(2^shift, FqFromSigned(s[idx])))
// with shift = 7*(i+j) in {0, 7, ..., 42}.
//
// Equivalence with the CPU chain (matmul/int8_field.cpp), term by term:
//   * FqFromSigned(s32 v): |v| <= n*64^2 < 2^31 < q, so the canonical residue
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
//     operands.
//   * FqAdd: chat, term < q so chat + term < 2^62 never wraps the u64
//     accumulator; one conditional subtract restores canonical form --
//     exactly the host FqAdd.
struct LimbFoldParams {
    uint rows;  // m
    uint cols;  // q_cols
    uint shift; // 7 * (limb_i + limb_j), in {0, 7, ..., 42}
};

kernel void matmul_v4_limb_fold_mod_q(
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
)METAL";

struct GemmParams {
    uint32_t m_rows{0};
    uint32_t k{0};
    uint32_t n_cols{0};
};

struct CombineParams {
    uint32_t m{0};
    uint32_t n{0};
};

// Host mirrors of the batched-sketch kernel parameter blocks (§K.2b/C-13).
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
// Self-test dimensions: one shape exercising partial 16x16 / 32x32 edge tiles
// and one tensor-eligible shape (n % 32 == 0). Both satisfy ValidateDims
// (n % 8 == 0, accumulation bound).
constexpr uint32_t kSelfTestEdgeN = 40;
constexpr uint32_t kSelfTestTensorN = 64;

/** Default nonce-window size Q for the batched path (§K.2b), overridable with
 *  BTX_MATMUL_V4_METAL_BATCH (clamped to [1, matmul::v4::kMaxMinerBatch] and
 *  then to what the device's buffer limits / working set can hold). Apple
 *  parts share system memory, so the window is deliberately smaller than the
 *  CUDA default (kDefaultBatchedWindow = 64 on discrete-VRAM parts): at
 *  n=4096 (m=1024) one in-flight nonce costs ~60.5 MiB of device buffers
 *  (Bstack 16 MiB + Qvert 16 MiB + Qstack digit planes 16 MiB + S 4 MiB +
 *  Chat 8 MiB + ~0.5 MiB serialized-payload share), so Q=8 is ~484 MiB of
 *  window buffers plus ~20 MiB of template-scoped state (V + the four P digit
 *  planes) -- comfortable on an 8 GB unified-memory Mac while already making
 *  the stacked combine GEMM (m x Q*m x n = 1024 x 8192 x 4096) dense and
 *  square-ish. Benchmarks (B2g/B2b) should sweep this upward on big-memory
 *  parts. */
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

std::vector<std::string> MatMulV4MetallibCandidatePaths()
{
    std::vector<std::string> paths;
    AppendUniquePath(paths, std::getenv("BTX_MATMUL_V4_METALLIB_PATH"));

    if (const auto executable_dir = ExecutableDirectory()) {
        const std::string packaged_path = *executable_dir + "/metal/matmul_v4_accel_kernels.metallib";
        AppendUniquePath(paths, packaged_path.c_str());
    }

#if defined(BTX_MATMUL_V4_METALLIB_PATH)
    AppendUniquePath(paths, BTX_MATMUL_V4_METALLIB_PATH);
#endif
    return paths;
}

bool EnvFlagDisabled(const char* name)
{
    const char* env = std::getenv(name);
    return env != nullptr && env[0] == '0';
}

// Singleton Metal state for the v4 backend. Command queues and pipeline state
// objects are documented thread-safe in Metal; every ComputeDigestAccel call
// uses its own buffers and command buffer, so no per-call locking is needed.
struct MetalV4Context {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> gemm_alu_pipeline{nil};
    id<MTLComputePipelineState> combine_pipeline{nil};
    // Metal 4 / M5-class GPU-neural-accelerator GEMM; nil when the runtime
    // compiler, OS, or device does not support mpp::tensor_ops, or when the
    // path failed the bit-exactness self-test.
    id<MTLComputePipelineState> gemm_tensor_pipeline{nil};
    std::string tensor_path_reason;
    std::string error;
    std::string device_name;

    // One-time full-pipeline self-test vs the CPU reference (see SelfTest()).
    std::once_flag self_test_once;
    bool self_test_passed{false};
    std::string self_test_error;

    // ---- Batched-sketch path (§K.2b, ComputeDigestsBatchedAccel) ----
    // Portable kernels for the limb-tensor combine. Created non-fatally: if a
    // stale precompiled metallib lacks them, only the batched path is
    // disabled, never the per-nonce path.
    id<MTLComputePipelineState> limb_split_pipeline{nil};
    id<MTLComputePipelineState> limb_split_qstack_pipeline{nil};
    id<MTLComputePipelineState> limb_fold_pipeline{nil};
    std::string batch_pipeline_error;

    // One-time batched bit-exactness gate vs matmul::v4::BatchedSketchMiner.
    std::once_flag batch_self_test_once;
    bool batch_self_test_passed{false};
    std::string batch_self_test_error;
    // Tensor-ops GEMM additionally validated on the batched shapes before use.
    bool batch_tensor_ok{false};

    // Template-scoped cache for the batched miner (guarded by batch_mutex):
    // V (s8 n x m) and the four balanced base-2^7 digit planes of P = U*A
    // (s8 m x n each), keyed by (template hash, n). Mirrors the amortization
    // of matmul::v4::BatchedSketchMiner across successive nonce windows.
    std::mutex batch_mutex;
    bool batch_template_valid{false};
    uint256 batch_template_hash;
    uint32_t batch_template_n{0};
    id<MTLBuffer> batch_buf_v{nil};
    id<MTLBuffer> batch_p_plane[4]{nil, nil, nil, nil};

    MetalV4Context()
    {
        @autoreleasepool {
            // MTLCreateSystemDefaultDevice() is restricted to interactive apps
            // on macOS 14+; MTLCopyAllDevices() works from CLI/daemon contexts
            // (same rationale as the v3 backend in metal/matmul_accel.mm).
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
            for (const auto& candidate_path : MatMulV4MetallibCandidatePaths()) {
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
                                             : "Failed to compile Metal MatMul v4 kernel source";
                return;
            }

            gemm_alu_pipeline = MakePipeline(library, @"matmul_v4_s8_gemm_s32", error);
            if (gemm_alu_pipeline == nil) return;
            combine_pipeline = MakePipeline(library, @"matmul_v4_combine_mod_q", error);
            if (combine_pipeline == nil) return;

            // Batched-sketch kernels (§K.2b). Failure here (e.g. a stale
            // precompiled metallib predating the batched path) is recorded in
            // batch_pipeline_error and disables ONLY the batched entry point.
            limb_split_pipeline = MakePipeline(library, @"matmul_v4_limb_split", batch_pipeline_error);
            if (limb_split_pipeline != nil) {
                limb_split_qstack_pipeline =
                    MakePipeline(library, @"matmul_v4_limb_split_qstack", batch_pipeline_error);
            }
            if (limb_split_qstack_pipeline != nil) {
                limb_fold_pipeline = MakePipeline(library, @"matmul_v4_limb_fold_mod_q", batch_pipeline_error);
            }

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
        // (equally bit-exact) integer-ALU path. BTX_MATMUL_V4_TENSOR_OPS=0
        // forces the ALU path.
        if (EnvFlagDisabled("BTX_MATMUL_V4_TENSOR_OPS")) {
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
            MakePipeline(tensor_library, @"matmul_v4_s8_gemm_s32_tensor", pipeline_error);
        if (pipeline == nil) {
            // Function absent (BTX_MATMUL_V4_HAVE_TENSOR_OPS not defined by
            // the runtime compiler) or pipeline creation failed on this GPU
            // family: no tensor path on this device.
            tensor_path_reason = pipeline_error;
            return;
        }
        gemm_tensor_pipeline = pipeline;
        tensor_path_reason = "ok";
    }
};

MetalV4Context& GetContext()
{
    static MetalV4Context context;
    return context;
}

std::atomic_bool g_logged_unavailable{false};
std::atomic_bool g_logged_self_test{false};

void LogUnavailableOnce(const std::string& reason)
{
    bool expected{false};
    if (g_logged_unavailable.compare_exchange_strong(expected, true)) {
        LogPrintf("MATMUL v4 WARNING: Metal backend unavailable (%s); falling back to CPU\n", reason);
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

// Core GPU digest computation. `use_tensor_gemm` selects the Metal 4
// tensor-ops GEMM (caller must have verified availability); the combine stage
// always runs the exact 64-bit mod-q ALU kernel. Returns false with `error`
// set on any failure -- never a wrong result.
bool ComputeDigestImpl(MetalV4Context& ctx,
                       const CBlockHeader& header,
                       uint32_t n,
                       uint32_t m,
                       bool use_tensor_gemm,
                       uint256& digest_out,
                       std::vector<unsigned char>& payload_out,
                       std::string& error)
{
    @autoreleasepool {
        // 1. Host-side consensus derivation and expansion (identical code to
        //    matmul_v4::ComputeDigest -- the same functions, not a re-impl).
        const uint256 sigma = matmul::v4::DeriveSigma(header);
        const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
        const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
        const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);

        const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);
        const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
        const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n);
        const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m);

        const size_t nn = static_cast<size_t>(n) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t mm = static_cast<size_t>(m) * m;

        const NSUInteger max_len = ctx.device.maxBufferLength;
        if (nn > max_len || mn * sizeof(int32_t) > max_len || mm * sizeof(uint64_t) > max_len) {
            error = "requested dimension exceeds Metal device buffer limits";
            return false;
        }

        id<MTLBuffer> buf_a = [ctx.device newBufferWithBytes:A.data() length:nn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_b = [ctx.device newBufferWithBytes:B.data() length:nn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_u = [ctx.device newBufferWithBytes:U.data() length:mn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_v = [ctx.device newBufferWithBytes:V.data() length:mn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_ua = [ctx.device newBufferWithLength:mn * sizeof(int32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_bv = [ctx.device newBufferWithLength:mn * sizeof(int32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_chat = [ctx.device newBufferWithLength:mm * sizeof(uint64_t) options:MTLResourceStorageModeShared];

        const GemmParams ua_params{.m_rows = m, .k = n, .n_cols = n};
        const GemmParams bv_params{.m_rows = n, .k = n, .n_cols = m};
        const CombineParams combine_params{.m = m, .n = n};
        id<MTLBuffer> buf_ua_params = [ctx.device newBufferWithBytes:&ua_params length:sizeof(ua_params) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_bv_params = [ctx.device newBufferWithBytes:&bv_params length:sizeof(bv_params) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_combine_params = [ctx.device newBufferWithBytes:&combine_params length:sizeof(combine_params) options:MTLResourceStorageModeShared];

        if (buf_a == nil || buf_b == nil || buf_u == nil || buf_v == nil ||
            buf_ua == nil || buf_bv == nil || buf_chat == nil ||
            buf_ua_params == nil || buf_bv_params == nil || buf_combine_params == nil) {
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

        // 2. UA = U * A (m x n s32) and BV = B * V (n x m s32). Successive
        //    encoders in one command buffer execute in order, so the combine
        //    stage observes completed UA/BV.
        if (!EncodeGemm(command, gemm_pipeline, use_tensor_gemm, ua_params, buf_ua_params, buf_u, buf_a, buf_ua, error)) return false;
        if (!EncodeGemm(command, gemm_pipeline, use_tensor_gemm, bv_params, buf_bv_params, buf_b, buf_v, buf_bv, error)) return false;

        // 3. Chat = (UA * BV) mod q -- exact 64-bit integer ALU kernel.
        {
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            if (encoder == nil) {
                error = "Failed to create Metal compute encoder";
                return false;
            }
            [encoder setComputePipelineState:ctx.combine_pipeline];
            [encoder setBuffer:buf_combine_params offset:0 atIndex:0];
            [encoder setBuffer:buf_ua offset:0 atIndex:1];
            [encoder setBuffer:buf_bv offset:0 atIndex:2];
            [encoder setBuffer:buf_chat offset:0 atIndex:3];
            const MTLSize groups = MTLSizeMake((m + kGemmTile - 1) / kGemmTile,
                                               (m + kGemmTile - 1) / kGemmTile, 1);
            const MTLSize group_size = MTLSizeMake(kGemmTile, kGemmTile, 1);
            [encoder dispatchThreadgroups:groups threadsPerThreadgroup:group_size];
            [encoder endEncoding];
        }

        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            error = command.error != nil
                ? std::string{"Metal command buffer failed: "} + [[command.error localizedDescription] UTF8String]
                : "Metal command buffer did not complete";
            return false;
        }

        // 4. Canonicality check + consensus serialization/digest on the host.
        std::vector<matmul::v4::Fq> chat(mm);
        std::memcpy(chat.data(), [buf_chat contents], mm * sizeof(uint64_t));
        for (const auto word : chat) {
            if (word >= matmul::int8_field::kFieldPrime) {
                // Defense in depth: the combine kernel proves words < q, so a
                // non-canonical word means a malfunctioning device/driver.
                error = "Metal produced a non-canonical F_q word";
                return false;
            }
        }

        payload_out = matmul::v4::SerializeSketch(chat);
        digest_out = matmul::v4::ComputeSketchDigest(sigma, payload_out);
        return true;
    }
}

// Replay one full digest through the GPU and require byte-identical digest
// AND payload vs the CPU consensus reference matmul_v4::ComputeDigest.
bool SelfTestCase(MetalV4Context& ctx, uint32_t n, bool use_tensor_gemm, std::string& error)
{
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul_v4::kTileB, m)) {
        error = "self-test dimensions invalid";
        return false;
    }

    // Deterministic non-trivial header: all-default fields still yield
    // pseudorandom operands because seeds are SHA256 derivations of the
    // header hash. Every node runs the identical vector.
    const CBlockHeader header{};

    uint256 cpu_digest;
    std::vector<unsigned char> cpu_payload;
    if (!matmul_v4::ComputeDigest(header, n, /*rounds=*/1, cpu_digest, cpu_payload)) {
        error = "self-test CPU reference failed";
        return false;
    }

    uint256 gpu_digest;
    std::vector<unsigned char> gpu_payload;
    if (!ComputeDigestImpl(ctx, header, n, m, use_tensor_gemm, gpu_digest, gpu_payload, error)) {
        return false;
    }
    if (gpu_digest != cpu_digest || gpu_payload != cpu_payload) {
        error = "self-test digest/payload mismatch vs CPU reference";
        return false;
    }
    return true;
}

// One-time bit-exactness gate. The ALU path must pass on an edge-tile shape
// and a tensor-eligible shape or the whole backend is reported unavailable.
// The tensor path must pass on this device or it is dropped (silently falling
// back to the ALU path), satisfying the "no conforming integer path => no GPU
// path" rule without ever emitting an unverified digest.
void RunSelfTest(MetalV4Context& ctx)
{
    std::string error;
    if (!SelfTestCase(ctx, kSelfTestEdgeN, /*use_tensor_gemm=*/false, error) ||
        !SelfTestCase(ctx, kSelfTestTensorN, /*use_tensor_gemm=*/false, error)) {
        ctx.self_test_passed = false;
        ctx.self_test_error = "alu:" + error;
        ctx.gemm_tensor_pipeline = nil;
        return;
    }
    ctx.self_test_passed = true;

    if (ctx.gemm_tensor_pipeline != nil) {
        if (!SelfTestCase(ctx, kSelfTestTensorN, /*use_tensor_gemm=*/true, error)) {
            ctx.gemm_tensor_pipeline = nil;
            ctx.tensor_path_reason = "self_test_failed:" + error;
            bool expected{false};
            if (g_logged_self_test.compare_exchange_strong(expected, true)) {
                LogPrintf("MATMUL v4 WARNING: Metal tensor-ops GEMM failed bit-exactness self-test (%s); using integer-ALU kernels\n", error);
            }
        }
    }
}

bool EnsureReady(MetalV4Context& ctx, std::string& reason)
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

// ===========================================================================
// Batched-sketch path (§K.2b, Appendix C-13) -- ComputeDigestsBatchedAccel.
//
// Device mirror of matmul::v4::BatchedSketchMiner::Mine, bit-for-bit:
//   TEMPLATE (cached across calls, keyed by template hash):
//     host   : expand A (n x n), U (m x n), V (n x m)   [consensus routines]
//     device : P = U*A (one exact INT8->INT32 GEMM, m x n x n)
//     device : split P into 4 balanced base-2^7 digit planes (C-13)
//   PER WINDOW of Q nonces:
//     host   : sigma_i = DeriveSigma(header_i); expand B_i (nonce-fresh)
//     device : Qvert = [B_1; ...; B_Q] * V (one stacked GEMM, Q*n x n x m)
//     device : split Qvert into 4 digit planes laid out as the horizontal
//              stack Qstack = [Q_1 | ... | Q_Q] (n x Q*m)
//     device : 16 limb-pair GEMMs S_ij = P_i * Q_j (m x Q*m x n) + shifted
//              mod-q folds Chat += 2^(7(i+j)) * S_ij (integer ALU)
//     host   : slice column block i, canonicality-check, SerializeSketch,
//              ComputeSketchDigest -- the identical consensus byte path.
//
// The GEMMs run on the same two device tiers as the per-nonce path: the
// portable integer-ALU kernel on every Metal GPU family (pre-M5), or Metal 4
// mpp::tensor_ops::matmul2d on M5-class GPU neural accelerators -- both exact
// INT8->INT32, both gated by bit-exactness self-tests. No floating point
// anywhere; a template-hash mismatch or any Metal error fails closed.
// ===========================================================================

std::atomic_bool g_logged_batch_self_test{false};

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
    const char* env = std::getenv("BTX_MATMUL_V4_METAL_BATCH");
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

// Largest per-window buffer sizes for a window of `w` nonces (bytes).
struct BatchWindowBytes {
    uint64_t bstack;  // [B_1; ...; B_Q], s8, w*n*n
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
uint32_t ResolveBatchWindowSize(MetalV4Context& ctx, uint32_t requested, uint32_t n, uint32_t m)
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

// Build (or reuse) the template-scoped device state: V and the four digit
// planes of P = U*A. Identical host derivations to BatchedSketchMiner's
// constructor; P itself is one exact INT8->INT32 GEMM on device (same
// integers as the CPU ComputeProjectedLeft by exactness + associativity of
// integer addition), then split with the C-13 digit recurrence on device.
// Caller holds ctx.batch_mutex.
bool PrepareBatchTemplate(MetalV4Context& ctx, const CBlockHeader& header,
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
        // Template-scoped consensus derivations (§A.2 v4.1, invariant I1'):
        // A, U, V bind the template hash only, so any header of the window
        // yields the identical seeds (DeriveOperandSeed/DeriveProjectorSeeds
        // project onto ComputeTemplateHash internally).
        const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
        const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);
        const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);
        const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n);
        const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m);

        const size_t nn = static_cast<size_t>(n) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const NSUInteger max_len = ctx.device.maxBufferLength;
        if (nn > max_len || mn * sizeof(int32_t) > max_len) {
            error = "requested dimension exceeds Metal device buffer limits";
            return false;
        }

        id<MTLBuffer> buf_a = [ctx.device newBufferWithBytes:A.data() length:nn options:MTLResourceStorageModeShared];
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
bool ComputeBatchWindow(MetalV4Context& ctx,
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
        // every (i, j) pair needs its own little params buffer.
        id<MTLBuffer> fold_params[16];
        for (uint32_t i = 0; i < 4; ++i) {
            for (uint32_t j = 0; j < 4; ++j) {
                const LimbFoldParams fp{.rows = m, .cols = q_cols, .shift = 7u * (i + j)};
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
        // (nonce-fresh, I1'); B is the nonce-fresh operand. Identical
        // routines -- not re-implementations -- to the CPU reference.
        std::vector<uint256> sigmas(window);
        int8_t* bstack_ptr = static_cast<int8_t*>([buf_bstack contents]);
        for (uint32_t w = 0; w < window; ++w) {
            const CBlockHeader& header = headers[first + w];
            sigmas[w] = matmul::v4::DeriveSigma(header);
            const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
            const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
            std::memcpy(bstack_ptr + static_cast<size_t>(w) * nn, B.data(), nn);
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

        // Qvert = [B_1; ...; B_Q] * V, one stacked exact GEMM (Q*n x n x m).
        if (!EncodeGemm(command, gemm_pipeline, use_tensor_gemm, qv_params, buf_qv_params,
                        buf_bstack, ctx.batch_buf_v, buf_qvert, error)) {
            return false;
        }
        // Digit planes of Qstack = [Q_1 | ... | Q_Q] (n x q_cols layout).
        if (!EncodeGrid2D(command, ctx.limb_split_qstack_pipeline, buf_split_params,
                          {buf_qvert, q_planes[0], q_planes[1], q_planes[2], q_planes[3]},
                          /*grid_cols=*/q_cols, /*grid_rows=*/n, error)) {
            return false;
        }
        // ONE LARGE DENSE COMBINE (C-13): 16 limb-pair GEMMs S_ij = P_i * Q_j
        // (m x q_cols x n), each folded into Chat with weight 2^(7(i+j)) mod q.
        // Encoders in one command buffer execute in order, so reusing the one
        // S buffer across pairs is race-free.
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
bool ComputeDigestsBatchedImpl(MetalV4Context& ctx,
                               const std::vector<CBlockHeader>& headers,
                               uint32_t n, uint32_t m, bool use_tensor_gemm,
                               uint32_t window_override,
                               std::vector<uint256>& digests_out,
                               std::vector<std::vector<unsigned char>>& payloads_out,
                               std::string& error)
{
    // Fail closed on a template mismatch, exactly as BatchedSketchMiner::Mine:
    // combining a stale template's cached A/U/V/P with a fresh header would
    // produce digests that are NOT the consensus digests for that header.
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
// digests AND payloads vs the CPU batched reference (which the unit tests pin
// to the per-nonce consensus digest for every nonce). Caller holds batch_mutex.
bool BatchSelfTestCase(MetalV4Context& ctx, uint32_t n, uint32_t count,
                       uint32_t window_override, bool use_tensor_gemm, std::string& error)
{
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul_v4::kTileB, m) || !matmul::v4::CheckCombineLimbBound(n)) {
        error = "self-test dimensions invalid";
        return false;
    }

    // Deterministic non-trivial template, same rationale as SelfTestCase.
    const CBlockHeader tmpl{};
    const matmul::v4::BatchedSketchMiner miner(tmpl, n);
    if (!miner.Valid()) {
        error = "self-test CPU batched miner invalid";
        return false;
    }
    std::vector<CBlockHeader> headers(count, tmpl);
    for (uint32_t i = 0; i < count; ++i) {
        headers[i].nNonce64 = 1 + i;
        headers[i].nNonce = static_cast<uint32_t>(headers[i].nNonce64);
    }
    std::vector<matmul::v4::BatchNonceResult> cpu;
    if (!miner.Mine(headers, cpu) || cpu.size() != count) {
        error = "self-test CPU batched reference failed";
        return false;
    }

    std::vector<uint256> digests;
    std::vector<std::vector<unsigned char>> payloads;
    if (!ComputeDigestsBatchedImpl(ctx, headers, n, m, use_tensor_gemm, window_override,
                                   digests, payloads, error)) {
        return false;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (digests[i] != cpu[i].digest || payloads[i] != cpu[i].payload) {
            error = "batched self-test digest/payload mismatch vs CPU reference";
            return false;
        }
    }

    // Belt and braces: also pin one entry directly against the per-nonce
    // consensus reference (independent of the batched CPU code path).
    uint256 ref_digest;
    std::vector<unsigned char> ref_payload;
    if (!matmul_v4::ComputeDigest(headers[0], n, /*rounds=*/1, ref_digest, ref_payload) ||
        ref_digest != digests[0] || ref_payload != payloads[0]) {
        error = "batched self-test mismatch vs per-nonce consensus reference";
        return false;
    }
    return true;
}

// One-time batched bit-exactness gate, mirroring RunSelfTest: the ALU path
// must reproduce the CPU batched reference on an edge-tile shape and a
// tensor-eligible shape (window_override = 2 with count = 3 exercises the
// window loop plus a remainder window) or the batched path is reported
// unavailable. The tensor-ops path must additionally pass on the batched
// shapes or it is dropped for the batched path only (ALU fallback).
void RunBatchSelfTest(MetalV4Context& ctx)
{
    std::lock_guard<std::mutex> lock(ctx.batch_mutex);
    std::string error;
    if (!BatchSelfTestCase(ctx, kSelfTestEdgeN, /*count=*/3, /*window_override=*/2,
                           /*use_tensor_gemm=*/false, error) ||
        !BatchSelfTestCase(ctx, kSelfTestTensorN, /*count=*/3, /*window_override=*/0,
                           /*use_tensor_gemm=*/false, error)) {
        ctx.batch_self_test_passed = false;
        ctx.batch_self_test_error = "batch_alu:" + error;
        return;
    }
    ctx.batch_self_test_passed = true;

    if (ctx.gemm_tensor_pipeline != nil) {
        if (BatchSelfTestCase(ctx, kSelfTestTensorN, /*count=*/3, /*window_override=*/2,
                              /*use_tensor_gemm=*/true, error)) {
            ctx.batch_tensor_ok = true;
        } else {
            ctx.batch_tensor_ok = false;
            bool expected{false};
            if (g_logged_batch_self_test.compare_exchange_strong(expected, true)) {
                LogPrintf("MATMUL v4 WARNING: Metal tensor-ops batched GEMM failed bit-exactness self-test (%s); using integer-ALU kernels for the batched path\n", error);
            }
        }
    }
}

bool EnsureBatchReady(MetalV4Context& ctx, std::string& reason)
{
    if (!EnsureReady(ctx, reason)) {
        return false;
    }
    if (ctx.limb_split_pipeline == nil || ctx.limb_split_qstack_pipeline == nil ||
        ctx.limb_fold_pipeline == nil) {
        reason = ctx.batch_pipeline_error.empty()
            ? "batched-sketch Metal kernels unavailable"
            : ctx.batch_pipeline_error;
        return false;
    }
    std::call_once(ctx.batch_self_test_once, [&ctx] { RunBatchSelfTest(ctx); });
    if (!ctx.batch_self_test_passed) {
        reason = ctx.batch_self_test_error.empty() ? "batched self-test failed"
                                                   : ctx.batch_self_test_error;
        return false;
    }
    return true;
}

} // namespace

namespace matmul_v4::metal {

AccelProbe ProbeAcceleration()
{
    AccelProbe probe;
    if (EnvFlagDisabled("BTX_MATMUL_V4_METAL")) {
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

bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                        uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    if (EnvFlagDisabled("BTX_MATMUL_V4_METAL")) {
        return false;
    }

    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul_v4::kTileB, m)) {
        return false;
    }
    if (rounds == 0) {
        // API symmetry with matmul_v4::ComputeDigest (the miner runs no
        // Freivalds rounds, but rounds must be a valid parameter).
        return false;
    }

    auto& ctx = GetContext();
    std::string reason;
    if (!EnsureReady(ctx, reason)) {
        LogUnavailableOnce(reason);
        return false;
    }

    // The tensor-ops GEMM accumulates over K = n; keep it on shapes whose
    // reduction extent is 32-aligned (production shapes are), and let the
    // portable integer-ALU kernels -- equally bit-exact -- cover the rest.
    const bool use_tensor_gemm = ctx.gemm_tensor_pipeline != nil && (n % 32u) == 0u;

    std::string error;
    if (!ComputeDigestImpl(ctx, header, n, m, use_tensor_gemm, digest_out, payload_out, error)) {
        LogUnavailableOnce(error);
        return false;
    }
    return true;
}

bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                std::vector<uint256>& digests_out,
                                std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();
    if (EnvFlagDisabled("BTX_MATMUL_V4_METAL")) {
        return false;
    }
    if (headers.empty()) {
        return false;
    }

    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul_v4::kTileB, m)) {
        return false;
    }
    if (!matmul::v4::CheckCombineLimbBound(n)) {
        return false;
    }
    if (rounds == 0) {
        // API symmetry with the per-nonce entry point.
        return false;
    }

    auto& ctx = GetContext();
    std::string reason;
    if (!EnsureBatchReady(ctx, reason)) {
        LogUnavailableOnce(reason);
        return false;
    }

    // Same tensor-ops shape gate as the per-nonce path (every batched GEMM
    // reduces over K = n), plus the batched-shape self-test gate.
    const bool use_tensor_gemm =
        ctx.gemm_tensor_pipeline != nil && ctx.batch_tensor_ok && (n % 32u) == 0u;

    std::lock_guard<std::mutex> lock(ctx.batch_mutex);
    std::string error;
    if (!ComputeDigestsBatchedImpl(ctx, headers, n, m, use_tensor_gemm, /*window_override=*/0,
                                   digests_out, payloads_out, error)) {
        LogUnavailableOnce(error);
        digests_out.clear();
        payloads_out.clear();
        return false;
    }
    return true;
}

} // namespace matmul_v4::metal
