// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_accel.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <hip/hip_runtime.h>

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

// ===========================================================================
// AMD ROCm/HIP INT8 MatMul v4 backend.
//
// Structure mirrors the NVIDIA CUDA accelerator (src/cuda/matmul_accel.cu):
// derive the identical operands on the host, run the heavy integer GEMMs on the
// device Matrix Cores, and finish the tiny mod-q combine + serialization with
// the shared host reference code so the digest is bit-identical to the CPU.
//
// COMPUTE MODEL (design spec §A.4/§B.6/§E.3):
//   Chat = U * C * V  with  C = A * B     (all over the integers Z)
//        = (U*A) * (B*V)                  (associativity of matrix mult over Z)
//   Let P = U*A  (m x n, exact INT32, |P_ij| <= n*125^2 < 2^30)
//       Q = B*V  (n x m, exact INT32, |Q_ij| <= n*125^2 < 2^30)
//   Chat[a][c] = sum_j P[a][j]*Q[j][c]  reduced mod q = 2^61-1  (canonical).
// Because reduction mod q is a ring homomorphism and the underlying integer
// matrix (U*A)(B*V) == U*C*V is identical to the CPU's, the canonical F_q
// residues -- hence the serialized payload and the digest -- are byte-identical
// to matmul_v4::ComputeDigest, regardless of GEMM tiling/accumulation order
// (integer add is associative, §B.6). We NEVER materialize the n x n product C.
//
// P and Q are produced by exact INT8->INT32 GEMMs on the CDNA Matrix Cores via
// the v_mfma_i32_16x16x16_i8 instruction (compiler intrinsic
// __builtin_amdgcn_mfma_i32_16x16x16i8): 4 packed int8 along K per lane, an
// int32x4 accumulator, exact INT32 output -- no float, no saturation. This is
// the AMD analogue of NVIDIA's IMMA path. The final m x m combine runs mod q on
// the integer ALU (NOT the matrix cores), reproducing int8_field.h::FqReduce
// bit-for-bit.
//
// References (AMD CDNA INT8 GEMM):
//   * AMD Lab Notes, "AMD matrix cores" (GPUOpen) -- MFMA intrinsic syntax
//     `d = __builtin_amdgcn_mfma_CDFmt_MxNxKABFmt(a,b,c,cbsz,abid,blgp)` and the
//     16x16x4 / lane<->element layout used below (extended to packed int8 K=16).
//     https://gpuopen.com/learn/amd-lab-notes/amd-lab-notes-matrix-cores-readme/
//   * ROCm Blogs, "AMD matrix cores": INT8/INT32 MFMA table incl.
//     M=N=16,K=16 (v_mfma_i32_16x16x16i8).
//     https://rocm.blogs.amd.com/software-tools-optimization/matrix-cores/README.html
//   * LLVM clang builtins test builtins-amdgcn-mfma.cl -- confirms signature
//     `<4 x i32> @llvm.amdgcn.mfma.i32.16x16x16i8(i32 a, i32 b, <4 x i32> c, ...)`
//     (a,b each hold 4 packed int8; d/c are int32x4).
//   * ROCm/amd_matrix_instruction_calculator -- authoritative per-lane VGPR
//     layout (`--architecture cdna2 --instruction v_mfma_i32_16x16x16i8
//     --register-layout`).
//   * rocBLAS: `rocblas_gemm_ex` with a/b = rocblas_datatype_i8_r,
//     c/d/compute = rocblas_datatype_i32_r dispatches to the same MFMA cores on
//     gfx908+ automatically (documented drop-in production alternative to the
//     hand-written microkernel; see BuildProductGemm comment).
//
// BATCHED-SKETCH PATH (§K.2b, Appendix C-13; ComputeDigestsBatchedAccel below):
// mirrors matmul::v4::BatchedSketchMiner::Mine (src/matmul/matmul_v4_batch.h/
// .cpp) bit-for-bit. A, U, V and P = U*A are TEMPLATE-scoped and computed ONCE
// per nonce window (invariant I1'); only B_i (nonce-fresh) and the per-nonce
// combine are marginal cost. The per-nonce right factors Q_i = B_i*V are
// written directly into their column block of the horizontal stack Qstack (n x
// count*m) by I8GemmTiledOffset (a strided twin of I8GemmTiled), and the whole
// window's combine is evaluated as ONE LARGE DENSE GEMM P * Qstack through the
// SAME 4-limb balanced base-2^7 tensor path as the CPU's
// ComputeCombineLimbTensorStacked (Appendix C-13) -- unlike the per-nonce
// combine above (which reduces mod q directly on the integer ALU, since a
// single m x m x n combine is too small to be MFMA-dense), the batched
// combine's m x (count*m) x n shape IS the dense tensor-core shape the v4.1
// batched profile exists to enforce, so it is routed through 16 INT8->INT32
// MFMA GEMMs (one per limb pair) instead. See DecomposeLimbPlanesKernel /
// AccumulateChatKernel below for the on-device port of the CPU decomposition
// and mod-q recombine, and ComputeDigestsBatchedAccel for the full pipeline
// and its device-memory-bounded chunking.
// ===========================================================================

namespace matmul_v4 {
namespace hip {

bool HipBackendCompiled() { return true; }

namespace {

using matmul::int8_field::Fq;

// q = 2^61 - 1, mirrored on the device (matches int8_field.h::kFieldPrime).
__device__ __host__ __forceinline__ uint64_t DevFieldPrime()
{
    return (static_cast<uint64_t>(1) << 61) - 1;
}

// --- Device F_q arithmetic, a bit-for-bit port of int8_field.cpp ------------
// These reproduce FqReduce / FqAdd / FqMul / FqNeg / FqFromSigned exactly. All
// operations are integer-only; the 128-bit multiply lowers to 64-bit integer
// ALU sequences on amdgpu (no floating point).

__device__ __forceinline__ Fq DevFqReduce(unsigned __int128 x)
{
    const uint64_t q = DevFieldPrime();
    const uint64_t lo = static_cast<uint64_t>(x & q);
    const uint64_t hi = static_cast<uint64_t>(x >> 61); // x < 2^122 => hi < 2^61
    uint64_t s = lo + hi;                                // < 2^62
    s = (s & q) + (s >> 61);                             // <= q + 1
    if (s >= q) {
        s -= q;
    }
    return s;
}

__device__ __forceinline__ Fq DevFqAdd(Fq a, Fq b)
{
    const uint64_t q = DevFieldPrime();
    uint64_t s = a + b; // a,b < q < 2^61 => s < 2^62, no wrap
    if (s >= q) {
        s -= q;
    }
    return s;
}

__device__ __forceinline__ Fq DevFqMul(Fq a, Fq b)
{
    return DevFqReduce(static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b));
}

__device__ __forceinline__ Fq DevFqNeg(Fq a)
{
    return a == 0 ? 0 : DevFieldPrime() - a;
}

__device__ __forceinline__ Fq DevFqFromSigned(int64_t x)
{
    if (x >= 0) {
        return DevFqReduce(static_cast<unsigned __int128>(static_cast<uint64_t>(x)));
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(x + 1)) + 1; // safe for INT64_MIN
    return DevFqNeg(DevFqReduce(static_cast<unsigned __int128>(magnitude)));
}

// Amendment v2 §1.D D4: MFMA only on CDNA; RDNA4/gfx1200 uses scalar/WMMA path.
#include <hip/btx_hip_mfma_guard.h>

using int32x4 = int32_t __attribute__((ext_vector_type(4)));

// Pack this lane's four consecutive-K int8 operands into one 32-bit register
// (byte p holds K index kBase+p, i.e. lowest K in the least-significant byte --
// the standard CDNA A/B packing along K).
__device__ __forceinline__ int PackI8x4(int8_t v0, int8_t v1, int8_t v2, int8_t v3)
{
    return static_cast<int>((static_cast<uint32_t>(static_cast<uint8_t>(v0))) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v1)) << 8) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v2)) << 16) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v3)) << 24));
}

// Exact INT8xINT8 -> INT32 GEMM  D(MxN) = A(MxK) * B(KxN), all row-major, exact
// integer accumulate. One wavefront (blockDim = {16,4,1}) computes one 16x16
// output tile; grid = {ceil(N/16), ceil(M/16)}. Ragged M/N/K are handled by
// zero-padding (int8 zero is exact and contributes nothing). Lane layout
// (threadIdx.x = lx in [0,16), threadIdx.y = ly in [0,4)) follows the AMD Lab
// Notes 16x16 convention:
//   A frag: row = tileRow + lx, K = ktBase + ly*4 + {0..3}   (packed int8)
//   B frag: col = tileCol + lx, K = ktBase + ly*4 + {0..3}   (packed int8)
//   D frag: 4 int32 per lane, D[tileRow + ly*4 + i][tileCol + lx], i in [0,4)
__global__ void I8GemmTiled(const int8_t* __restrict__ A,
                            const int8_t* __restrict__ B,
                            int32_t* __restrict__ D,
                            int M, int N, int K)
{
    const int lx = static_cast<int>(threadIdx.x); // 0..15
    const int ly = static_cast<int>(threadIdx.y); // 0..3
    const int tileRow = static_cast<int>(blockIdx.y) * 16;
    const int tileCol = static_cast<int>(blockIdx.x) * 16;
    const int kTiles = (K + 15) / 16;

#if defined(BTX_HIP_HAVE_MFMA)
    int32x4 acc = {0, 0, 0, 0};
    const int aRow = tileRow + lx;
    const int bCol = tileCol + lx;
    for (int kt = 0; kt < kTiles; ++kt) {
        const int kBase = kt * 16 + ly * 4;

        int8_t a0 = 0, a1 = 0, a2 = 0, a3 = 0;
        if (aRow < M) {
            const size_t base = static_cast<size_t>(aRow) * K;
            const int k0 = kBase, k1 = kBase + 1, k2 = kBase + 2, k3 = kBase + 3;
            if (k0 < K) a0 = A[base + k0];
            if (k1 < K) a1 = A[base + k1];
            if (k2 < K) a2 = A[base + k2];
            if (k3 < K) a3 = A[base + k3];
        }
        int8_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
        if (bCol < N) {
            const int k0 = kBase, k1 = kBase + 1, k2 = kBase + 2, k3 = kBase + 3;
            if (k0 < K) b0 = B[static_cast<size_t>(k0) * N + bCol];
            if (k1 < K) b1 = B[static_cast<size_t>(k1) * N + bCol];
            if (k2 < K) b2 = B[static_cast<size_t>(k2) * N + bCol];
            if (k3 < K) b3 = B[static_cast<size_t>(k3) * N + bCol];
        }

        const int a_pack = PackI8x4(a0, a1, a2, a3);
        const int b_pack = PackI8x4(b0, b1, b2, b3);
        acc = __builtin_amdgcn_mfma_i32_16x16x16i8(a_pack, b_pack, acc, 0, 0, 0);
    }
    for (int i = 0; i < 4; ++i) {
        const int row = tileRow + ly * 4 + i;
        const int col = tileCol + lx;
        if (row < M && col < N) {
            D[static_cast<size_t>(row) * N + col] = acc[i];
        }
    }
#else
    // Portable scalar-integer twin producing the identical integer result: this
    // lane owns outputs D[tileRow + ly*4 + i][tileCol + lx], i in [0,4).
    const int col = tileCol + lx;
    int32_t acc[4] = {0, 0, 0, 0};
    if (col < N) {
        for (int i = 0; i < 4; ++i) {
            const int row = tileRow + ly * 4 + i;
            if (row >= M) continue;
            int32_t s = 0;
            const size_t arow = static_cast<size_t>(row) * K;
            for (int k = 0; k < K; ++k) {
                s += static_cast<int32_t>(A[arow + k]) *
                     static_cast<int32_t>(B[static_cast<size_t>(k) * N + col]);
            }
            acc[i] = s;
        }
        for (int i = 0; i < 4; ++i) {
            const int row = tileRow + ly * 4 + i;
            if (row < M) {
                D[static_cast<size_t>(row) * N + col] = acc[i];
            }
        }
    }
    (void)kTiles;
#endif
}

// Chat(m x m) = P(m x n) * Q(n x m) reduced mod q = 2^61-1, canonical F_q.
// Integer ALU only (NOT the matrix cores): reproduces int8_field.h's field
// arithmetic exactly. One thread per Chat entry.
__global__ void CombineModQ(const int32_t* __restrict__ P,
                            const int32_t* __restrict__ Q,
                            uint64_t* __restrict__ Chat,
                            int m, int n)
{
    const int c = static_cast<int>(blockIdx.x) * static_cast<int>(blockDim.x) + static_cast<int>(threadIdx.x);
    const int a = static_cast<int>(blockIdx.y) * static_cast<int>(blockDim.y) + static_cast<int>(threadIdx.y);
    if (a >= m || c >= m) {
        return;
    }
    const int32_t* prow = P + static_cast<size_t>(a) * n;
    Fq acc = 0;
    for (int j = 0; j < n; ++j) {
        const Fq pj = DevFqFromSigned(static_cast<int64_t>(prow[j]));
        const Fq qc = DevFqFromSigned(static_cast<int64_t>(Q[static_cast<size_t>(j) * m + c]));
        acc = DevFqAdd(acc, DevFqMul(pj, qc));
    }
    Chat[static_cast<size_t>(a) * m + c] = acc;
}

// ===========================================================================
// BATCHED-SKETCH (§K.2b, Appendix C-13) device kernels.
// ===========================================================================

// Exact INT8xINT8 -> INT32 GEMM, identical math to I8GemmTiled above (same
// tiling, same MFMA/scalar dual path, verbatim-duplicated body so the already-
// reviewed per-nonce kernel above is untouched), but the M x N output tile is
// written at row-stride `ldD` starting at column `colOffset` instead of at
// stride N, offset 0. This lets Q_i = B_i*V (M=n, N=m, K=n) land directly in
// its column block [colOffset, colOffset+m) of the wider horizontal stack
// Qstack (n x count*m, ldD = count*m) -- no separate copy/reshape kernel, and
// the CPU's Qstack layout (column block i = Q_i, matching
// ComputeCombineLimbTensorStacked's expected `Qstack` argument) is reproduced
// exactly by construction.
__global__ void I8GemmTiledOffset(const int8_t* __restrict__ A,
                                  const int8_t* __restrict__ B,
                                  int32_t* __restrict__ D,
                                  int M, int N, int K,
                                  int ldD, int colOffset)
{
    const int lx = static_cast<int>(threadIdx.x); // 0..15
    const int ly = static_cast<int>(threadIdx.y); // 0..3
    const int tileRow = static_cast<int>(blockIdx.y) * 16;
    const int tileCol = static_cast<int>(blockIdx.x) * 16;
    const int kTiles = (K + 15) / 16;

#if defined(BTX_HIP_HAVE_MFMA)
    int32x4 acc = {0, 0, 0, 0};
    const int aRow = tileRow + lx;
    const int bCol = tileCol + lx;
    for (int kt = 0; kt < kTiles; ++kt) {
        const int kBase = kt * 16 + ly * 4;

        int8_t a0 = 0, a1 = 0, a2 = 0, a3 = 0;
        if (aRow < M) {
            const size_t base = static_cast<size_t>(aRow) * K;
            const int k0 = kBase, k1 = kBase + 1, k2 = kBase + 2, k3 = kBase + 3;
            if (k0 < K) a0 = A[base + k0];
            if (k1 < K) a1 = A[base + k1];
            if (k2 < K) a2 = A[base + k2];
            if (k3 < K) a3 = A[base + k3];
        }
        int8_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
        if (bCol < N) {
            const int k0 = kBase, k1 = kBase + 1, k2 = kBase + 2, k3 = kBase + 3;
            if (k0 < K) b0 = B[static_cast<size_t>(k0) * N + bCol];
            if (k1 < K) b1 = B[static_cast<size_t>(k1) * N + bCol];
            if (k2 < K) b2 = B[static_cast<size_t>(k2) * N + bCol];
            if (k3 < K) b3 = B[static_cast<size_t>(k3) * N + bCol];
        }

        const int a_pack = PackI8x4(a0, a1, a2, a3);
        const int b_pack = PackI8x4(b0, b1, b2, b3);
        acc = __builtin_amdgcn_mfma_i32_16x16x16i8(a_pack, b_pack, acc, 0, 0, 0);
    }
    for (int i = 0; i < 4; ++i) {
        const int row = tileRow + ly * 4 + i;
        const int col = tileCol + lx;
        if (row < M && col < N) {
            D[static_cast<size_t>(row) * ldD + colOffset + col] = acc[i];
        }
    }
#else
    // Portable scalar-integer twin, same layout as I8GemmTiled's fallback.
    const int col = tileCol + lx;
    int32_t acc[4] = {0, 0, 0, 0};
    if (col < N) {
        for (int i = 0; i < 4; ++i) {
            const int row = tileRow + ly * 4 + i;
            if (row >= M) continue;
            int32_t s = 0;
            const size_t arow = static_cast<size_t>(row) * K;
            for (int k = 0; k < K; ++k) {
                s += static_cast<int32_t>(A[arow + k]) *
                     static_cast<int32_t>(B[static_cast<size_t>(k) * N + col]);
            }
            acc[i] = s;
        }
        for (int i = 0; i < 4; ++i) {
            const int row = tileRow + ly * 4 + i;
            if (row < M) {
                D[static_cast<size_t>(row) * ldD + colOffset + col] = acc[i];
            }
        }
    }
    (void)kTiles;
#endif
}

static_assert(matmul::v4::kCombineLimbs == 4 && matmul::v4::kCombineLimbBase == 128,
             "DecomposeLimbPlanesKernel/AccumulateChatKernel hard-code the 4-limb "
             "balanced base-2^7 decomposition; keep in sync with matmul_v4.h");

// Entrywise balanced base-2^7 digit decomposition (Appendix C-13), a bit-for-
// bit device port of matmul::v4::DecomposeLimbPlanes (matmul_v4.cpp, anonymous
// namespace): for each element x, extract 4 digits d_l in [-64,63] such that
// x = sum_l d_l * 128^l, via the SAME balanced-remainder recurrence
//   d = ((x + 64) & 127) - 64;  x = (x - d) / 128;
// repeated 4 times. Every element is decomposed independently of every other
// (no cross-thread state), so parallelizing over elements changes nothing:
// this reproduces the CPU decomposition digit-for-digit for every entry.
__global__ void DecomposeLimbPlanesKernel(const int32_t* __restrict__ M,
                                          int8_t* __restrict__ plane0,
                                          int8_t* __restrict__ plane1,
                                          int8_t* __restrict__ plane2,
                                          int8_t* __restrict__ plane3,
                                          size_t count)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    int32_t x = M[idx];

    int32_t d = ((x + 64) & 127) - 64;
    plane0[idx] = static_cast<int8_t>(d);
    x = (x - d) / 128; // exact: (x - d) is a multiple of 128

    d = ((x + 64) & 127) - 64;
    plane1[idx] = static_cast<int8_t>(d);
    x = (x - d) / 128;

    d = ((x + 64) & 127) - 64;
    plane2[idx] = static_cast<int8_t>(d);
    x = (x - d) / 128;

    d = ((x + 64) & 127) - 64;
    plane3[idx] = static_cast<int8_t>(d);
    x = (x - d) / 128;
    // The decomposition is total under CheckCombineLimbBound (checked on the
    // host before any kernel is launched); x must be 0 here, exactly as the
    // CPU reference documents (not asserted in the hot loop; pinned by the
    // matmul_v4_batch_tests.cpp byte-identity tests).
}

// Chat[idx] = FqAdd(Chat[idx], FqMul(weight, FqFromSigned(S[idx]))) -- the
// O(m*q_cols) shifted mod-q recombine of Appendix C-13, invoked once per limb
// pair (i,j) with weight = 128^(i+j) mod q. Every exponent 7*(i+j) <= 42 < 61,
// so (matching matmul_v4.cpp's `weight[i][j] = 1 << (7*(i+j))` exactly) the
// weight is just the literal power of two, no reduction needed. F_q addition
// is commutative and associative over the exact integer sum
// sum_k P[a][k]*Qstack[k][c] = sum_ij 128^(i+j) * S_ij[a][c], so accumulating
// the 16 limb-pair contributions here (one AccumulateChatKernel launch per
// (i,j), same values as the CPU's i-major/j-minor loop) reproduces the
// identical canonical F_q residue as
// matmul::v4::ComputeCombineLimbTensorStacked, regardless of GEMM/launch
// order -- only exact-integer intermediate values and the field arithmetic
// itself matter (§B.6).
__global__ void AccumulateChatKernel(const int32_t* __restrict__ S,
                                     uint64_t* __restrict__ Chat,
                                     uint64_t weight,
                                     size_t count)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    const Fq s_fq = DevFqFromSigned(static_cast<int64_t>(S[idx]));
    Chat[idx] = DevFqAdd(Chat[idx], DevFqMul(weight, s_fq));
}

// RAII-ish device buffer so every early return frees cleanly.
struct DeviceBuffer {
    void* ptr{nullptr};
    ~DeviceBuffer() { if (ptr) hipFree(ptr); }
    bool Alloc(size_t bytes)
    {
        if (bytes == 0) { ptr = nullptr; return true; }
        return hipMalloc(&ptr, bytes) == hipSuccess;
    }
};

} // namespace

bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                        uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    // §A.4 Solve: identical validation to matmul_v4::ComputeDigest.
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul::v4::kTileB, m)) {
        return false;
    }
    if (rounds == 0) {
        return false;
    }

    // --- Derive operands on the host with the SHARED reference routines so they
    // are guaranteed byte-equal to the CPU (task requirement 1; §A.2). ---
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
    const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
    const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);

    const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);   // n x n
    const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);   // n x n
    const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n); // m x n
    const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m); // n x m

    const size_t nn = static_cast<size_t>(n) * n;
    const size_t mn = static_cast<size_t>(m) * n;
    const size_t mm = static_cast<size_t>(m) * m;

    // --- Device allocations. ---
    DeviceBuffer dA, dB, dU, dV, dP, dQ, dChat;
    if (!dA.Alloc(nn * sizeof(int8_t)) ||
        !dB.Alloc(nn * sizeof(int8_t)) ||
        !dU.Alloc(mn * sizeof(int8_t)) ||
        !dV.Alloc(mn * sizeof(int8_t)) ||
        !dP.Alloc(mn * sizeof(int32_t)) ||     // P = U*A, m x n
        !dQ.Alloc(mn * sizeof(int32_t)) ||     // Q = B*V, n x m
        !dChat.Alloc(mm * sizeof(uint64_t))) {
        return false;
    }

    if (hipMemcpy(dA.ptr, A.data(), nn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dB.ptr, B.data(), nn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dU.ptr, U.data(), mn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dV.ptr, V.data(), mn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess) {
        return false;
    }

    const dim3 mfmaBlock(16, 4, 1);
    auto ceilDiv = [](uint32_t a, uint32_t b) -> unsigned { return (a + b - 1) / b; };

    // BuildProductGemm: the two heavy integer GEMMs on the MFMA cores.
    // GEMM 1: P = U * A  -> M=m, K=n, N=n   (P is m x n)
    // GEMM 2: Q = B * V  -> M=n, K=n, N=m   (Q is n x m)
    // (rocBLAS drop-in production alternative for either GEMM:
    //   rocblas_gemm_ex(handle, opN, opN, N, M, K, &one,
    //                   dB_colmajor, i8_r, ldb, dA_colmajor, i8_r, lda, &zero,
    //                   dC, i32_r, ldc, dC, i32_r, ldc, i32_r,
    //                   rocblas_gemm_algo_standard, 0, rocblas_gemm_flags_none)
    //  computing the row-major C=A*B as the column-major C^T=B^T*A^T; it
    //  dispatches to the same v_mfma_i32_*_i8 cores on gfx908+.)
    {
        const dim3 grid(ceilDiv(n, 16), ceilDiv(m, 16), 1); // N=n cols, M=m rows
        hipLaunchKernelGGL(I8GemmTiled, grid, mfmaBlock, 0, 0,
                           static_cast<const int8_t*>(dU.ptr),
                           static_cast<const int8_t*>(dA.ptr),
                           static_cast<int32_t*>(dP.ptr),
                           static_cast<int>(m), static_cast<int>(n), static_cast<int>(n));
    }
    {
        const dim3 grid(ceilDiv(m, 16), ceilDiv(n, 16), 1); // N=m cols, M=n rows
        // Q = B*V is n x m: (M,N,K) = (n,m,n). Passing (n,n,m) sets N=n/K=m,
        // which contradicts this grid (N=m cols), diverges from the CPU
        // reference, and overruns dQ (sized n*m). Consensus-correctness fix,
        // mirrors the CUDA backend's ComputeSketchOnDevice Q GEMM.
        hipLaunchKernelGGL(I8GemmTiled, grid, mfmaBlock, 0, 0,
                           static_cast<const int8_t*>(dB.ptr),
                           static_cast<const int8_t*>(dV.ptr),
                           static_cast<int32_t*>(dQ.ptr),
                           static_cast<int>(n), static_cast<int>(m), static_cast<int>(n));
    }
    if (hipGetLastError() != hipSuccess) {
        return false;
    }

    // Combine mod q on the integer ALU -> canonical Chat (m x m).
    {
        const dim3 block(16, 16, 1);
        const dim3 grid(ceilDiv(m, 16), ceilDiv(m, 16), 1);
        hipLaunchKernelGGL(CombineModQ, grid, block, 0, 0,
                           static_cast<const int32_t*>(dP.ptr),
                           static_cast<const int32_t*>(dQ.ptr),
                           static_cast<uint64_t*>(dChat.ptr),
                           static_cast<int>(m), static_cast<int>(n));
    }
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) {
        return false;
    }

    // Copy Chat back and finish with the SHARED reference serialization + digest
    // so the outputs are byte-identical to CPU (task requirement 4; §E.1).
    std::vector<Fq> Chat(mm);
    if (hipMemcpy(Chat.data(), dChat.ptr, mm * sizeof(uint64_t), hipMemcpyDeviceToHost) != hipSuccess) {
        return false;
    }

    payload_out = matmul::v4::SerializeSketch(Chat);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, payload_out);
    return true;
}

// ===========================================================================
// Batched-sketch entry point (§K.2b, Appendix C-13). Mirrors
// matmul::v4::BatchedSketchMiner::Mine bit-for-bit; see matmul_v4_accel.h and
// the file header comment above for the algorithm summary.
// ===========================================================================

bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                std::vector<uint256>& digests_out,
                                std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();

    // §A.4 Solve: identical validation to matmul_v4::ComputeDigest / the CPU
    // BatchedSketchMiner constructor.
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul::v4::kTileB, m)) {
        return false;
    }
    if (!matmul::v4::CheckCombineLimbBound(n)) {
        return false;
    }
    if (rounds == 0) {
        return false;
    }
    if (headers.empty()) {
        return false;
    }

    const uint32_t count = static_cast<uint32_t>(headers.size());

    // Fail-closed template gate (§A.2/I1', matching BatchedSketchMiner::Mine
    // exactly): headers[0] defines the window's template; every header MUST
    // project onto the SAME template hash before any device work is issued, or
    // this call returns false with no partial output. sigma is derived here too
    // (cheap, host-only) so it is available once we start filling in results.
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(headers[0]);
    std::vector<uint256> sigmas(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (matmul::v4::ComputeTemplateHash(headers[i]) != template_hash) {
            return false;
        }
        sigmas[i] = matmul::v4::DeriveSigma(headers[i]);
    }

    // --- TEMPLATE-scoped derivation, ONCE per window (§K.2b): A, U, V from
    // headers[0]'s template, then P = U*A on the MFMA cores. ---
    const uint256 seed_a = matmul::v4::DeriveOperandSeed(headers[0], matmul::v4::Operand::A);
    const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(headers[0]);
    const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);       // n x n
    const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n); // m x n
    const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m); // n x m

    const size_t nn = static_cast<size_t>(n) * n;
    const size_t mn = static_cast<size_t>(m) * n;

    DeviceBuffer dA, dU, dV, dP;
    DeviceBuffer dPPlane[matmul::v4::kCombineLimbs];
    if (!dA.Alloc(nn * sizeof(int8_t)) ||
        !dU.Alloc(mn * sizeof(int8_t)) ||
        !dV.Alloc(mn * sizeof(int8_t)) ||
        !dP.Alloc(mn * sizeof(int32_t))) {
        return false;
    }
    for (uint32_t l = 0; l < matmul::v4::kCombineLimbs; ++l) {
        if (!dPPlane[l].Alloc(mn * sizeof(int8_t))) return false;
    }

    if (hipMemcpy(dA.ptr, A.data(), nn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dU.ptr, U.data(), mn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dV.ptr, V.data(), mn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess) {
        return false;
    }

    const dim3 mfmaBlock(16, 4, 1);
    auto ceilDiv = [](uint32_t a, uint32_t b) -> unsigned { return (a + b - 1) / b; };
    constexpr unsigned kElemThreads = 256;

    // P = U*A -> M=m, K=n, N=n (P is m x n). Template-scoped: paid ONCE for the
    // whole window (invariant I1').
    {
        const dim3 grid(ceilDiv(n, 16), ceilDiv(m, 16), 1);
        hipLaunchKernelGGL(I8GemmTiled, grid, mfmaBlock, 0, 0,
                           static_cast<const int8_t*>(dU.ptr),
                           static_cast<const int8_t*>(dA.ptr),
                           static_cast<int32_t*>(dP.ptr),
                           static_cast<int>(m), static_cast<int>(n), static_cast<int>(n));
    }
    if (hipGetLastError() != hipSuccess) {
        return false;
    }

    // 4-limb decomposition of P (Appendix C-13), also template-scoped / paid
    // ONCE: P does not change across the nonce window.
    {
        const unsigned blocks = static_cast<unsigned>((mn + kElemThreads - 1) / kElemThreads);
        hipLaunchKernelGGL(DecomposeLimbPlanesKernel, dim3(blocks), dim3(kElemThreads), 0, 0,
                           static_cast<const int32_t*>(dP.ptr),
                           static_cast<int8_t*>(dPPlane[0].ptr), static_cast<int8_t*>(dPPlane[1].ptr),
                           static_cast<int8_t*>(dPPlane[2].ptr), static_cast<int8_t*>(dPPlane[3].ptr),
                           mn);
    }
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) {
        return false;
    }

    // --- Device-memory-bounded chunking over the nonce window. ---
    // Per-nonce marginal device bytes for the VARIABLE (per-chunk) buffers:
    //   Qstack column block: n int32           = 4n
    //   its 4 limb planes:   n int8 x 4        = 4n
    //   S (one limb-pair product, m rows x m cols per nonce): m int32 x 1 (reused across all 16 pairs, sized for the whole chunk, so per-nonce contribution is m int32) = 4m
    //   Chat column block:   m int64           = 8m
    // total per-nonce variable bytes = m*(8n + 12m) [derivation: q_cols = chunk_q*m,
    // Qstack = n*q_cols*4, planes = 4*n*q_cols, S = m*q_cols*4, Chat = m*q_cols*8;
    // sum = q_cols*(8n+12m) = chunk_q*m*(8n+12m)].
    // Fixed (window-wide, already allocated above) bytes: dA+dB (2*n^2) plus
    // dU+dV+dP+dPPlane (m*n*(1+1+4+4) = 10*m*n).
    size_t free_bytes = 0, total_bytes = 0;
    if (hipMemGetInfo(&free_bytes, &total_bytes) != hipSuccess || free_bytes == 0) {
        free_bytes = size_t{512} << 20; // conservative 512 MiB if the query is unavailable
    }
    const size_t fixed_bytes = 2 * nn + 10 * mn;
    // 256 MiB headroom for the HIP runtime / other allocations we don't track
    // precisely (workspace, driver overhead); spend at most half of whatever is
    // left on one chunk's variable buffers so at least two chunks' worth of
    // slack always remains.
    constexpr size_t kSafetyMargin = size_t{256} << 20;
    size_t budget = 0;
    if (free_bytes > fixed_bytes + kSafetyMargin) {
        budget = (free_bytes - fixed_bytes - kSafetyMargin) / 2;
    }
    const size_t per_nonce_bytes = static_cast<size_t>(m) * (8ull * n + 12ull * m);
    uint32_t chunk_q = (per_nonce_bytes == 0)
        ? count
        : static_cast<uint32_t>(std::max<size_t>(1, budget / per_nonce_bytes));
    // Final sanity clamp: never build a single chunk larger than
    // kMaxBatchedWindow, mirroring the CUDA backend's fixed cap even though
    // this backend's chunk size is primarily memory-derived (see header).
    chunk_q = std::min(chunk_q, kMaxBatchedWindow);
    chunk_q = std::max<uint32_t>(1, std::min(chunk_q, count));

    // Fail-closed contract (matches the CPU BatchedSketchMiner::Mine and the
    // sibling CUDA/Metal batched backends): no partial windows. Results are
    // accumulated in LOCAL vectors and only moved into digests_out/payloads_out
    // once the ENTIRE window has succeeded; every early `return false` below
    // therefore leaves digests_out/payloads_out in the cleared state set at the
    // top of this function, with no caller-visible partial output.
    std::vector<uint256> local_digests(count);
    std::vector<std::vector<unsigned char>> local_payloads(count);

    // Per-nonce transient operand B (n x n s8), reused for every nonce in every
    // chunk -- B is nonce-fresh and never needed after its Q_i = B_i*V GEMM.
    DeviceBuffer dB;
    if (!dB.Alloc(nn * sizeof(int8_t))) {
        return false;
    }

    for (uint32_t chunk_start = 0; chunk_start < count; chunk_start += chunk_q) {
        const uint32_t this_chunk = std::min(chunk_q, count - chunk_start);
        const uint32_t q_cols = this_chunk * m;
        const size_t n_qcols = static_cast<size_t>(n) * q_cols;
        const size_t m_qcols = static_cast<size_t>(m) * q_cols;

        DeviceBuffer dQstack, dS, dChat;
        DeviceBuffer dQPlane[matmul::v4::kCombineLimbs];
        if (!dQstack.Alloc(n_qcols * sizeof(int32_t)) ||
            !dS.Alloc(m_qcols * sizeof(int32_t)) ||
            !dChat.Alloc(m_qcols * sizeof(uint64_t))) {
            return false;
        }
        for (uint32_t l = 0; l < matmul::v4::kCombineLimbs; ++l) {
            if (!dQPlane[l].Alloc(n_qcols * sizeof(int8_t))) return false;
        }

        // Per-nonce Q_i = B_i*V (M=n, K=n, N=m), written directly into column
        // block `local_idx` of Qstack (ldD = q_cols, colOffset = local_idx*m) --
        // reproduces the CPU's Qstack assembly loop exactly, one nonce at a time.
        for (uint32_t local_idx = 0; local_idx < this_chunk; ++local_idx) {
            const CBlockHeader& header = headers[chunk_start + local_idx];
            const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
            const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
            if (hipMemcpy(dB.ptr, B.data(), nn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess) {
                return false;
            }

            const dim3 grid(ceilDiv(m, 16), ceilDiv(n, 16), 1); // N=m cols, M=n rows
            hipLaunchKernelGGL(I8GemmTiledOffset, grid, mfmaBlock, 0, 0,
                               static_cast<const int8_t*>(dB.ptr),
                               static_cast<const int8_t*>(dV.ptr),
                               static_cast<int32_t*>(dQstack.ptr),
                               static_cast<int>(n), static_cast<int>(m), static_cast<int>(n),
                               static_cast<int>(q_cols), static_cast<int>(local_idx * m));
            if (hipGetLastError() != hipSuccess) {
                return false;
            }
        }

        // Decompose Qstack into its 4 limb planes (Appendix C-13).
        {
            const unsigned blocks = static_cast<unsigned>((n_qcols + kElemThreads - 1) / kElemThreads);
            hipLaunchKernelGGL(DecomposeLimbPlanesKernel, dim3(blocks), dim3(kElemThreads), 0, 0,
                               static_cast<const int32_t*>(dQstack.ptr),
                               static_cast<int8_t*>(dQPlane[0].ptr), static_cast<int8_t*>(dQPlane[1].ptr),
                               static_cast<int8_t*>(dQPlane[2].ptr), static_cast<int8_t*>(dQPlane[3].ptr),
                               n_qcols);
        }
        if (hipGetLastError() != hipSuccess) {
            return false;
        }

        if (hipMemset(dChat.ptr, 0, m_qcols * sizeof(uint64_t)) != hipSuccess) {
            return false;
        }

        // ONE LARGE DENSE COMBINE (§K.2b): Chat_wide = P * Qstack (m x q_cols),
        // via the 16 limb-pair MFMA GEMMs S_ij = Pi*Qj (m x q_cols x n) each
        // immediately folded into Chat with weight 128^(i+j) (Appendix C-13).
        for (uint32_t i = 0; i < matmul::v4::kCombineLimbs; ++i) {
            for (uint32_t j = 0; j < matmul::v4::kCombineLimbs; ++j) {
                const dim3 grid(ceilDiv(q_cols, 16), ceilDiv(m, 16), 1);
                hipLaunchKernelGGL(I8GemmTiled, grid, mfmaBlock, 0, 0,
                                   static_cast<const int8_t*>(dPPlane[i].ptr),
                                   static_cast<const int8_t*>(dQPlane[j].ptr),
                                   static_cast<int32_t*>(dS.ptr),
                                   static_cast<int>(m), static_cast<int>(q_cols), static_cast<int>(n));
                if (hipGetLastError() != hipSuccess) {
                    return false;
                }

                const uint64_t weight = static_cast<uint64_t>(1) << (7 * (i + j));
                const unsigned blocks = static_cast<unsigned>((m_qcols + kElemThreads - 1) / kElemThreads);
                hipLaunchKernelGGL(AccumulateChatKernel, dim3(blocks), dim3(kElemThreads), 0, 0,
                                   static_cast<const int32_t*>(dS.ptr),
                                   static_cast<uint64_t*>(dChat.ptr),
                                   weight, m_qcols);
                if (hipGetLastError() != hipSuccess) {
                    return false;
                }
            }
        }
        if (hipDeviceSynchronize() != hipSuccess) {
            return false;
        }

        // Copy the chunk's Chat_wide back and finish with the SHARED host
        // reference routines (byte-identical to CPU): slice per nonce,
        // serialize, digest.
        std::vector<Fq> chat_wide(m_qcols);
        static_assert(sizeof(Fq) == sizeof(uint64_t), "Fq must be a 64-bit word");
        if (hipMemcpy(chat_wide.data(), dChat.ptr, m_qcols * sizeof(uint64_t), hipMemcpyDeviceToHost) != hipSuccess) {
            return false;
        }

        for (uint32_t local_idx = 0; local_idx < this_chunk; ++local_idx) {
            const uint32_t global_idx = chunk_start + local_idx;
            std::vector<Fq> chat(static_cast<size_t>(m) * m);
            for (uint32_t a = 0; a < m; ++a) {
                const Fq* src = &chat_wide[static_cast<size_t>(a) * q_cols + static_cast<size_t>(local_idx) * m];
                std::copy(src, src + m, &chat[static_cast<size_t>(a) * m]);
            }
            local_payloads[global_idx] = matmul::v4::SerializeSketch(chat);
            local_digests[global_idx] =
                matmul::v4::ComputeSketchDigest(sigmas[global_idx], local_payloads[global_idx]);
        }
        // dQstack/dS/dChat/dQPlane go out of scope here and free before the next
        // chunk allocates -- keeps peak device memory bounded by ONE chunk's
        // variable footprint plus the window-wide fixed buffers, regardless of
        // how many chunks the window requires.
    }

    digests_out = std::move(local_digests);
    payloads_out = std::move(local_payloads);
    return true;
}

} // namespace hip
} // namespace matmul_v4
