// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_accel.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <hip/hip_runtime.h>

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

// CDNA Matrix Cores expose the integer MFMA only on gfx9 (CDNA) targets. When
// compiling device code for such an arch, use the intrinsic; otherwise fall
// back to a scalar-integer accumulation with the identical tiled layout so the
// kernel still exists and stays bit-exact (used only for non-CDNA device
// builds / host-side syntax passes -- production targets are gfx908/90a/942).
#if defined(__HIP_DEVICE_COMPILE__) &&                                         \
    (defined(__gfx908__) || defined(__gfx90a__) || defined(__gfx940__) ||      \
     defined(__gfx941__) || defined(__gfx942__) || defined(__gfx950__))
#define BTX_HIP_HAVE_MFMA 1
#endif

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
    const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(sigma);

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
        hipLaunchKernelGGL(I8GemmTiled, grid, mfmaBlock, 0, 0,
                           static_cast<const int8_t*>(dB.ptr),
                           static_cast<const int8_t*>(dV.ptr),
                           static_cast<int32_t*>(dQ.ptr),
                           static_cast<int>(n), static_cast<int>(n), static_cast<int>(m));
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

} // namespace hip
} // namespace matmul_v4
