// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_accel.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cublasLt.h>
#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

// ===========================================================================
// MatMul v4 NVIDIA INT8 tensor-core backend.
//
// STRATEGY (§E.3 optimal-miner path, §B.6 determinism):
//
//   The CPU reference (matmul_v4.cpp) forms the exact INT32 product C = A*B
//   (n x n, |C_ij| <= n*125^2 < 2^30) and then the sketch Chat = U*C*V over
//   q = 2^61-1. Because exact-integer matmul is associative, the §E.3 optimal
//   factoring
//
//       Chat = U*(A*B)*V = (U*A)*(B*V)   (all exact integers, then mod q)
//
//   yields the IDENTICAL committed Chat. We evaluate:
//
//     P = U*A   -- (m x n) = (m x n)*(n x n)   INT8 -> INT32 tensor-core GEMM
//     Q = B*V   -- (n x m) = (n x n)*(n x m)   INT8 -> INT32 tensor-core GEMM
//     Chat[a][c] = ( sum_k P[a][k]*Q[k][c] ) mod q   -- integer-ALU mod-q GEMM
//
//   Both P and Q have the SAME accumulation bound as C: every entry is a length-n
//   dot of balanced-s8 values, so |P|,|Q| <= n*125^2 < 2^30 and fits an exact
//   INT32 accumulator. cuBLASLt INT8->INT32 (CUDA_R_8I inputs, CUDA_R_32I output,
//   CUBLAS_COMPUTE_32I, scale type CUDA_R_32I, alpha=1/beta=0) accumulates in
//   INT32 with NO rounding, so the result is the exact integer product regardless
//   of the tile/reduction order the library picks -- integer addition is
//   associative and commutative (§B.6). This is EXACT, never TF32/FP.
//
//   BIT-EXACTNESS PROOF. As integer matrices, (U*A)(B*V) == U*(A*B)*V == U*C*V
//   entry-for-entry (associativity). Reduction Z -> F_q is a ring homomorphism,
//   so reducing the exact integer entry mod q gives the same canonical residue
//   in [0, q) as the CPU's FqAdd/FqMul chain over U*C*V. The canonical residue
//   is unique, hence SerializeSketch (LE64 words) and H(sigma||Chat) are
//   byte-identical to the CPU. The result does NOT depend on matching any CPU
//   intermediate (C or T); it only requires (i) exact INT32 GEMMs and (ii) a
//   mod-q reduction identical to int8_field.h FqReduce -- both provided here.
//
// GEMM API CHOICE (researched; see the SUMMARY returned to the team):
//   * PRIMARY: cuBLASLt cublasLtMatmul, CUDA_R_8I -> CUDA_R_32I, CUBLAS_COMPUTE_32I,
//     row-major layouts (CUBLASLT_ORDER_ROW). This is the exact INT32-accumulate
//     path named in the task; on SM_75+ (Turing/Ampere/Ada/Hopper/Blackwell) the
//     library serves large INT8 GEMMs on the integer tensor cores (IMMA), which
//     under the hood issue mma.sync.aligned.m16n8k32.s32.s8.s8.s32. INT32
//     accumulation makes DP4A vs IMMA dispatch irrelevant to the RESULT bytes.
//   * The maximum-throughput IMMA layout (A: CUBLASLT_ORDER_COL32/OP_N,
//     B: CUBLASLT_ORDER_COL4_4R2_8C(Turing)/COL32_2R_4R4(Ampere)/OP_T,
//     C: CUBLASLT_ORDER_COL32) is documented in the SUMMARY; it is a pure
//     performance swap (same INT32-exact result) and can replace RunInt8Gemm
//     verbatim once validated on hardware.
//   * FALLBACK: a scalar INT32 GEMM kernel (RunInt8GemmScalar) that also produces
//     the exact integer product. Used automatically if cuBLASLt returns an error,
//     or forced via BTX_MATMUL_V4_CUDA_GEMM=scalar for cross-checking the mod-q /
//     digest plumbing independently of the library.
//
// The operand derivation, sketch serialization and digest are done on the HOST
// by REUSING the exact matmul_v4 / int8_field routines (guaranteeing identical
// operands and identical digest bytes). Only the three GEMMs run on the GPU.
// ===========================================================================

namespace matmul_v4::cuda {
namespace {

using matmul::v4::Fq;

// --- q = 2^61 - 1 field arithmetic, a bit-for-bit device mirror of the CPU
//     int8_field.cpp reductions. These MUST match FqReduce/FqMul/FqAdd/
//     FqFromSigned/FqNeg exactly (they do -- same Mersenne fold, same branches).
__device__ __forceinline__ uint64_t V4FqReduce(unsigned __int128 x)
{
    constexpr uint64_t kQ = (static_cast<uint64_t>(1) << 61) - 1;
    const uint64_t lo = static_cast<uint64_t>(x & kQ);
    const uint64_t hi = static_cast<uint64_t>(x >> 61); // x < 2^122 => hi < 2^61
    uint64_t s = lo + hi;                                // < 2^62
    s = (s & kQ) + (s >> 61);                            // <= q + 1
    if (s >= kQ) {
        s -= kQ;
    }
    return s;
}

__device__ __forceinline__ uint64_t V4FqAdd(uint64_t a, uint64_t b)
{
    constexpr uint64_t kQ = (static_cast<uint64_t>(1) << 61) - 1;
    uint64_t s = a + b; // a, b < q < 2^61 => s < 2^62, no wrap
    if (s >= kQ) {
        s -= kQ;
    }
    return s;
}

__device__ __forceinline__ uint64_t V4FqNeg(uint64_t a)
{
    constexpr uint64_t kQ = (static_cast<uint64_t>(1) << 61) - 1;
    return a == 0 ? 0 : kQ - a;
}

__device__ __forceinline__ uint64_t V4FqMul(uint64_t a, uint64_t b)
{
    return V4FqReduce(static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b));
}

// Mirror of int8_field.cpp FqFromSigned (used via FqFromInt32 on C's entries).
// Here the argument is an exact INT32 entry of P or Q (|x| < 2^30 < q).
__device__ __forceinline__ uint64_t V4FqFromSigned(int64_t x)
{
    if (x >= 0) {
        return V4FqReduce(static_cast<unsigned __int128>(static_cast<uint64_t>(x)));
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(x + 1)) + 1; // safe for INT64_MIN
    return V4FqNeg(V4FqReduce(static_cast<unsigned __int128>(magnitude)));
}

// Chat = (P * Q) mod q. P is m x n (row-major, INT32), Q is n x m (row-major,
// INT32), Chat is m x m (row-major, canonical F_q in [0, q)). One thread per
// output entry; the length-n inner reduction is exact mod q. This is the small
// integer-ALU mod-q stage of §E.3 / §0.7-(3) -- deliberately NOT on tensor cores.
__global__ void V4CombineModQKernel(const int32_t* __restrict__ P,
                                    const int32_t* __restrict__ Q,
                                    uint64_t* __restrict__ Chat,
                                    uint32_t m,
                                    uint32_t n)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t total = static_cast<size_t>(m) * m;
    if (gid >= total) {
        return;
    }
    const uint32_t a = static_cast<uint32_t>(gid / m);
    const uint32_t c = static_cast<uint32_t>(gid % m);

    const int32_t* p_row = P + static_cast<size_t>(a) * n; // P[a][*]
    uint64_t acc = 0;
    for (uint32_t k = 0; k < n; ++k) {
        const uint64_t pq = V4FqMul(V4FqFromSigned(static_cast<int64_t>(p_row[k])),
                                    V4FqFromSigned(static_cast<int64_t>(Q[static_cast<size_t>(k) * m + c])));
        acc = V4FqAdd(acc, pq);
    }
    Chat[static_cast<size_t>(a) * m + c] = acc;
}

// Exact scalar INT32 GEMM fallback: C[M x N] = A[M x K] * B[K x N], all
// row-major, s8 inputs, s32 output. Identical integer semantics to
// matmul::int8_field::ExactDot, so it is bit-exact.
__global__ void V4GemmS8S32ScalarKernel(const int8_t* __restrict__ A,
                                        const int8_t* __restrict__ B,
                                        int32_t* __restrict__ C,
                                        uint32_t M,
                                        uint32_t N,
                                        uint32_t K)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t total = static_cast<size_t>(M) * N;
    if (gid >= total) {
        return;
    }
    const uint32_t r = static_cast<uint32_t>(gid / N);
    const uint32_t c = static_cast<uint32_t>(gid % N);
    const int8_t* a_row = A + static_cast<size_t>(r) * K;
    int32_t acc = 0;
    for (uint32_t k = 0; k < K; ++k) {
        acc += static_cast<int32_t>(a_row[k]) * static_cast<int32_t>(B[static_cast<size_t>(k) * N + c]);
    }
    C[gid] = acc;
}

// --- Batched-sketch device kernels (§K.2b, Appendix C-13) -------------------
//
// These three kernels are the only NEW device code the batched path needs on
// top of the per-nonce backend above: a pure int32 layout permutation, the
// entrywise limb decomposition, and the shifted mod-q recombine. All GEMMs
// reuse RunInt8Gemm / the scalar fallback unchanged.

// Vertical -> horizontal stack permutation. Qtall = [Q_1; Q_2; ...; Q_Q]
// (count*n x m row-major) is the output of the ONE stacked GEMM
// [B_1; ...; B_Q] * V; ComputeCombineLimbTensorStacked's contract wants
// Qstack = [Q_1 | Q_2 | ... | Q_Q] (n x count*m row-major, column block i
// holds Q_i). Row-major identity: Qtall[(i*n + k)*m + c] == Q_i[k][c] ==
// Qstack[k*(count*m) + i*m + c]. Every element is copied UNCHANGED (exact
// int32), so this stage cannot affect any byte.
__global__ void V4ScatterQStackKernel(const int32_t* __restrict__ Qtall,
                                      int32_t* __restrict__ Qstack,
                                      uint32_t n,
                                      uint32_t m,
                                      uint32_t count)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t per_nonce = static_cast<size_t>(n) * m;
    const size_t total = per_nonce * count;
    if (gid >= total) {
        return;
    }
    const uint32_t i = static_cast<uint32_t>(gid / per_nonce); // nonce index in window
    const size_t rem = gid % per_nonce;
    const uint32_t k = static_cast<uint32_t>(rem / m); // row inside Q_i
    const uint32_t c = static_cast<uint32_t>(rem % m); // column inside Q_i
    const size_t q_cols = static_cast<size_t>(count) * m;
    Qstack[static_cast<size_t>(k) * q_cols + static_cast<size_t>(i) * m + c] = Qtall[gid];
}

// Entrywise balanced base-2^7 limb decomposition -- a bit-for-bit device mirror
// of matmul_v4.cpp DecomposeLimbPlanes (Appendix C-13):
//     d = ((x + 64) & 127) - 64;  x = (x - d) / 128;   (4 digits, LSD first)
// Identical arithmetic statement-for-statement: `&` on the two's-complement
// int32 (C++20 mandates two's complement on host, CUDA guarantees it on
// device) yields the low 7 bits as a value in [0, 127], so d is the unique
// balanced digit in [-64, 63]; (x - d) is an exact multiple of 128, so the
// truncating signed division is exact. Plane l of the output is stored at
// planes[l*total ..], matching the CPU's planes[l][idx] indexing. The
// decomposition is total for every |x| < 128^4/2 = 2^27, guaranteed by the
// host-side CheckCombineLimbBound gate (|P|,|Q| <= 15,625*n).
__global__ void V4DecomposeLimbPlanesKernel(const int32_t* __restrict__ M,
                                            int8_t* __restrict__ planes,
                                            size_t total)
{
    constexpr uint32_t kLimbs = 4;     // == matmul::v4::kCombineLimbs (static_assert below)
    constexpr int32_t kLimbBase = 128; // == matmul::v4::kCombineLimbBase
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total) {
        return;
    }
    int32_t x = M[gid];
#pragma unroll
    for (uint32_t l = 0; l < kLimbs; ++l) {
        const int32_t d = ((x + 64) & (kLimbBase - 1)) - 64;
        planes[static_cast<size_t>(l) * total + gid] = static_cast<int8_t>(d);
        x = (x - d) / kLimbBase;
    }
}

// Keep the device-local limb constants pinned to the consensus constants.
static_assert(matmul::v4::kCombineLimbs == 4 && matmul::v4::kCombineLimbBase == 128,
              "V4DecomposeLimbPlanesKernel hard-codes the 4 x base-128 balanced decomposition");

// Shifted mod-q recombine of ONE limb-pair product (Appendix C-13):
//     Chat[idx] = FqAdd(Chat[idx], FqMul(weight, FqFromSigned(S[idx])))
// with weight = 2^(7*(i+j)) < q already canonical. Statement-for-statement the
// CPU recombine loop in ComputeCombineLimbTensorStacked; the device Fq helpers
// above are bit-for-bit the int8_field.cpp routines, and canonical residues
// are unique, so accumulating the 16 launches in the CPU's (i outer, j inner)
// order reproduces the identical canonical residue per entry.
__global__ void V4LimbRecombineKernel(const int32_t* __restrict__ S,
                                      uint64_t* __restrict__ Chat,
                                      uint64_t weight,
                                      size_t total)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total) {
        return;
    }
    Chat[gid] = V4FqAdd(Chat[gid], V4FqMul(weight, V4FqFromSigned(static_cast<int64_t>(S[gid]))));
}

constexpr uint32_t kThreads = 256;

bool CudaOk(cudaError_t e, const char* what, std::string& error)
{
    if (e != cudaSuccess) {
        error = std::string(what) + ": " + cudaGetErrorString(e);
        return false;
    }
    return true;
}

bool ForceScalarGemm()
{
    const char* env = std::getenv("BTX_MATMUL_V4_CUDA_GEMM");
    return env != nullptr && std::string(env) == "scalar";
}

// Exact INT8->INT32 GEMM via cuBLASLt, row-major layouts:
// C[M x N] = A[M x K] * B[K x N], A,B are device s8, C is device s32.
//   Atype=Btype=CUDA_R_8I, Ctype=Dtype=CUDA_R_32I, computeType=CUBLAS_COMPUTE_32I,
//   scaleType=CUDA_R_32I (only alpha in {0,1}, beta in {0,1} supported), alpha=1,
//   beta=0. Row-major (CUBLASLT_ORDER_ROW) so the device buffers map 1:1 to the
//   CPU row-major matrices without any transpose/transform. INT32 accumulation is
//   exact and order-independent, so the bytes match the CPU reference.
bool RunInt8Gemm(cublasLtHandle_t lt,
                 cudaStream_t stream,
                 void* workspace,
                 size_t workspace_size,
                 const int8_t* dA,
                 const int8_t* dB,
                 int32_t* dC,
                 uint32_t M,
                 uint32_t N,
                 uint32_t K,
                 std::string& error)
{
    cublasLtMatmulDesc_t op_desc = nullptr;
    cublasLtMatrixLayout_t a_layout = nullptr;
    cublasLtMatrixLayout_t b_layout = nullptr;
    cublasLtMatrixLayout_t c_layout = nullptr;
    cublasLtMatmulPreference_t preference = nullptr;
    bool ok = false;

    auto fail = [&](const char* what) {
        if (error.empty()) {
            error = std::string("cublasLt ") + what + " failed";
        }
        return false;
    };

    do {
        if (cublasLtMatmulDescCreate(&op_desc, CUBLAS_COMPUTE_32I, CUDA_R_32I) != CUBLAS_STATUS_SUCCESS) {
            fail("MatmulDescCreate");
            break;
        }
        const cublasOperation_t op_n = CUBLAS_OP_N;
        if (cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_TRANSA, &op_n, sizeof(op_n)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_TRANSB, &op_n, sizeof(op_n)) != CUBLAS_STATUS_SUCCESS) {
            fail("MatmulDescSetAttribute(TRANS)");
            break;
        }

        // Row-major: leading dimension == number of columns.
        const cublasLtOrder_t row = CUBLASLT_ORDER_ROW;
        auto make_layout = [&](cublasLtMatrixLayout_t* layout, cudaDataType_t dtype,
                               uint64_t rows, uint64_t cols, int64_t ld) -> bool {
            if (cublasLtMatrixLayoutCreate(layout, dtype, rows, cols, ld) != CUBLAS_STATUS_SUCCESS) {
                return false;
            }
            return cublasLtMatrixLayoutSetAttribute(*layout, CUBLASLT_MATRIX_LAYOUT_ORDER,
                                                    &row, sizeof(row)) == CUBLAS_STATUS_SUCCESS;
        };
        if (!make_layout(&a_layout, CUDA_R_8I, M, K, K) ||
            !make_layout(&b_layout, CUDA_R_8I, K, N, N) ||
            !make_layout(&c_layout, CUDA_R_32I, M, N, N)) {
            fail("MatrixLayoutCreate");
            break;
        }

        if (cublasLtMatmulPreferenceCreate(&preference) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulPreferenceSetAttribute(preference, CUBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,
                                                 &workspace_size, sizeof(workspace_size)) != CUBLAS_STATUS_SUCCESS) {
            fail("MatmulPreference");
            break;
        }

        cublasLtMatmulHeuristicResult_t heuristic{};
        int returned = 0;
        const cublasStatus_t hstat = cublasLtMatmulAlgoGetHeuristic(
            lt, op_desc, a_layout, b_layout, c_layout, c_layout, preference, 1, &heuristic, &returned);
        if (hstat != CUBLAS_STATUS_SUCCESS || returned == 0) {
            error = "cublasLtMatmulAlgoGetHeuristic found no INT8 algorithm";
            break;
        }

        const int32_t alpha = 1;
        const int32_t beta = 0;
        const cublasStatus_t mstat = cublasLtMatmul(
            lt, op_desc,
            &alpha,
            dA, a_layout,
            dB, b_layout,
            &beta,
            dC, c_layout,
            dC, c_layout,
            &heuristic.algo,
            workspace, workspace_size,
            stream);
        if (mstat != CUBLAS_STATUS_SUCCESS) {
            error = "cublasLtMatmul failed, status " + std::to_string(static_cast<int>(mstat));
            break;
        }
        ok = true;
    } while (false);

    if (preference) cublasLtMatmulPreferenceDestroy(preference);
    if (c_layout) cublasLtMatrixLayoutDestroy(c_layout);
    if (b_layout) cublasLtMatrixLayoutDestroy(b_layout);
    if (a_layout) cublasLtMatrixLayoutDestroy(a_layout);
    if (op_desc) cublasLtMatmulDescDestroy(op_desc);
    return ok;
}

bool LaunchScalarGemm(cudaStream_t stream,
                      const int8_t* dA,
                      const int8_t* dB,
                      int32_t* dC,
                      uint32_t M,
                      uint32_t N,
                      uint32_t K,
                      std::string& error)
{
    const size_t total = static_cast<size_t>(M) * N;
    const uint32_t blocks = static_cast<uint32_t>((total + kThreads - 1) / kThreads);
    V4GemmS8S32ScalarKernel<<<blocks, kThreads, 0, stream>>>(dA, dB, dC, M, N, K);
    return CudaOk(cudaGetLastError(), "scalar GEMM launch", error);
}

// Grid size for a 1-thread-per-element launch. Largest batched total is
// n*(Q*m) int32 elements = 2^30 at n=4096, Q=kMaxBatchedWindow, so blocks
// <= 2^30/256 = 4,194,304 -- comfortably under the 2^31-1 gridDim.x limit.
uint32_t BlocksFor(size_t total)
{
    return static_cast<uint32_t>((total + kThreads - 1) / kThreads);
}

// One exact s8xs8->s32 GEMM with the same tensor-core-first / scalar-fallback
// policy as ComputeSketchOnDevice: cuBLASLt IMMA when available (and not
// overridden by BTX_MATMUL_V4_CUDA_GEMM=scalar), else the exact scalar kernel.
// Both paths compute the identical exact integer product -- INT32 accumulation
// is associative and order-independent (§B.6) -- so a mid-window fallback
// cannot change any byte of any digest.
bool RunGemmAuto(cublasLtHandle_t lt,
                 cudaStream_t stream,
                 void* workspace,
                 size_t workspace_size,
                 const int8_t* dA,
                 const int8_t* dB,
                 int32_t* dC,
                 uint32_t M,
                 uint32_t N,
                 uint32_t K,
                 std::string& error)
{
    if (lt != nullptr && workspace != nullptr && !ForceScalarGemm()) {
        std::string gemm_err;
        if (RunInt8Gemm(lt, stream, workspace, workspace_size, dA, dB, dC, M, N, K, gemm_err)) {
            return true;
        }
        // Non-fatal: fall through to the exact scalar path (also bit-exact).
    }
    return LaunchScalarGemm(stream, dA, dB, dC, M, N, K, error);
}

// Device evaluation of Chat = (U*A)(B*V) mod q. All host inputs are row-major
// balanced-s8 as produced by matmul_v4::ExpandOperand / ExpandProjector.
//   A,B : n x n     U : m x n     V : n x m     Chat_out : m x m (canonical F_q)
bool ComputeSketchOnDevice(const int8_t* A_host,
                           const int8_t* B_host,
                           const int8_t* U_host,
                           const int8_t* V_host,
                           uint32_t n,
                           uint32_t m,
                           Fq* Chat_host,
                           std::string& error)
{
    const size_t nn = static_cast<size_t>(n) * n;
    const size_t mn = static_cast<size_t>(m) * n; // U and P
    const size_t nm = static_cast<size_t>(n) * m; // V and Q
    const size_t mm = static_cast<size_t>(m) * m; // Chat

    int8_t* dA = nullptr;
    int8_t* dB = nullptr;
    int8_t* dU = nullptr;
    int8_t* dV = nullptr;
    int32_t* dP = nullptr; // P = U*A, m x n
    int32_t* dQ = nullptr; // Q = B*V, n x m
    uint64_t* dChat = nullptr;
    void* workspace = nullptr;
    cudaStream_t stream = nullptr;
    cublasLtHandle_t lt = nullptr;

    // 32 MiB matmul workspace (cuBLASLt heuristics may want scratch; ignored by
    // the scalar path).
    constexpr size_t kWorkspaceBytes = size_t{32} << 20;

    bool ok = false;
    do {
        if (!CudaOk(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreate", error)) break;

        if (!CudaOk(cudaMalloc(&dA, nn), "cudaMalloc A", error)) break;
        if (!CudaOk(cudaMalloc(&dB, nn), "cudaMalloc B", error)) break;
        if (!CudaOk(cudaMalloc(&dU, mn), "cudaMalloc U", error)) break;
        if (!CudaOk(cudaMalloc(&dV, nm), "cudaMalloc V", error)) break;
        if (!CudaOk(cudaMalloc(&dP, mn * sizeof(int32_t)), "cudaMalloc P", error)) break;
        if (!CudaOk(cudaMalloc(&dQ, nm * sizeof(int32_t)), "cudaMalloc Q", error)) break;
        if (!CudaOk(cudaMalloc(&dChat, mm * sizeof(uint64_t)), "cudaMalloc Chat", error)) break;

        if (!CudaOk(cudaMemcpyAsync(dA, A_host, nn, cudaMemcpyHostToDevice, stream), "H2D A", error)) break;
        if (!CudaOk(cudaMemcpyAsync(dB, B_host, nn, cudaMemcpyHostToDevice, stream), "H2D B", error)) break;
        if (!CudaOk(cudaMemcpyAsync(dU, U_host, mn, cudaMemcpyHostToDevice, stream), "H2D U", error)) break;
        if (!CudaOk(cudaMemcpyAsync(dV, V_host, nm, cudaMemcpyHostToDevice, stream), "H2D V", error)) break;

        bool used_tensor_cores = false;
        if (!ForceScalarGemm()) {
            if (cublasLtCreate(&lt) == CUBLAS_STATUS_SUCCESS &&
                cudaMalloc(&workspace, kWorkspaceBytes) == cudaSuccess) {
                std::string gemm_err;
                // RunInt8Gemm takes dims in (M, N, K) order (C[MxN] = A[MxK]*B[KxN]).
                // P = U * A : P[m x n] = U[m x n] * A[n x n]  => M=m, N=n, K=n  => (m, n, n)
                // Q = B * V : Q[n x m] = B[n x n] * V[n x m]  => M=n, N=m, K=n  => (n, m, n)
                // NB: Q's N and K differ (m != n), so the arg ORDER matters here; passing
                // (n, n, m) computes an n x n output that both diverges from the CPU
                // reference AND overruns dQ (sized n*m). Consensus-correctness fix.
                const bool p_ok = RunInt8Gemm(lt, stream, workspace, kWorkspaceBytes, dU, dA, dP, m, n, n, gemm_err);
                const bool q_ok = p_ok && RunInt8Gemm(lt, stream, workspace, kWorkspaceBytes, dB, dV, dQ, n, m, n, gemm_err);
                used_tensor_cores = p_ok && q_ok;
                if (!used_tensor_cores) {
                    // Non-fatal: fall back to the exact scalar path below.
                    error = gemm_err;
                }
            }
        }

        if (!used_tensor_cores) {
            // Exact scalar INT32 GEMM fallback (also bit-exact).
            error.clear();
            if (!LaunchScalarGemm(stream, dU, dA, dP, m, n, n, error)) break; // P = U*A : (M,N,K)=(m,n,n)
            if (!LaunchScalarGemm(stream, dB, dV, dQ, n, m, n, error)) break; // Q = B*V : (M,N,K)=(n,m,n)
        }

        // Chat = (P * Q) mod q  (exact integer-ALU mod-q GEMM, m x m outputs).
        const size_t combine_total = mm;
        const uint32_t combine_blocks = static_cast<uint32_t>((combine_total + kThreads - 1) / kThreads);
        V4CombineModQKernel<<<combine_blocks, kThreads, 0, stream>>>(dP, dQ, dChat, m, n);
        if (!CudaOk(cudaGetLastError(), "combine launch", error)) break;

        static_assert(sizeof(Fq) == sizeof(uint64_t), "Fq must be a 64-bit word");
        if (!CudaOk(cudaMemcpyAsync(Chat_host, dChat, mm * sizeof(uint64_t), cudaMemcpyDeviceToHost, stream),
                    "D2H Chat", error)) break;
        if (!CudaOk(cudaStreamSynchronize(stream), "stream sync", error)) break;
        ok = true;
    } while (false);

    if (workspace) cudaFree(workspace);
    if (lt) cublasLtDestroy(lt);
    if (dChat) cudaFree(dChat);
    if (dQ) cudaFree(dQ);
    if (dP) cudaFree(dP);
    if (dV) cudaFree(dV);
    if (dU) cudaFree(dU);
    if (dB) cudaFree(dB);
    if (dA) cudaFree(dA);
    if (stream) cudaStreamDestroy(stream);
    return ok;
}

} // namespace

bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                        uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    // Validity gate: identical to matmul_v4::ComputeDigest (pow_v4.cpp) so the
    // accel and CPU paths agree on which (n, rounds) are computable.
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul::v4::kTileB, m)) {
        return false;
    }
    if (rounds == 0) {
        return false;
    }

    // --- Operand derivation: REUSE the exact CPU routines so A,B,U,V are
    //     byte-identical to matmul_v4.cpp (§A.2/§E.1). No re-derivation on device.
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
    const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
    const std::pair<uint256, uint256> proj = matmul::v4::DeriveProjectorSeeds(header);

    const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);         // n x n
    const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);         // n x n
    const std::vector<int8_t> U = matmul::v4::ExpandProjector(proj.first, m, n); // m x n
    const std::vector<int8_t> V = matmul::v4::ExpandProjector(proj.second, n, m); // n x m

    // --- Chat = (U*A)(B*V) mod q on the GPU (INT8 tensor-core GEMMs + mod-q).
    std::vector<Fq> Chat(static_cast<size_t>(m) * m);
    std::string error;
    if (!ComputeSketchOnDevice(A.data(), B.data(), U.data(), V.data(), n, m, Chat.data(), error)) {
        // Any CUDA/cuBLASLt failure -> report failure; the dispatch layer runs
        // the CPU reference instead. (Optionally log `error`.)
        return false;
    }

    // --- Serialize + digest: REUSE the exact CPU routines (§E.1/§0.7-(3)) so the
    //     committed bytes and H(sigma||Chat) are byte-identical to the CPU.
    payload_out = matmul::v4::SerializeSketch(Chat);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, payload_out);
    return true;
}

// ===========================================================================
// BATCHED-SKETCH backend (design spec §K.2b, Appendix C-13) -- the device
// mirror of matmul::v4::BatchedSketchMiner::Mine (matmul_v4_batch.cpp). This
// is the B2f port that makes the datacenter-vs-consumer measurement (B2g) and
// ASERT calibration (B2b) runnable on NVIDIA hardware.
//
// STAGE MAP (host <-> device):
//   HOST  : template hash + fail-closed projection check for every header;
//           sigma_i; expansion of A, U, V (template-scoped, once) and the
//           nonce-fresh B_i -- all via the exact matmul_v4 routines, so every
//           operand byte is identical to the CPU reference.
//   DEVICE: P = U*A                    -- ONE m x n x n INT8 GEMM per call.
//           Qtall = [B_1;...;B_Q] * V  -- ONE (Q*n) x n x m stacked INT8 GEMM
//                                         per window chunk (the Q per-nonce
//                                         Q_i = B_i*V GEMMs fused; row block i
//                                         of Qtall IS Q_i exactly).
//           scatter Qtall -> Qstack    -- pure int32 permutation into the
//                                         n x Q*m horizontal-stack layout that
//                                         ComputeCombineLimbTensorStacked
//                                         defines (column block i = Q_i).
//           limb decompose P, Qstack   -- V4DecomposeLimbPlanesKernel, the
//                                         bit-for-bit DecomposeLimbPlanes
//                                         mirror (see kernel comment).
//           16 limb GEMMs + recombine  -- S_ij = P_i * Qstack_j, each an
//                                         m x (Q*m) x n INT8->INT32 tensor
//                                         GEMM (the ONE LARGE DENSE COMBINE,
//                                         run per limb pair), folded as
//                                         Chat += 2^(7(i+j)) * S_ij mod q on
//                                         the integer ALU in the CPU's
//                                         (i outer, j inner) order.
//   HOST  : slice column block i -> Chat_i (m x m), SerializeSketch,
//           H(sigma_i || payload_i) -- exact CPU routines again.
//
// BIT-EXACTNESS. Stages either (a) reuse host consensus routines verbatim,
// (b) compute exact integer products (INT32 accumulation, order-independent,
// §B.6 -- true for cuBLASLt IMMA and the scalar fallback alike), (c) permute
// int32 values unchanged, or (d) replicate DecomposeLimbPlanes /
// FqAdd(FqMul(w, FqFromSigned(.))) statement-for-statement with the device Fq
// helpers that mirror int8_field.cpp bit-for-bit. Canonical residues in [0,q)
// are unique, so identical integers => identical residues => identical
// SerializeSketch bytes => identical digests. NO floating point anywhere.
//
// DEVICE MEMORY BUDGET (the "large batched buffer" strategy). Bytes at
// dimension n, m = n/4, window chunk Q (values at n=4096, m=1024):
//     template-scoped, once per call, reused across chunks:
//         dA        n*n            s8    16 MiB
//         dU        m*n            s8     4 MiB
//         dV        n*m            s8     4 MiB
//         dP        m*n            s32   16 MiB
//         dPplanes  4*m*n          s8    16 MiB      (56 MiB total)
//     per-chunk, sized once for min(count, kMaxBatchedWindow) and REUSED for
//     every chunk of the window (no per-nonce cudaMalloc traffic):
//         dBstack   Q*n*n          s8    Q*16 MiB
//         dQtall    Q*n*m          s32   Q*16 MiB
//         dQstack   n*(Q*m)        s32   Q*16 MiB
//         dQplanes  4*n*(Q*m)      s8    Q*16 MiB
//         dS        m*(Q*m)        s32   Q* 4 MiB    (one limb pair at a time;
//                                                     16 resident copies would
//                                                     cost Q*64 MiB for zero
//                                                     correctness benefit)
//         dChat     m*(Q*m)        u64   Q* 8 MiB
//     plus the 32 MiB cuBLASLt workspace => ~56 MiB + Q*76 MiB device, and
//     Q*16 MiB (Bstack staging) + Q*8 MiB (Chat_wide) host. This is the
//     device-side big sibling of the CPU header's "~64 MiB int32 intermediates
//     at n=4096, b=4, Q=8" note. Q = kDefaultBatchedWindow = 64 -> ~4.9 GiB;
//     Q = kMaxBatchedWindow = 256 -> ~19.1 GiB, sized to fill an H100 80 GB /
//     B200 while leaving headroom; larger requested windows are processed in
//     internal chunks of 256 (per-nonce results are independent, so chunking
//     changes no byte). If cudaMalloc fails (small device, huge n), we fail
//     closed and the dispatcher falls back to the CPU miner.
//
// THROUGHPUT NOTE (same precedent as the per-nonce backend's GEMM API CHOICE
// block): all GEMMs use row-major CUBLASLT_ORDER_ROW layouts, which cuBLASLt
// serves on the integer tensor cores (IMMA) on SM_75+ for these shapes. The
// documented maximum-throughput IMMA layout swap -- transform operands into
// CUBLASLT_ORDER_COL32 (A/C) x CUBLASLT_ORDER_COL4_4R2_8C / COL32_2R_4R4 (B,
// with CUBLAS_OP_T) via cublasLtMatrixTransform, run cublasLtMatmul in the
// transformed layouts, transform C back -- applies UNCHANGED to the batched
// GEMMs here (the transforms are byte-preserving permutations of exact int32/
// int8 data, so the result bytes cannot change). It pays off most for the 16
// combine GEMMs, whose m x (Q*m) x n shape dominates the window; the Qstack
// limb planes could even be transformed ONCE and reused across all 4 P-limb
// passes. Left as a hardware-validated follow-up, exactly like the per-nonce
// path. An alternative to the Qtall+scatter pair is a strided-batched GEMM
// (CUBLASLT_MATRIX_LAYOUT_BATCH_COUNT = Q with C ld = Q*m, batch stride = m)
// writing each Q_i directly into its Qstack column block; that saves one
// Q*16 MiB buffer and the permutation kernel but couples correctness to
// less-traveled layout attributes, so the port keeps the transparent
// permutation (it is bandwidth-trivial next to the GEMMs).
// ===========================================================================

bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                std::vector<uint256>& digests_out,
                                std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();

    // Validity gates: identical to the CPU BatchedSketchMiner (ValidateDims +
    // CheckCombineLimbBound) plus the per-nonce backend's rounds gate, so the
    // accel and CPU paths agree on which (n, rounds) are computable.
    uint32_t m = 0;
    if (headers.empty()) {
        return false;
    }
    if (!matmul::v4::ValidateDims(n, matmul::v4::kTileB, m)) {
        return false;
    }
    if (!matmul::v4::CheckCombineLimbBound(n)) {
        return false;
    }
    if (rounds == 0) {
        return false;
    }
    const uint32_t count = static_cast<uint32_t>(headers.size());

    // --- HOST: template projection (fail closed) + per-nonce sigma. Every
    //     header MUST project onto one shared template hash; combining a stale
    //     template's A/U/V/P with a fresh header would produce digests that
    //     are NOT the consensus digests for that header.
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(headers[0]);
    std::vector<uint256> sigmas(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (matmul::v4::ComputeTemplateHash(headers[i]) != template_hash) {
            return false;
        }
        sigmas[i] = matmul::v4::DeriveSigma(headers[i]);
    }

    // --- HOST: template-scoped operands, byte-identical to the CPU miner
    //     (BatchedSketchMiner ctor): A, U, V expanded ONCE per call via the
    //     exact matmul_v4 routines (§A.2 v4.1, invariant I1').
    const uint256 seed_a = matmul::v4::DeriveOperandSeed(headers[0], matmul::v4::Operand::A);
    const std::pair<uint256, uint256> proj = matmul::v4::DeriveProjectorSeeds(headers[0]);
    const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);          // n x n
    const std::vector<int8_t> U = matmul::v4::ExpandProjector(proj.first, m, n); // m x n
    const std::vector<int8_t> V = matmul::v4::ExpandProjector(proj.second, n, m); // n x m

    const uint32_t chunk_cap = std::min(count, kMaxBatchedWindow);
    const size_t nn = static_cast<size_t>(n) * n;
    const size_t mn = static_cast<size_t>(m) * n;     // U, P, and one P limb plane
    const size_t cap_qcols = static_cast<size_t>(chunk_cap) * m;
    const size_t cap_stack = static_cast<size_t>(n) * cap_qcols; // Qtall/Qstack elems
    const size_t cap_out = static_cast<size_t>(m) * cap_qcols;   // Chat_wide elems

    // Host staging, allocated once and reused per chunk.
    std::vector<int8_t> bstack_host(static_cast<size_t>(chunk_cap) * nn);
    std::vector<uint64_t> chat_host(cap_out);

    int8_t* dA = nullptr;
    int8_t* dU = nullptr;
    int8_t* dV = nullptr;
    int32_t* dP = nullptr;      // P = U*A, m x n
    int8_t* dPplanes = nullptr; // 4 limb planes of P, plane stride mn
    int8_t* dBstack = nullptr;  // [B_1; ...; B_Q], Q*n x n
    int32_t* dQtall = nullptr;  // [Q_1; ...; Q_Q], Q*n x m
    int32_t* dQstack = nullptr; // [Q_1 | ... | Q_Q], n x Q*m
    int8_t* dQplanes = nullptr; // 4 limb planes of Qstack, plane stride n*Q*m
    int32_t* dS = nullptr;      // one limb-pair product S_ij, m x Q*m
    uint64_t* dChat = nullptr;  // Chat_wide accumulator, m x Q*m
    void* workspace = nullptr;
    cudaStream_t stream = nullptr;
    cublasLtHandle_t lt = nullptr;
    constexpr size_t kWorkspaceBytes = size_t{32} << 20;

    digests_out.resize(count);
    payloads_out.resize(count);

    std::string error;
    bool ok = false;
    do {
        if (!CudaOk(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreate", error)) break;

        if (!CudaOk(cudaMalloc(&dA, nn), "cudaMalloc A", error)) break;
        if (!CudaOk(cudaMalloc(&dU, mn), "cudaMalloc U", error)) break;
        if (!CudaOk(cudaMalloc(&dV, mn), "cudaMalloc V", error)) break;
        if (!CudaOk(cudaMalloc(&dP, mn * sizeof(int32_t)), "cudaMalloc P", error)) break;
        if (!CudaOk(cudaMalloc(&dPplanes, mn * matmul::v4::kCombineLimbs), "cudaMalloc Pplanes", error)) break;
        if (!CudaOk(cudaMalloc(&dBstack, static_cast<size_t>(chunk_cap) * nn), "cudaMalloc Bstack", error)) break;
        if (!CudaOk(cudaMalloc(&dQtall, cap_stack * sizeof(int32_t)), "cudaMalloc Qtall", error)) break;
        if (!CudaOk(cudaMalloc(&dQstack, cap_stack * sizeof(int32_t)), "cudaMalloc Qstack", error)) break;
        if (!CudaOk(cudaMalloc(&dQplanes, cap_stack * matmul::v4::kCombineLimbs), "cudaMalloc Qplanes", error)) break;
        if (!CudaOk(cudaMalloc(&dS, cap_out * sizeof(int32_t)), "cudaMalloc S", error)) break;
        if (!CudaOk(cudaMalloc(&dChat, cap_out * sizeof(uint64_t)), "cudaMalloc Chat", error)) break;

        if (!CudaOk(cudaMemcpyAsync(dA, A.data(), nn, cudaMemcpyHostToDevice, stream), "H2D A", error)) break;
        if (!CudaOk(cudaMemcpyAsync(dU, U.data(), mn, cudaMemcpyHostToDevice, stream), "H2D U", error)) break;
        if (!CudaOk(cudaMemcpyAsync(dV, V.data(), mn, cudaMemcpyHostToDevice, stream), "H2D V", error)) break;

        // cuBLASLt is best-effort: on handle/workspace failure every GEMM runs
        // the exact scalar fallback instead (identical bytes, lower speed).
        if (!ForceScalarGemm()) {
            if (cublasLtCreate(&lt) != CUBLAS_STATUS_SUCCESS) {
                lt = nullptr;
            } else if (cudaMalloc(&workspace, kWorkspaceBytes) != cudaSuccess) {
                workspace = nullptr;
            }
        }

        // --- TEMPLATE-scoped device work, ONCE per call: P = U*A (m x n x n
        //     exact INT8->INT32 GEMM), then its 4 limb planes.
        if (!RunGemmAuto(lt, stream, workspace, kWorkspaceBytes, dU, dA, dP, m, n, n, error)) break;
        V4DecomposeLimbPlanesKernel<<<BlocksFor(mn), kThreads, 0, stream>>>(dP, dPplanes, mn);
        if (!CudaOk(cudaGetLastError(), "P limb decompose launch", error)) break;

        // --- Window chunks. Per-nonce results are independent (every Chat_i
        //     entry depends only on its own P row and Q_i column), so chunking
        //     is byte-transparent.
        bool chunk_failed = false;
        for (uint32_t start = 0; start < count; start += chunk_cap) {
            const uint32_t q = std::min(chunk_cap, count - start);
            const size_t q_cols = static_cast<size_t>(q) * m;
            const size_t stack_elems = static_cast<size_t>(n) * q_cols;
            const size_t out_elems = static_cast<size_t>(m) * q_cols;

            // HOST: expand the chunk's nonce-fresh B_i (exact CPU routine,
            // §A.2/I1') into the vertical staging stack. On a production
            // miner this expansion overlaps the previous chunk's GEMMs (SHA
            // on host, GEMMs on device); kept sequential here for clarity.
            for (uint32_t idx = 0; idx < q; ++idx) {
                const uint256 seed_b =
                    matmul::v4::DeriveOperandSeed(headers[start + idx], matmul::v4::Operand::B);
                const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
                std::copy(B.begin(), B.end(), bstack_host.begin() + static_cast<size_t>(idx) * nn);
            }
            if (!CudaOk(cudaMemcpyAsync(dBstack, bstack_host.data(), static_cast<size_t>(q) * nn,
                                        cudaMemcpyHostToDevice, stream), "H2D Bstack", error)) {
                chunk_failed = true;
                break;
            }

            // ONE stacked GEMM Qtall = [B_1; ...; B_q] * V ((q*n) x n x m):
            // row block i of Qtall is exactly Q_i = B_i*V because each output
            // row depends only on its own Bstack row (exact INT32).
            if (!RunGemmAuto(lt, stream, workspace, kWorkspaceBytes, dBstack, dV, dQtall,
                             q * n, m, n, error)) {
                chunk_failed = true;
                break;
            }

            // Qtall -> Qstack permutation, then the entrywise limb planes.
            V4ScatterQStackKernel<<<BlocksFor(stack_elems), kThreads, 0, stream>>>(dQtall, dQstack, n, m, q);
            if (!CudaOk(cudaGetLastError(), "Qstack scatter launch", error)) {
                chunk_failed = true;
                break;
            }
            V4DecomposeLimbPlanesKernel<<<BlocksFor(stack_elems), kThreads, 0, stream>>>(
                dQstack, dQplanes, stack_elems);
            if (!CudaOk(cudaGetLastError(), "Q limb decompose launch", error)) {
                chunk_failed = true;
                break;
            }

            // Chat_wide = 0, then the 16 limb-pair combine GEMMs
            // S_ij = P_i * Qstack_j (m x q*m x n) with the shifted mod-q fold,
            // in the CPU's (i outer, j inner) order.
            if (!CudaOk(cudaMemsetAsync(dChat, 0, out_elems * sizeof(uint64_t), stream),
                        "Chat memset", error)) {
                chunk_failed = true;
                break;
            }
            for (uint32_t i = 0; i < matmul::v4::kCombineLimbs && !chunk_failed; ++i) {
                for (uint32_t j = 0; j < matmul::v4::kCombineLimbs; ++j) {
                    const int8_t* Pi = dPplanes + static_cast<size_t>(i) * mn;
                    const int8_t* Qj = dQplanes + static_cast<size_t>(j) * stack_elems;
                    if (!RunGemmAuto(lt, stream, workspace, kWorkspaceBytes, Pi, Qj, dS,
                                     m, static_cast<uint32_t>(q_cols), n, error)) {
                        chunk_failed = true;
                        break;
                    }
                    // weight = 2^(7*(i+j)) mod q; exponent <= 42 < 61 so the
                    // canonical weight is the plain power of two (CPU-equal).
                    const uint64_t w = static_cast<uint64_t>(1) << (7 * (i + j));
                    V4LimbRecombineKernel<<<BlocksFor(out_elems), kThreads, 0, stream>>>(dS, dChat, w, out_elems);
                    if (!CudaOk(cudaGetLastError(), "limb recombine launch", error)) {
                        chunk_failed = true;
                        break;
                    }
                }
            }
            if (chunk_failed) break;

            static_assert(sizeof(Fq) == sizeof(uint64_t), "Fq must be a 64-bit word");
            if (!CudaOk(cudaMemcpyAsync(chat_host.data(), dChat, out_elems * sizeof(uint64_t),
                                        cudaMemcpyDeviceToHost, stream), "D2H Chat", error) ||
                !CudaOk(cudaStreamSynchronize(stream), "stream sync", error)) {
                chunk_failed = true;
                break;
            }

            // HOST: slice column block idx -> Chat_idx (m x m), serialize and
            // digest with the exact CPU routines -- the same loop as
            // BatchedSketchMiner::Mine.
            for (uint32_t idx = 0; idx < q; ++idx) {
                std::vector<Fq> Chat(static_cast<size_t>(m) * m);
                for (uint32_t a = 0; a < m; ++a) {
                    const uint64_t* src = chat_host.data() + static_cast<size_t>(a) * q_cols +
                                          static_cast<size_t>(idx) * m;
                    std::copy(src, src + m, Chat.begin() + static_cast<size_t>(a) * m);
                }
                payloads_out[start + idx] = matmul::v4::SerializeSketch(Chat);
                digests_out[start + idx] =
                    matmul::v4::ComputeSketchDigest(sigmas[start + idx], payloads_out[start + idx]);
            }
        }
        if (chunk_failed) break;
        ok = true;
    } while (false);

    if (workspace) cudaFree(workspace);
    if (lt) cublasLtDestroy(lt);
    if (dChat) cudaFree(dChat);
    if (dS) cudaFree(dS);
    if (dQplanes) cudaFree(dQplanes);
    if (dQstack) cudaFree(dQstack);
    if (dQtall) cudaFree(dQtall);
    if (dBstack) cudaFree(dBstack);
    if (dPplanes) cudaFree(dPplanes);
    if (dP) cudaFree(dP);
    if (dV) cudaFree(dV);
    if (dU) cudaFree(dU);
    if (dA) cudaFree(dA);
    if (stream) cudaStreamDestroy(stream);

    if (!ok) {
        // Fail closed: no partial windows. The dispatcher falls back to the
        // CPU reference for the whole window. (Optionally log `error`.)
        digests_out.clear();
        payloads_out.clear();
        return false;
    }
    return true;
}

} // namespace matmul_v4::cuda
