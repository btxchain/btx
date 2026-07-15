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
                // P = U * A : (m x n) = (m x n) * (n x n)  => M=m, K=n, N=n
                // Q = B * V : (n x m) = (n x n) * (n x m)  => M=n, K=n, N=m
                const bool p_ok = RunInt8Gemm(lt, stream, workspace, kWorkspaceBytes, dU, dA, dP, m, n, n, gemm_err);
                const bool q_ok = p_ok && RunInt8Gemm(lt, stream, workspace, kWorkspaceBytes, dB, dV, dQ, n, n, m, gemm_err);
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
            if (!LaunchScalarGemm(stream, dU, dA, dP, m, n, n, error)) break; // P = U*A
            if (!LaunchScalarGemm(stream, dB, dV, dQ, n, n, m, error)) break; // Q = B*V
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

} // namespace matmul_v4::cuda
