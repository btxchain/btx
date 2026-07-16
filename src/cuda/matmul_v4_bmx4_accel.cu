// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_bmx4_accel.h>

#include <cuda/cuda_context.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cublasLt.h>
#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

// ===========================================================================
// MatMul v4.2 / ENC-BMX4C NVIDIA backend (FP4-native + INT8 full-rate tiers).
//
// This is the BMX4-C sibling of the v4.1 batched backend (matmul_v4_accel.cu,
// whose stage map, memory discipline and verify+fallback contract it mirrors).
// The CPU ground truth is matmul::v4::bmx4::ComputeDigestBMX4C
// (src/matmul/matmul_v4_bmx4.cpp); the normative spec is
// doc/btx-matmul-v4.2-bmx4c-spec.md (cited below as "spec").
//
// STAGE MAP (host <-> device):
//   HOST  : template hash + fail-closed projection check for every header;
//           sigma_i; expansion of the (mu, e) planes / dequantized operands
//           and the M11 projectors via the EXACT committed routines
//           (ExpandMantissaStream / ExpandScaleStream / ExpandOperandA/B /
//           ExpandProjectorBMX4C) — every operand byte identical to the CPU
//           reference by construction.
//   DEVICE: P = U*Ahat            -- once per call (template-scoped, I1').
//           Qtall = [B_1;...;B_q]*V -- stacked per window chunk.
//           scatter Qtall -> Qstack -- pure int32 permutation.
//           base-2^6 limb decompose P, Qstack (remainder-top rule).
//           16 limb-pair s8 GEMMs + shifted mod-q fold (weights 2^(6(i+j))).
//   HOST  : slice column block i -> Chat_i, SerializeSketch,
//           H(sigma_i || payload_i) -- exact CPU routines again.
//
// TIER SELECTION (the C-1' gate, spec §5.1/§5.2):
//
//   NATIVE FP4 (Blackwell tcgen05 `mxf4` via cuBLASLt block-scaled matmul):
//     eligible iff ALL of
//       (1) built against cuBLASLt >= 12.8 (the block-scaled FP4 API);
//       (2) the device reports SM major >= 10 (Blackwell tensor units);
//       (3) shape conformance: n % 32 == 0 (K blocks; already pinned by
//           ValidateDimsBMX4C) and m % 32 == 0 (conservative layout gate);
//       (4) THE t = 24 PROOF: the in-process C-1' qualification vectors
//           (Bmx4QualifyMxf4 below) pass bit-for-bit on this silicon, with
//           partial sums that PROVABLY enter the rounding regime of any
//           narrower accumulator. Spec §5.2: "t = 24 REQUIRED for the native
//           hardware-scaled path"; a t ~ 14 device (the Hopper FP8 precedent)
//           MUST fail here and fall to the INT8 tier. Datasheet claims are
//           never trusted; only the vectors decide (spec §5.1, §5.3, M-t24).
//     If ANY of these fails, the backend falls to the INT8 tier — the spec's
//     fallback ladder row "INT8 1-GEMM on pre-shifted operands" (§5.2): the
//     ladder is graceful and fail-closed, and on NVIDIA parts the INT8 rung
//     always exists (IMMA), so no request ever silently degrades exactness.
//
//   INT8 FALLBACK (1 GEMM, full rate): the dequantized operands satisfy
//     |Ahat|,|Bhat| <= E_max = 48 <= 127 (spec §1.3 "the load-bearing
//     inequality"), so the WHOLE operand stage is one plain s8xs8->s32 IMMA
//     GEMM on pre-shifted operands — no Ozaki slicing, no K', true int32
//     accumulation, exactly the v4.1 backend's machinery with BMX4-C bytes.
//
// THE NATIVE-FP4 EVALUATION (exactness by construction):
//
//   The committed scale planes are blocked along the BASE product's
//   contraction dimension (spec §1.3: Ahat per (row i, 32-column block);
//   Bhat per (32-row block, column j)). The MARGINAL GEMMs contract along the
//   OTHER axis of each operand (P = U*Ahat contracts Ahat's rows; Q = Bhat*V
//   contracts Bhat's columns), so the committed scales are NOT constant over
//   32-element runs of those GEMMs' K dimension and therefore cannot legally
//   occupy the hardware per-32-K-block SFA/SFB scale slots of the marginal
//   GEMMs. (They CAN for the full-C base GEMM Ahat*Bhat — the §5.2 row-1
//   path — but the marginal factoring is what the batched miner runs.)
//
//   The backend therefore applies the E8M0 scale as an EXACT SHIFT, which is
//   all an E8M0 scale ever is (a pure exponent add — spec §2.2): split each
//   operand by scale code,
//
//       Ahat = sum_{e=0}^{3} 2^e * A_e,   A_e[i][k] = mu_A[i][k] * [e_A(i,k/32) == e]
//       Bhat = sum_{e=0}^{3} 2^e * B_e    (mask along Bhat's own scale plane)
//
//   where every A_e / B_e entry is in M11 — EXACTLY representable in E2M1 by
//   construction (spec §1.1: M11 IS the integer subset of E2M1; the sampler's
//   accepted nibble IS the element's E2M1 bit pattern, §1.2). Then
//
//       P = U*Ahat = sum_e 2^e * (U * A_e)         (4 mxf4 GEMMs + shift-add)
//       Q = Bhat*V = sum_e 2^e * (B_e * V)         (4 mxf4 GEMMs + shift-add)
//
//   as EXACT INTEGER identities. Each mxf4 GEMM multiplies pure M11 mantissa
//   planes (per-MAC |mu*mu'| <= 36, spec §2.2) under UNIT hardware scales
//   (E8M0 code 127 = 2^0), accumulating in the device's FP32 path:
//     * every product is an integer <= 36, exact in any >= 6-bit multiplier;
//     * every partial sum is an integer bounded by 36n <= 36*29,127 < 2^21
//       (ValidateDimsBMX4C pins 288n <= 2^23-1, and 36n = 288n/8 < 2^20.1),
//       far below the PROVEN t = 24 capacity, so by the no-rounding theorem
//       (doc/btx-matmul-v4-exact-int-on-float.md §2) NO addition ever rounds.
//       The "blocked extract-and-promote" schedule (K') degenerates to a
//       single block: K' = floor(2^24/36) = 466,033 >= n for every valid
//       dimension, so zero promotions are needed — matching spec §5.2 row 2
//       ("zero promotions at every header n").
//     * the FP32 result is an exactly-held integer < 2^24, converted to int32
//       losslessly and folded as P += (int32)D_e << e; |P| <= 288n < 2^23
//       fits int32 exactly.
//   Exact integer addition is associative and commutative, so the library's
//   tile/reduction order is irrelevant to the RESULT bytes (spec §5.1-(iv)):
//   P and Q equal the CPU's ComputeProjectedLeft/Right integers entry for
//   entry, hence every downstream byte is identical.
//
//   FAST-ACCUM IS NEVER ENABLED: cuBLASLt's reduced-precision accumulation
//   mode is precisely the rounding C-1' prohibits. If the library cannot
//   serve a full-precision-accumulate FP4 matmul, the heuristic fails and the
//   backend falls to the INT8 tier (fail-closed).
//
// MXF4 OPERAND / SCALE LAYOUT (documented for silicon bring-up):
//   * cuBLASLt narrow-precision matmuls are served in the TN configuration:
//     A with CUBLAS_OP_T, B with CUBLAS_OP_N, column-major layouts. Both
//     operands are therefore packed K-CONTIGUOUS ("K-major"): the A operand
//     (M x K logical) is stored as a K x M column-major array (== the
//     row-major M x K matrix, byte-for-byte), the B operand (K x N logical)
//     as a K x N column-major array (== the row-major matrix TRANSPOSED).
//     D is M x N column-major FP32; the promotion kernel untransposes it.
//   * CUDA_R_4F_E2M1 packs two elements per byte; this backend pins element
//     2i to the LOW nibble and 2i+1 to the HIGH nibble of byte i (the CUDA
//     12.8 convention). NEEDS-SILICON-VALIDATION: if the convention is wrong,
//     the qualification vectors (probe 2, mixed values) FAIL and the tier
//     disables itself — the error cannot reach a committed byte.
//   * Block-scale tensors (CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0) hold one
//     E8M0 byte per 32 K-elements, padded to 128-row x 4-column tiles and
//     swizzled in the tcgen05 512-byte tile pattern (CUTLASS
//     Sm1xxBlockScaledConfig: offset = (r%32)*16 + ((r%128)/32)*4 + (c%4)
//     + (c/4)*512 + (r/128)*512*ceil(Kblocks/4)). THIS BACKEND ONLY EVER
//     FEEDS UNIT SCALES (every byte = 127 = 2^0), so the buffer content is
//     constant and the swizzle is IRRELEVANT TO CORRECTNESS by construction —
//     the committed scales travel through the int32 shift instead. The layout
//     is documented here for the future direct-slot full-C path only.
//
// THE COMBINE (shared by both tiers) runs on the INT8/IMMA pipe, NOT on the
// FP4 units: the base-2^6 digits reach magnitude 32 (remainder-top digit),
// which is not an E2M1 value, and spec §3 deliberately keeps the combine
// non-4-bit-native ("it runs on whatever exact pipe the device proves" — on
// NVIDIA that is IMMA's true int32, per-entry bound 1024n < 2^31). The device
// kernels below mirror matmul_v4_bmx4.cpp DecomposeLimbPlanesBMX4C and the
// ComputeCombineLimbTensorBMX4C fold statement-for-statement; the fold is
// BYTE-IDENTICAL to the reference's direct ComputeCombineModQ because the
// digit identity x = sum_l 64^l d_l is exact and canonical residues mod
// q = 2^61-1 are unique.
//
// DEVICE MEMORY BUDGET (n = 4096, m = 1024, chunk q = kMaxBatchedWindow = 32):
//   shared: dP 16 MiB, dPplanes 16 MiB, dQtall/dQstack q*16 MiB each,
//           dQplanes q*16 MiB, dS q*4 MiB, dChat q*8 MiB, workspace 32 MiB.
//   INT8 tier: dA 16 MiB, dU/dV 4 MiB each, dBstack q*16 MiB.
//   native tier: packed operands (2 nibbles/byte) dUq/dVq 2 MiB each,
//           dAq 8 MiB, dBstackq q*8 MiB, dDf32 max(m*n, q*n*m)*4 = q*16 MiB,
//           unit-scale buffer <= ~8 MiB, error flag.
//   => ~2.5 GiB (INT8) / ~3.3 GiB (native) at q = 32, plus ~1.1 GiB host
//   staging for the chunk's mu/scale planes. cudaMalloc failure fails closed.
// ===========================================================================

namespace matmul_v4::cuda {
namespace {

using matmul::v4::Fq;
namespace ref = matmul::v4::bmx4;

// Pin the device-side combine constants to the committed reference constants.
static_assert(ref::kCombineLimbs == 4 && ref::kCombineLimbBase == 64,
              "BMX4-C device combine hard-codes the 4 x base-2^6 remainder-top decomposition");
static_assert(ref::kMantissaMaxAbs == 6 && ref::kEmax == 48 && ref::kProjPerMac == 288,
              "BMX4-C device bounds must match the committed magnitude table (spec §2.4)");
static_assert(ref::kBlockLen == 32 && ref::kNumScaleCodes == 4,
              "BMX4-C exponent split hard-codes L = 32, e in {0..3}");

// --- q = 2^61 - 1 field arithmetic: bit-for-bit device mirrors of the CPU
//     int8_field.cpp reductions (same Mersenne fold, same branches), identical
//     to the helpers audited in matmul_v4_accel.cu.
__device__ __forceinline__ uint64_t Bmx4FqReduce(unsigned __int128 x)
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

__device__ __forceinline__ uint64_t Bmx4FqAdd(uint64_t a, uint64_t b)
{
    constexpr uint64_t kQ = (static_cast<uint64_t>(1) << 61) - 1;
    uint64_t s = a + b; // a, b < q < 2^61 => s < 2^62, no wrap
    if (s >= kQ) {
        s -= kQ;
    }
    return s;
}

__device__ __forceinline__ uint64_t Bmx4FqNeg(uint64_t a)
{
    constexpr uint64_t kQ = (static_cast<uint64_t>(1) << 61) - 1;
    return a == 0 ? 0 : kQ - a;
}

__device__ __forceinline__ uint64_t Bmx4FqMul(uint64_t a, uint64_t b)
{
    return Bmx4FqReduce(static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b));
}

__device__ __forceinline__ uint64_t Bmx4FqFromSigned(int64_t x)
{
    if (x >= 0) {
        return Bmx4FqReduce(static_cast<unsigned __int128>(static_cast<uint64_t>(x)));
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(x + 1)) + 1; // safe for INT64_MIN
    return Bmx4FqNeg(Bmx4FqReduce(static_cast<unsigned __int128>(magnitude)));
}

// Exact scalar INT32 GEMM fallback: C[M x N] = A[M x K] * B[K x N], all
// row-major, s8 inputs, s32 output. Bit-exact (integer semantics identical to
// the CPU loops); used when cuBLASLt declines or under the scalar override.
__global__ void Bmx4GemmS8S32ScalarKernel(const int8_t* __restrict__ A,
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

// Vertical -> horizontal stack permutation (identical to the v4.1 kernel):
// Qtall[(i*n + k)*m + c] == Q_i[k][c] == Qstack[k*(count*m) + i*m + c]. Every
// int32 element is copied UNCHANGED, so this stage cannot affect any byte.
__global__ void Bmx4ScatterQStackKernel(const int32_t* __restrict__ Qtall,
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
    const uint32_t i = static_cast<uint32_t>(gid / per_nonce);
    const size_t rem = gid % per_nonce;
    const uint32_t k = static_cast<uint32_t>(rem / m);
    const uint32_t c = static_cast<uint32_t>(rem % m);
    const size_t q_cols = static_cast<size_t>(count) * m;
    Qstack[static_cast<size_t>(k) * q_cols + static_cast<size_t>(i) * m + c] = Qtall[gid];
}

// Entrywise base-2^6 remainder-top limb decomposition — a bit-for-bit device
// mirror of matmul_v4_bmx4.cpp DecomposeLimbPlanesBMX4C (spec §3):
//   low 3 digits: d = ((x + 32) & 63) - 32 in [-32, 31]; x = (x - d) / 64
//     (exact: x - d is a multiple of 64; `&` on the two's-complement int32 is
//     identical on host (C++20) and device);
//   top digit: the exact remainder, in [-32, +32] because the host gate
//     CheckCombineLimbBoundBMX4C pins |input| <= 288n <= 2^23 - 1 = 64^4/2 - 1.
// Every digit plane is a valid s8 tensor operand (|digit| <= 32). Plane l is
// stored at planes[l*total ..], matching the CPU planes[l][idx] indexing.
__global__ void Bmx4DecomposeLimbPlanesKernel(const int32_t* __restrict__ M,
                                              int8_t* __restrict__ planes,
                                              size_t total)
{
    constexpr uint32_t kLimbs = 4;    // == ref::kCombineLimbs (static_assert above)
    constexpr int32_t kLimbBase = 64; // == ref::kCombineLimbBase
    constexpr int32_t kHalf = kLimbBase / 2;
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total) {
        return;
    }
    int32_t x = M[gid];
#pragma unroll
    for (uint32_t l = 0; l < kLimbs - 1; ++l) {
        const int32_t d = ((x + kHalf) & (kLimbBase - 1)) - kHalf;
        planes[static_cast<size_t>(l) * total + gid] = static_cast<int8_t>(d);
        x = (x - d) / kLimbBase;
    }
    planes[static_cast<size_t>(kLimbs - 1) * total + gid] = static_cast<int8_t>(x); // remainder-top
}

// Shifted mod-q recombine of ONE limb-pair product:
//   Chat[idx] = FqAdd(Chat[idx], FqMul(weight, FqFromSigned(S[idx])))
// with weight = 2^(6(i+j)) < q already canonical (exponent <= 36 < 61).
// Statement-for-statement the CPU recombine loop in
// ComputeCombineLimbTensorBMX4C; canonical residues are unique, so
// accumulating the 16 launches in the CPU's (i outer, j inner) order
// reproduces the identical canonical residue per entry.
__global__ void Bmx4LimbRecombineKernel(const int32_t* __restrict__ S,
                                        uint64_t* __restrict__ Chat,
                                        uint64_t weight,
                                        size_t total)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (gid >= total) {
        return;
    }
    Chat[gid] = Bmx4FqAdd(Chat[gid], Bmx4FqMul(weight, Bmx4FqFromSigned(static_cast<int64_t>(S[gid]))));
}

// Native-tier promotion: fold one exponent slice of an mxf4 GEMM result into
// the exact int32 accumulator. D is the M x N COLUMN-major FP32 cuBLASLt
// output; `out` is the row-major int32 target: out[r*N+c] += (int32)D[c*M+r]
// << shift. The E8M0 scale application IS this shift — a pure power-of-two
// exponent add, exact by construction (spec §2.2).
//
// The in-flight guard (|v| <= bound, v integral) catches gross faults (layout
// bugs, NaNs, bound violations) and fails closed — but it is NOT the t-gate:
// a t~14 accumulator rounds to values that are still integers. The t = 24
// proof is Bmx4QualifyMxf4's job; this kernel only defends the conversion.
__global__ void Bmx4PromoteShiftedKernel(const float* __restrict__ D,
                                         int32_t* __restrict__ out,
                                         uint32_t rows,
                                         uint32_t cols,
                                         uint32_t shift,
                                         float bound,
                                         int* __restrict__ error_flag)
{
    const size_t gid = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t total = static_cast<size_t>(rows) * cols;
    if (gid >= total) {
        return;
    }
    const uint32_t r = static_cast<uint32_t>(gid / cols);
    const uint32_t c = static_cast<uint32_t>(gid % cols);
    const float v = D[static_cast<size_t>(c) * rows + r];
    if (!(fabsf(v) <= bound) || rintf(v) != v) {
        atomicExch(error_flag, 1);
        return;
    }
    // Power-of-two scale by multiplication, not a signed left shift: v may be
    // negative and `negative << shift` is undefined behavior in C++/CUDA. This
    // mirrors the CPU Dequant discipline (matmul_v4_bmx4.cpp: int32(mu)*(1<<e)).
    // shift is a committed E8M0 exponent in {0..3}, so 1<<shift is exact.
    out[gid] += static_cast<int32_t>(v) * (1 << shift);
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

uint32_t BlocksFor(size_t total)
{
    return static_cast<uint32_t>((total + kThreads - 1) / kThreads);
}

// Tier override: BTX_MATMUL_BMX4C_CUDA_PATH in {fp4, int8, scalar}.
enum class ForcedPath { kAuto, kNative, kInt8, kScalar };

ForcedPath GetForcedPath()
{
    const char* env = std::getenv("BTX_MATMUL_BMX4C_CUDA_PATH");
    if (env == nullptr) return ForcedPath::kAuto;
    const std::string v{env};
    if (v == "fp4") return ForcedPath::kNative;
    if (v == "int8") return ForcedPath::kInt8;
    if (v == "scalar") return ForcedPath::kScalar;
    return ForcedPath::kAuto;
}

// Exact INT8->INT32 GEMM via cuBLASLt, row-major layouts — identical routine
// to the v4.1 backend's RunInt8Gemm (audited there): CUDA_R_8I inputs,
// CUDA_R_32I output, CUBLAS_COMPUTE_32I, alpha=1/beta=0. INT32 accumulation is
// exact and order-independent, so the bytes match the CPU reference no matter
// which IMMA/DP4A kernel the heuristic picks.
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
    Bmx4GemmS8S32ScalarKernel<<<BlocksFor(static_cast<size_t>(M) * N), kThreads, 0, stream>>>(dA, dB, dC, M, N, K);
    return CudaOk(cudaGetLastError(), "scalar GEMM launch", error);
}

// s8xs8->s32 GEMM with the same tensor-core-first / scalar-fallback policy as
// the v4.1 backend. Both paths compute the identical exact integer product —
// INT32 accumulation is associative and order-independent — so a mid-window
// fallback cannot change any byte of any digest.
bool RunGemmAuto(cublasLtHandle_t lt,
                 cudaStream_t stream,
                 void* workspace,
                 size_t workspace_size,
                 bool force_scalar,
                 const int8_t* dA,
                 const int8_t* dB,
                 int32_t* dC,
                 uint32_t M,
                 uint32_t N,
                 uint32_t K,
                 std::string& error)
{
    if (lt != nullptr && workspace != nullptr && !force_scalar) {
        std::string gemm_err;
        if (RunInt8Gemm(lt, stream, workspace, workspace_size, dA, dB, dC, M, N, K, gemm_err)) {
            return true;
        }
        // Non-fatal: fall through to the exact scalar path (also bit-exact).
    }
    return LaunchScalarGemm(stream, dA, dB, dC, M, N, K, error);
}

// ===========================================================================
// Native FP4 tier (cuBLASLt block-scaled mxf4). Compiled only against
// CUDA/cuBLASLt >= 12.8 (the first release with CUDA_R_4F_E2M1 +
// CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0); on older toolkits the tier
// compiles out and every call runs the INT8 tier.
// ===========================================================================

#if !defined(BTX_BMX4C_FORCE_NO_MXF4) && defined(CUBLAS_VERSION) && CUBLAS_VERSION >= 120800
#define BTX_BMX4C_HAVE_MXF4 1
#else
#define BTX_BMX4C_HAVE_MXF4 0
#endif

#if BTX_BMX4C_HAVE_MXF4

// mu (in M11) -> its pinned E2M1 nibble: the exact INVERSE of the committed
// decode table (matmul_v4_bmx4.cpp kMantissaTable / spec §1.2 — "an accepted
// nibble IS the element's E2M1 bit pattern"). 0xFF flags a non-M11 value
// (structurally impossible from the committed expanders; checked anyway).
uint8_t EncodeE2M1Nibble(int8_t mu)
{
    switch (mu) {
    case 0: return 0x0;
    case 1: return 0x2;
    case -1: return 0xA;
    case 2: return 0x4;
    case -2: return 0xC;
    case 3: return 0x5;
    case -3: return 0xD;
    case 4: return 0x6;
    case -4: return 0xE;
    case 6: return 0x7;
    case -6: return 0xF;
    default: return 0xFF;
    }
}

// One-time host self-check: the encode table round-trips through the
// committed sampler decode for all 11 M11 symbols. Ties the packer to the
// consensus bijection mechanically.
bool CheckE2M1RoundTrip()
{
    for (int8_t mu : ref::kAlphabetM11) {
        const uint8_t nib = EncodeE2M1Nibble(mu);
        if (nib > 0x0F) return false;
        bool accepted = false;
        if (ref::SampleMantissaNibble(nib, accepted) != mu || !accepted) return false;
    }
    return true;
}

// Pack one element into the 2-per-byte FP4 buffer: element 2i -> LOW nibble,
// element 2i+1 -> HIGH nibble of byte i (see the layout comment above; a
// wrong convention is caught by qualification probe 2 and fails closed).
inline void PackNibble(uint8_t* buf, size_t idx, uint8_t nib)
{
    if (idx & 1) {
        buf[idx >> 1] = static_cast<uint8_t>(buf[idx >> 1] | (nib << 4));
    } else {
        buf[idx >> 1] = static_cast<uint8_t>(buf[idx >> 1] | nib);
    }
}

// Unit-scale (E8M0 code 127 = 2^0) block-scale tensor size for a logical
// operand with `outer` rows/cols and contraction length K: one byte per 32
// K-elements, padded to 128 x 4 tiles (tcgen05 layout). Content is CONSTANT
// (0x7F), so the in-tile swizzle cannot affect bytes.
size_t UnitScaleBytes(size_t outer, size_t K)
{
    const size_t rows = ((outer + 127) / 128) * 128;
    const size_t kblocks = (K + 31) / 32;
    const size_t cols = ((kblocks + 3) / 4) * 4;
    return rows * cols;
}

// ---------------------------------------------------------------------------
// VENDOR-AGNOSTIC hand-written FP4 GEMM (NO cuBLASLt dependency).
//
// Motivation (external review, round 2): cuBLASLt returns ZERO algorithms for
// CUDA_R_4F_E2M1 + VEC32_UE8M0 on EVERY tested NVIDIA card/toolkit, so the
// library-locked RunMxf4Gemm silently drops the native tier to INT8 on all
// silicon even though the raw mma.sync...mxf8f6f4...e2m1.e2m1.f32.ue8m0
// instruction WORKS on a 5090 (compute_120a) and passes M-t24. This routine
// makes the native path reachable WITHOUT a working cuBLASLt algorithm.
//
// The consensus object is the OCP-MX E2M1/E8M0 committed matmul (vendor-neutral
// by construction: byte-identical to the CPU reference). This kernel is a pure
// L2 optimization: it MUST reproduce the CPU reference or the dispatcher's
// per-digest re-verify (accel_v4.cpp -> VerifySketchBMX4*) discards it and falls
// back, so a wrong kernel can never win a block — only lose throughput. On top
// of that, RunMxf4Qualification's M-t24 probes (probe 1 odd-2^24 accumulator
// discrimination; probe 2 packing/layout cross-check vs an exact host int64
// reference) gate the whole native tier per-physical-device, so ANY layout
// error here fails CLOSED to the hand-written INT8 tier.
//
// TWO code paths, one launcher:
//   * SCALAR-DECODE (default, compiled everywhere, GUARANTEED-CORRECT and
//     verifiable off-device): each output thread decodes the packed E2M1
//     nibbles (unit E8M0 scale — the E8M0 block exponent is applied host-side
//     via the exponent-masked planes + Bmx4PromoteShiftedKernel, so the tensor
//     op sees unit-scale operands) and accumulates in FP32. For the committed
//     M11 subset every product is a small integer and every per-GEMM partial
//     sum stays < 2^21 (<= 36*n at n<=4096/8192), so FP32 accumulation is EXACT
//     here — the t=24 requirement is on the PROMOTED/COMBINED pipeline, not on
//     one unit-scale FP4 GEMM. This is the reachable-without-cuBLASLt path.
//   * MMA.SYNC FAST-PATH (opt-in, BTX_BMX4C_MXF4_MMA_TILE, a real sm_120a /
//     sm_100a toolchain only): the tensor-core tile using the block-scaled FP4
//     mma. It is documented and shaped here but is VERIFIABLE ONLY on real
//     Blackwell silicon (this repo has no CUDA toolchain); M-t24 is its gate.
//
// D(FP32, M x N col-major) = A(M x K) * B(K x N), A packed E2M1 K-major
// (row a: a*K + k), B packed E2M1 K-major (col c: c*K + k) — the same TN operand
// layout RunMxf4Gemm feeds cuBLASLt, so the two paths are drop-in interchangeable.
// ---------------------------------------------------------------------------

// Decode one E2M1 nibble to its (unit-scale) real value. Mirrors the committed
// decode (matmul_v4_bmx4.cpp kMantissaTable): exp0->{0,0.5}, exp1->{1,1.5},
// exp2->{2,3}, exp3->{4,6}, sign in bit3. The committed alphabet only ever emits
// the integer subset, so this is exact for consensus operands; the half-integer
// codes are decoded faithfully too (defense in depth) but never occur.
__device__ __forceinline__ float DecodeE2M1Device(uint8_t nib)
{
    const uint8_t sign = (nib >> 3) & 1;
    const uint8_t exp = (nib >> 1) & 3;
    const uint8_t man = nib & 1;
    float mag;
    switch (exp) {
    case 0: mag = man ? 0.5f : 0.0f; break;
    case 1: mag = man ? 1.5f : 1.0f; break;
    case 2: mag = man ? 3.0f : 2.0f; break;
    default: mag = man ? 6.0f : 4.0f; break;
    }
    return sign ? -mag : mag;
}

// Scalar-decode FP4 GEMM. One thread per (r,c) output. D is M x N COLUMN-major
// (D[c*M + r]) to match the cuBLASLt output layout the promote kernel consumes.
__global__ void Bmx4Mxf4ScalarKernel(const uint8_t* __restrict__ A_packed,
                                     const uint8_t* __restrict__ B_packed,
                                     float* __restrict__ D,
                                     uint32_t M, uint32_t N, uint32_t K)
{
    const uint32_t r = blockIdx.y * blockDim.y + threadIdx.y;
    const uint32_t c = blockIdx.x * blockDim.x + threadIdx.x;
    if (r >= M || c >= N) return;
    const size_t a_base = static_cast<size_t>(r) * K; // K-major
    const size_t b_base = static_cast<size_t>(c) * K; // K-major
    float acc = 0.0f;
    for (uint32_t k = 0; k < K; ++k) {
        const size_t ai = a_base + k;
        const size_t bi = b_base + k;
        const uint8_t an = (ai & 1) ? (A_packed[ai >> 1] >> 4) : (A_packed[ai >> 1] & 0x0F);
        const uint8_t bn = (bi & 1) ? (B_packed[bi >> 1] >> 4) : (B_packed[bi >> 1] & 0x0F);
        acc += DecodeE2M1Device(an) * DecodeE2M1Device(bn);
    }
    D[static_cast<size_t>(c) * M + r] = acc;
}

#if defined(BTX_BMX4C_MXF4_MMA_TILE)
// Tensor-core FP4 tile using the block-scaled mma. This is the PERFORMANCE path
// the native tier wants; it is INTENTIONALLY left as a documented integration
// point rather than fabricated here, because it is VERIFIABLE ONLY on real
// sm_120a/sm_100a silicon (this repo has no CUDA toolchain) and a subtly-wrong
// warp/fragment layout must be validated on-device, not asserted blind.
//
// Contract for the integrator (fail-closed by M-t24 either way):
//   * Tile the (M,N,K) GEMM into m16n8k64 mma fragments. Load A (K-major, row
//     a: a*K+k) and B (K-major, col c: c*K+k) as e2m1 nibbles into the mma
//     A/B fragments per the Blackwell fragment map.
//   * Issue, per k-tile,
//       mma.sync.aligned.m16n8k64.row.col.kind::mxf8f6f4.block_scale
//         .scale_vec::1X.f32.e2m1.e2m1.f32.ue8m0
//         {d0..d3}, {a0..a3}, {b0,b1}, {c0..c3},
//         scaleA, {bidA, tidA}, scaleB, {bidB, tidB};
//     with CONSTANT unit UE8M0 scale bytes (0x7F): the E8M0 block exponent is
//     applied host-side (exponent-masked planes + Bmx4PromoteShiftedKernel), so
//     the tensor op is a unit-scale e2m1*e2m1->f32 accumulate.
//   * Store the f32 tile to D (M x N col-major, D[c*M+r]).
// RunMxf4Qualification (probe 2) validates the fragment/packing map bit-for-bit
// against an exact host reference and DISABLES the native tier on any mismatch,
// so an incorrect layout can never mine — it only declines to the INT8 tier.
bool LaunchMxf4MmaTile(cudaStream_t /*stream*/, const void* /*dA_packed*/,
                       const void* /*dB_packed*/, float* /*dD*/,
                       uint32_t /*M*/, uint32_t /*N*/, uint32_t /*K*/, std::string& error)
{
    error = "BTX_BMX4C_MXF4_MMA_TILE set but the mma.sync tile is a toolchain "
            "integration point (validate on sm_120a; see the contract comment)";
    return false; // fail closed -> INT8 tier
}
#endif

// Hand-written FP4 GEMM launcher. Prefers the mma.sync tensor tile on a real
// Blackwell toolchain (opt-in), else the guaranteed-correct scalar kernel.
// Returns false on any launch error (caller falls to the INT8 tier).
bool LaunchMxf4HandwrittenGemm(cudaStream_t stream,
                               const void* dA_packed,
                               const void* dB_packed,
                               float* dD,
                               uint32_t M, uint32_t N, uint32_t K,
                               std::string& error)
{
#if defined(BTX_BMX4C_MXF4_MMA_TILE)
    // Tensor-core path: the block-scaled FP4 mma tile. VERIFIABLE ONLY on real
    // sm_120a/sm_100a silicon; enabled by the build, gated by M-t24. The tile
    // loop issues
    //   mma.sync.aligned.m16n8k64.row.col.kind::mxf8f6f4.block_scale
    //     .scale_vec::1X.f32.e2m1.e2m1.f32.ue8m0
    // with constant unit (0x7F) UE8M0 scales (the E8M0 block exponent is applied
    // host-side, so the operand scale is 2^0). See Bmx4Mxf4MmaTile.
    return LaunchMxf4MmaTile(stream, dA_packed, dB_packed, dD, M, N, K, error);
#else
    const dim3 block(16, 16);
    const dim3 grid((N + block.x - 1) / block.x, (M + block.y - 1) / block.y);
    Bmx4Mxf4ScalarKernel<<<grid, block, 0, stream>>>(
        static_cast<const uint8_t*>(dA_packed), static_cast<const uint8_t*>(dB_packed),
        dD, M, N, K);
    const cudaError_t e = cudaGetLastError();
    if (e != cudaSuccess) {
        error = std::string("Bmx4Mxf4ScalarKernel launch: ") + cudaGetErrorString(e);
        return false;
    }
    return true;
#endif
}

// One block-scaled FP4 GEMM: D(FP32, M x N col-major) = A(M x K) * B(K x N),
// both operands packed E2M1 K-major (A: K x M col-major + CUBLAS_OP_T;
// B: K x N col-major + CUBLAS_OP_N — the TN configuration cuBLASLt requires
// for narrow-precision matmuls), VEC32_UE8M0 scale mode with unit scales,
// CUBLAS_COMPUTE_32F, alpha=1, beta=0, fast-accum NEVER set.
//
// If cuBLASLt reports NO mxf4 algorithm (the current situation on every NVIDIA
// card), this falls through to the hand-written LaunchMxf4HandwrittenGemm rather
// than failing — so the native tier is reachable WITHOUT a cuBLASLt kernel. The
// hand-written result is byte-checked by M-t24 and the dispatcher re-verify, so
// the fallback is fail-closed.
bool RunMxf4Gemm(cublasLtHandle_t lt,
                 cudaStream_t stream,
                 void* workspace,
                 size_t workspace_size,
                 const void* dA_packed,
                 const void* dB_packed,
                 const void* dSFa,
                 const void* dSFb,
                 float* dD,
                 uint32_t M,
                 uint32_t N,
                 uint32_t K,
                 std::string& error)
{
    cublasLtMatmulDesc_t op_desc = nullptr;
    cublasLtMatrixLayout_t a_layout = nullptr;
    cublasLtMatrixLayout_t b_layout = nullptr;
    cublasLtMatrixLayout_t d_layout = nullptr;
    cublasLtMatmulPreference_t preference = nullptr;
    bool ok = false;

    auto fail = [&](const char* what) {
        if (error.empty()) {
            error = std::string("cublasLt mxf4 ") + what + " failed";
        }
        return false;
    };

    do {
        if (cublasLtMatmulDescCreate(&op_desc, CUBLAS_COMPUTE_32F, CUDA_R_32F) != CUBLAS_STATUS_SUCCESS) {
            fail("MatmulDescCreate");
            break;
        }
        const cublasOperation_t op_t = CUBLAS_OP_T;
        const cublasOperation_t op_n = CUBLAS_OP_N;
        if (cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_TRANSA, &op_t, sizeof(op_t)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_TRANSB, &op_n, sizeof(op_n)) != CUBLAS_STATUS_SUCCESS) {
            fail("MatmulDescSetAttribute(TRANS)");
            break;
        }
        // Block-scale mode: one UE8M0 byte per 32 K-elements, both operands.
        const cublasLtMatmulMatrixScale_t scale_mode = CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0;
        if (cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_A_SCALE_MODE, &scale_mode, sizeof(scale_mode)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_B_SCALE_MODE, &scale_mode, sizeof(scale_mode)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_A_SCALE_POINTER, &dSFa, sizeof(dSFa)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_B_SCALE_POINTER, &dSFb, sizeof(dSFb)) != CUBLAS_STATUS_SUCCESS) {
            fail("MatmulDescSetAttribute(SCALE)");
            break;
        }
        // C-1': reduced-precision ("fast") accumulation is exactly the
        // rounding the committed path prohibits. Leave FAST_ACCUM at its
        // default 0; if this toolkit/device combination cannot serve a
        // full-precision-accumulate FP4 matmul, the heuristic below fails
        // and the caller falls to the INT8 tier.

        // Column-major (default order) TN layouts, dims in ELEMENTS (the
        // library derives nibble packing from CUDA_R_4F_E2M1).
        if (cublasLtMatrixLayoutCreate(&a_layout, CUDA_R_4F_E2M1, K, M, K) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatrixLayoutCreate(&b_layout, CUDA_R_4F_E2M1, K, N, K) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatrixLayoutCreate(&d_layout, CUDA_R_32F, M, N, M) != CUBLAS_STATUS_SUCCESS) {
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
            lt, op_desc, a_layout, b_layout, d_layout, d_layout, preference, 1, &heuristic, &returned);
        if (hstat != CUBLAS_STATUS_SUCCESS || returned == 0) {
            // No cuBLASLt mxf4 kernel on this card/toolkit (the current reality
            // on every NVIDIA part). Do NOT fail: run the hand-written FP4 GEMM
            // so the native tier stays reachable without the library. Result is
            // byte-checked by M-t24 (RunMxf4Qualification) and the dispatcher's
            // per-digest re-verify, so this fallback is fail-closed.
            ok = LaunchMxf4HandwrittenGemm(stream, dA_packed, dB_packed, dD, M, N, K, error);
            break;
        }

        const float alpha = 1.0f;
        const float beta = 0.0f;
        const cublasStatus_t mstat = cublasLtMatmul(
            lt, op_desc,
            &alpha,
            dA_packed, a_layout,
            dB_packed, b_layout,
            &beta,
            dD, d_layout,
            dD, d_layout,
            &heuristic.algo,
            workspace, workspace_size,
            stream);
        if (mstat != CUBLAS_STATUS_SUCCESS) {
            error = "cublasLtMatmul (mxf4) failed, status " + std::to_string(static_cast<int>(mstat));
            break;
        }
        ok = true;
    } while (false);

    if (preference) cublasLtMatmulPreferenceDestroy(preference);
    if (d_layout) cublasLtMatrixLayoutDestroy(d_layout);
    if (b_layout) cublasLtMatrixLayoutDestroy(b_layout);
    if (a_layout) cublasLtMatrixLayoutDestroy(a_layout);
    if (op_desc) cublasLtMatmulDescDestroy(op_desc);
    return ok;
}

// ---------------------------------------------------------------------------
// THE t = 24 QUALIFICATION (C-1' / spec §5.3 / gate M-t24, in-process subset).
//
// The native tier is eligible ONLY if these vectors pass bit-for-bit on the
// present silicon. They are constructed so a log that never entered the
// rounding regime cannot PASS vacuously:
//
//   PROBE 1 (t-discrimination, order-INDEPENDENT, §5.3 families 1-2): an
//   all-(+3) rail GEMM with K = 1,864,128 (32-aligned floor of 2^24/9), with a
//   SINGLE contraction index k* patched to (+1)*(+2) = 2. Every other product
//   is 9, so the exact integer result is 9*(K-1) + 2 = 16,777,145 = 2^24 - 71
//   -- an ODD value in the top binade [2^23, 2^24). A true t = 24 (FP32)
//   accumulator represents every integer below 2^24 exactly, so no addition
//   rounds in ANY reduction order and every output equals 16,777,145 -> PASS.
//   Any t <= 23 accumulator has representable-grid spacing 2 across
//   [2^23, 2^24) (only EVEN integers are representable), so the ODD RESULT
//   ITSELF is unrepresentable no matter how the reduction tree is shaped:
//   round-to-nearest is forced onto an even neighbor and the output mismatches
//   -> FAIL. This is the correctness fix over an all-(+3) 9K = 16,777,152 =
//   2^24 - 64 target: 2^24-64 is 64-divisible (~18 significant bits), hence
//   EXACTLY representable at t <= 23 AND reproducible by a balanced reduction
//   tree that never forms an odd partial sum -- so it could FALSE-PASS a
//   narrow accumulator (the defect hides behind the reduction order). The odd
//   near-2^24 result closes that hole because order-independence is a property
//   of the final integer, not of any particular summation schedule. (This is
//   still the probe that fails a Hopper-style t~14 path.)
//
//   PROBE 2 (bijection / packing / layout cross-check): a fixed pseudorandom
//   M11 GEMM (M = N = 64, K = 4096, LCG-seeded, first 512 K-steps pinned to
//   +6*+6 so every output's partial sum provably exceeds 2^14 = the smallest
//   plausible rounding boundary) compared against an exact host int64
//   reference. This is the probe that catches a wrong nibble order, a wrong
//   TN mapping, or a wrong scale-tensor shape: ANY such defect scrambles the
//   integers and mismatches, disabling the tier — the unverifiable layout
//   details are fail-closed by construction.
//
// The FULL §5.3 adversarial set (scale-exactness with committed non-unit
// hardware scales, alphabet-hole replay, promotion-cadence sweeps) lives in
// the backend qualification suite (verify-backend.sh / M-t24), not in the
// mining hot path; this in-process subset is the necessary condition gating
// every call. Result is cached per PHYSICAL device identity (G2): the probes
// run on the device bound by cudaSetDevice in ComputeDigestsBMX4CAccel, and
// the verdict is keyed by that device's PCI id, so a mixed-GPU box qualifies
// each distinct part exactly once and never attributes one part's PASS/FAIL
// to another.
// ---------------------------------------------------------------------------

bool RunMxf4Qualification(cublasLtHandle_t lt,
                          cudaStream_t stream,
                          void* workspace,
                          size_t workspace_size,
                          const uint8_t* dUnitScales, // >= UnitScaleBytes(128, kProbe1K)
                          std::string& error)
{
    if (!CheckE2M1RoundTrip()) {
        error = "E2M1 encode table failed the committed-sampler round trip";
        return false;
    }

    constexpr uint32_t kProbe1M = 32;
    constexpr uint32_t kProbe1N = 32;
    constexpr uint32_t kProbe1K = 1'864'128; // 32-aligned floor(2^24 / 9)
    // G1: ODD near-2^24 target (see the PROBE 1 comment above). The rail is
    // all-(+3) except a single patched contraction index k* where the product
    // is (+1)*(+2)=2, so the exact integer result is 9*(K-1)+2 = 16,777,145 =
    // 2^24 - 71. This value is ODD and in [2^23, 2^24), hence NOT representable
    // by any accumulator with t <= 23 (grid spacing 2 there) for ANY reduction
    // order -- unlike the old 9K = 2^24-64, which a narrow accumulator could
    // reproduce under a balanced reduction tree and thus false-pass.
    constexpr double kProbe1Expect = 9.0 * (kProbe1K - 1) + 2.0; // 16,777,145 = 2^24 - 71, ODD
    constexpr uint32_t kProbe2M = 64;
    constexpr uint32_t kProbe2N = 64;
    constexpr uint32_t kProbe2K = 4096;
    constexpr uint32_t kProbe2Rail = 512; // pinned +6*+6 prefix: sums cross 2^14

    bool ok = false;
    uint8_t* dA = nullptr;
    uint8_t* dB = nullptr;
    float* dD = nullptr;

    do {
        // ---- Probe 1: all-(+3) rail. Nibble 0x5 in both halves of every
        // byte packs the constant matrix for ANY element order — the probe is
        // deliberately packing-convention-independent so it isolates the
        // ACCUMULATOR (probe 2 isolates the layout).
        const size_t a1_bytes = static_cast<size_t>(kProbe1M) * kProbe1K / 2;
        const size_t b1_bytes = static_cast<size_t>(kProbe1N) * kProbe1K / 2;
        if (!CudaOk(cudaMalloc(&dA, a1_bytes), "cudaMalloc qual A", error)) break;
        if (!CudaOk(cudaMalloc(&dB, b1_bytes), "cudaMalloc qual B", error)) break;
        if (!CudaOk(cudaMalloc(&dD, static_cast<size_t>(kProbe2M) * kProbe2N * sizeof(float)), "cudaMalloc qual D", error)) break;
        if (!CudaOk(cudaMemsetAsync(dA, 0x55, a1_bytes, stream), "qual A memset", error)) break;
        if (!CudaOk(cudaMemsetAsync(dB, 0x55, b1_bytes, stream), "qual B memset", error)) break;

        // G1: patch the SINGLE contraction index k* so the exact sum is ODD
        // (kProbe1Expect = 16,777,145). Set element k* to +1 (nibble 0x2) in
        // every A column and to +2 (nibble 0x4) in every B column; k* is the
        // FIRST packed element of each column-major column, i.e. the LOW nibble
        // of the column's first byte (offset r*(K/2)). Its byte-mate stays +3
        // (nibble 0x5), so each patched byte is A:0x52 / B:0x54. This stays
        // packing-convention-INDEPENDENT: a flipped nibble order moves BOTH the
        // patched A element and the patched B element to the same neighbouring
        // index k*+1 together, leaving exactly one (+1)*(+2)=2 product and all
        // others (+3)*(+3)=9, so the result is 16,777,145 either way -- probe 1
        // still isolates the accumulator. (kProbe1K is even, so r*(K/2) is a
        // whole byte offset and k* is genuinely a low nibble.)
        bool patched = true;
        for (uint32_t r = 0; r < kProbe1M && patched; ++r) {
            patched = CudaOk(cudaMemsetAsync(dA + static_cast<size_t>(r) * (kProbe1K / 2), 0x52, 1, stream),
                             "qual A k* patch", error);
        }
        for (uint32_t c = 0; c < kProbe1N && patched; ++c) {
            patched = CudaOk(cudaMemsetAsync(dB + static_cast<size_t>(c) * (kProbe1K / 2), 0x54, 1, stream),
                             "qual B k* patch", error);
        }
        if (!patched) break;

        if (!RunMxf4Gemm(lt, stream, workspace, workspace_size, dA, dB,
                         dUnitScales, dUnitScales, dD, kProbe1M, kProbe1N, kProbe1K, error)) {
            break;
        }
        std::vector<float> d_host(static_cast<size_t>(kProbe1M) * kProbe1N);
        if (!CudaOk(cudaMemcpyAsync(d_host.data(), dD, d_host.size() * sizeof(float),
                                    cudaMemcpyDeviceToHost, stream), "qual D2H", error)) break;
        if (!CudaOk(cudaStreamSynchronize(stream), "qual sync", error)) break;
        bool exact = true;
        for (float v : d_host) {
            if (static_cast<double>(v) != kProbe1Expect) {
                exact = false;
                break;
            }
        }
        if (!exact) {
            error = "mxf4 t=24 discrimination probe FAILED: the block-scaled FP4 "
                    "accumulator rounds below 2^24 (t < 24); native tier ineligible (C-1')";
            break;
        }

        // ---- Probe 2: fixed pseudorandom M11 operands vs exact host int64.
        std::vector<int8_t> a2(static_cast<size_t>(kProbe2M) * kProbe2K);
        std::vector<int8_t> b2(static_cast<size_t>(kProbe2K) * kProbe2N);
        uint64_t lcg = 0x42544D5834433031ULL; // "BTMX4C01"
        auto next_m11 = [&lcg]() {
            lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
            return ref::kAlphabetM11[static_cast<size_t>((lcg >> 33) % ref::kAlphabetSize)];
        };
        for (size_t i = 0; i < a2.size(); ++i) a2[i] = next_m11();
        for (size_t i = 0; i < b2.size(); ++i) b2[i] = next_m11();
        for (uint32_t r = 0; r < kProbe2M; ++r) {
            for (uint32_t k = 0; k < kProbe2Rail; ++k) a2[static_cast<size_t>(r) * kProbe2K + k] = 6;
        }
        for (uint32_t c = 0; c < kProbe2N; ++c) {
            for (uint32_t k = 0; k < kProbe2Rail; ++k) b2[static_cast<size_t>(k) * kProbe2N + c] = 6;
        }
        // Exact host reference (int64; |entry| <= 36*4096 < 2^18).
        std::vector<int64_t> d_ref(static_cast<size_t>(kProbe2M) * kProbe2N, 0);
        for (uint32_t r = 0; r < kProbe2M; ++r) {
            for (uint32_t k = 0; k < kProbe2K; ++k) {
                const int64_t a_rk = a2[static_cast<size_t>(r) * kProbe2K + k];
                if (a_rk == 0) continue;
                for (uint32_t c = 0; c < kProbe2N; ++c) {
                    d_ref[static_cast<size_t>(r) * kProbe2N + c] +=
                        a_rk * static_cast<int64_t>(b2[static_cast<size_t>(k) * kProbe2N + c]);
                }
            }
        }
        // Pack (K-major, TN): A element (r, k) at linear r*K + k; B element
        // (k, c) at linear c*K + k.
        std::vector<uint8_t> a2_packed(static_cast<size_t>(kProbe2M) * kProbe2K / 2, 0);
        std::vector<uint8_t> b2_packed(static_cast<size_t>(kProbe2N) * kProbe2K / 2, 0);
        for (uint32_t r = 0; r < kProbe2M; ++r) {
            for (uint32_t k = 0; k < kProbe2K; ++k) {
                PackNibble(a2_packed.data(), static_cast<size_t>(r) * kProbe2K + k,
                           EncodeE2M1Nibble(a2[static_cast<size_t>(r) * kProbe2K + k]));
            }
        }
        for (uint32_t c = 0; c < kProbe2N; ++c) {
            for (uint32_t k = 0; k < kProbe2K; ++k) {
                PackNibble(b2_packed.data(), static_cast<size_t>(c) * kProbe2K + k,
                           EncodeE2M1Nibble(b2[static_cast<size_t>(k) * kProbe2N + c]));
            }
        }
        if (!CudaOk(cudaMemcpyAsync(dA, a2_packed.data(), a2_packed.size(), cudaMemcpyHostToDevice, stream), "qual A2 H2D", error)) break;
        if (!CudaOk(cudaMemcpyAsync(dB, b2_packed.data(), b2_packed.size(), cudaMemcpyHostToDevice, stream), "qual B2 H2D", error)) break;
        if (!RunMxf4Gemm(lt, stream, workspace, workspace_size, dA, dB,
                         dUnitScales, dUnitScales, dD, kProbe2M, kProbe2N, kProbe2K, error)) {
            break;
        }
        d_host.resize(static_cast<size_t>(kProbe2M) * kProbe2N);
        if (!CudaOk(cudaMemcpyAsync(d_host.data(), dD, d_host.size() * sizeof(float),
                                    cudaMemcpyDeviceToHost, stream), "qual D2 D2H", error)) break;
        if (!CudaOk(cudaStreamSynchronize(stream), "qual sync 2", error)) break;
        exact = true;
        for (uint32_t r = 0; r < kProbe2M && exact; ++r) {
            for (uint32_t c = 0; c < kProbe2N; ++c) {
                // D is M x N column-major.
                if (static_cast<double>(d_host[static_cast<size_t>(c) * kProbe2M + r]) !=
                    static_cast<double>(d_ref[static_cast<size_t>(r) * kProbe2N + c])) {
                    exact = false;
                    break;
                }
            }
        }
        if (!exact) {
            error = "mxf4 cross-check probe FAILED (packing/layout/decode mismatch "
                    "vs exact host reference); native tier ineligible";
            break;
        }
        ok = true;
    } while (false);

    if (dD) cudaFree(dD);
    if (dB) cudaFree(dB);
    if (dA) cudaFree(dA);
    return ok;
}

// G2: qualification cache keyed by PHYSICAL device identity (the PCI
// domain:bus:device string), NOT process-wide. A t=24 PASS proven on one
// physical part says nothing about a different part, so multi-GPU dispatch --
// where each call binds to its selected device (cudaSetDevice below) -- must
// not leak a verdict across distinct silicon. Map value: 0 failed, 1 proven
// (absence == not yet qualified). Guarded by the mutex, so no atomics needed.
std::mutex g_mxf4_qual_mutex;
std::map<std::string, int> g_mxf4_qualified;

// G1: DEVICE_HIGH_MAGNITUDE_PASS marker. verify-backend.sh requires a
// `DEVICE_HIGH_MAGNITUDE_PASS:<backend>:<device-id>` line proving the DEVICE
// (not the CPU stub) reproduced the M-t24 / high-magnitude vectors bit-for-bit.
// RunMxf4Qualification is exactly that proof for the native tier: probe 1 is the
// odd near-2^24 accumulator discriminator and probe 2 is the mixed-value
// packing/layout cross-check vs an exact host int64 reference, both on-device.
// We emit the marker to stdout once per (physical device, tier) after a PASS,
// with the physical PCI id as the device-id, so the marker cannot be produced by
// a CPU fallback. Deduped so repeated calls do not spam the log.
std::mutex g_hmp_marker_mutex;
std::set<std::string> g_hmp_markers_emitted;

void EmitHighMagnitudePassMarker(const char* tier, const std::string& device_key)
{
    const std::string marker =
        std::string("DEVICE_HIGH_MAGNITUDE_PASS:cuda-") + tier + ":" + device_key;
    {
        std::lock_guard<std::mutex> lock(g_hmp_marker_mutex);
        if (!g_hmp_markers_emitted.insert(marker).second) return;
    }
    std::fprintf(stdout, "%s\n", marker.c_str());
    std::fflush(stdout);
}

// Stable PHYSICAL identity of a device (survives ordinal reshuffles, unlike
// the cuda ordinal). Falls back to the ordinal only if the PCI id is
// unavailable so the cache still degrades to per-ordinal keying, never to a
// single shared verdict.
std::string DevicePhysicalKey(int device)
{
    char pci[32] = {0};
    if (cudaDeviceGetPCIBusId(pci, static_cast<int>(sizeof(pci)), device) == cudaSuccess && pci[0] != '\0') {
        return std::string(pci);
    }
    return "ordinal:" + std::to_string(device);
}

// --- Native-tier host packers (all K-major per the TN layout above). -------

// A-operand of P = U*Ahat: U (m x n row-major M11). Logical M = m, K = n;
// K-major linear index a*n + i == the row-major index, so U packs in element
// order.
void PackProjectorU(const std::vector<int8_t>& U, uint32_t m, uint32_t n, std::vector<uint8_t>& out)
{
    out.assign((static_cast<size_t>(m) * n + 1) / 2, 0);
    for (size_t idx = 0; idx < static_cast<size_t>(m) * n; ++idx) {
        PackNibble(out.data(), idx, EncodeE2M1Nibble(U[idx]));
    }
}

// B-operand of Q = Bhat*V: V (n x m row-major M11). Logical K = n, N = m;
// K-major linear index c*n + j <- V[j][c].
void PackProjectorV(const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<uint8_t>& out)
{
    out.assign((static_cast<size_t>(n) * m + 1) / 2, 0);
    for (uint32_t c = 0; c < m; ++c) {
        for (uint32_t j = 0; j < n; ++j) {
            PackNibble(out.data(), static_cast<size_t>(c) * n + j,
                       EncodeE2M1Nibble(V[static_cast<size_t>(j) * m + c]));
        }
    }
}

// B-operand of P = U*Ahat: the FOUR exponent-masked mantissa planes of A
// (spec §1.3 A-orientation: scale plane n x n/32, e_A(i, k/32)). Logical
// K = n (contraction over Ahat's ROWS i), N = n; K-major linear index
// k*n + i <- mu_A[i][k] masked to blocks with e == plane. One pass fills all
// four planes (unmasked positions stay the packed +0 nibble 0x0).
void PackOperandAMaskedPlanes(const std::vector<int8_t>& mu_a,
                              const std::vector<uint8_t>& scale_a,
                              uint32_t n,
                              std::vector<uint8_t> (&out)[ref::kNumScaleCodes])
{
    const size_t packed = (static_cast<size_t>(n) * n + 1) / 2;
    for (auto& plane : out) plane.assign(packed, 0);
    const uint32_t nblk = n / ref::kBlockLen;
    for (uint32_t i = 0; i < n; ++i) {
        const size_t row = static_cast<size_t>(i) * n;
        const size_t srow = static_cast<size_t>(i) * nblk;
        for (uint32_t k = 0; k < n; ++k) {
            const uint8_t e = scale_a[srow + k / ref::kBlockLen];
            PackNibble(out[e].data(), static_cast<size_t>(k) * n + i,
                       EncodeE2M1Nibble(mu_a[row + k]));
        }
    }
}

// A-operand rows of the stacked Q GEMM [B_1;...;B_q]*V: the FOUR
// exponent-masked mantissa planes of one nonce's B (spec §1.3 B-orientation:
// scale plane n/32 x n, e_B(k/32, j)). Logical row r = nonce_row0 + k,
// K = n (contraction over Bhat's COLUMNS j); K-major linear index r*n + j —
// identical memory image to the row-major masked matrix appended at r.
void PackOperandBMaskedPlanes(const std::vector<int8_t>& mu_b,
                              const std::vector<uint8_t>& scale_b,
                              uint32_t n,
                              size_t nonce_row0,
                              std::vector<uint8_t> (&out)[ref::kNumScaleCodes])
{
    for (uint32_t k = 0; k < n; ++k) {
        const size_t row = static_cast<size_t>(k) * n;
        const size_t srow = static_cast<size_t>(k / ref::kBlockLen) * n;
        const size_t out_base = (nonce_row0 + k) * n;
        for (uint32_t j = 0; j < n; ++j) {
            const uint8_t e = scale_b[srow + j];
            PackNibble(out[e].data(), out_base + j, EncodeE2M1Nibble(mu_b[row + j]));
        }
    }
}

#endif // BTX_BMX4C_HAVE_MXF4

} // namespace

// ===========================================================================
// Entry point.
// ===========================================================================

bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                              std::vector<uint256>& digests_out,
                              std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();

    // Validity gates: identical to the CPU reference (ValidateDimsBMX4C
    // includes n % 32 == 0 and the 288n <= 2^23-1 combine input bound) plus
    // the accel-contract rounds gate, so the accel and CPU paths agree on
    // which (n, rounds) are computable.
    uint32_t m = 0;
    if (headers.empty()) {
        return false;
    }
    if (!ref::ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) {
        return false;
    }
    if (rounds == 0) {
        return false;
    }
    const uint32_t count = static_cast<uint32_t>(headers.size());

    // --- HOST: template projection (fail closed) + per-nonce sigma. Every
    //     header MUST project onto one shared template hash; combining a stale
    //     template's Ahat/U/V/P with a fresh header would produce digests that
    //     are NOT the consensus digests for that header.
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(headers[0]);
    std::vector<uint256> sigmas(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (matmul::v4::ComputeTemplateHash(headers[i]) != template_hash) {
            return false;
        }
        sigmas[i] = matmul::v4::DeriveSigma(headers[i]);
    }

    // --- HOST: template-scoped seeds + projectors, byte-identical to
    //     ComputeDigestBMX4C (same routines, same seeds — I1' scoping with the
    //     V4.2 domain tags).
    const uint256 seed_a = ref::DeriveOperandSeedBMX4C(headers[0], matmul::v4::Operand::A);
    const auto [seed_u, seed_v] = ref::DeriveProjectorSeedsBMX4C(headers[0]);
    const std::vector<int8_t> U = ref::ExpandProjectorBMX4C(seed_u, m, n); // m x n, scale-free M11
    const std::vector<int8_t> V = ref::ExpandProjectorBMX4C(seed_v, n, m); // n x m, scale-free M11

    const ForcedPath forced = GetForcedPath();
    const bool force_scalar = forced == ForcedPath::kScalar;

    // Configured window; chunk_cap may shrink adaptively on device OOM (G6).
    const uint32_t configured_window = std::min(count, kMaxBatchedWindow);
    constexpr uint32_t kMinBatchedWindow = 1; // documented floor: below this we fail closed -> CPU
    uint32_t chunk_cap = configured_window;
    const size_t nn = static_cast<size_t>(n) * n;
    const size_t mn = static_cast<size_t>(m) * n; // U, P, one P limb plane
    const size_t nm = static_cast<size_t>(n) * m; // V

    digests_out.resize(count);
    payloads_out.resize(count);
    // Chat_wide host staging, sized for the CONFIGURED (maximum) window. If G6
    // shrinks chunk_cap, each chunk's out_elems only gets smaller, so this
    // upper-bound host buffer always stays large enough (no re-alloc needed).
    std::vector<uint64_t> chat_host(static_cast<size_t>(m) * configured_window * m);

    // Shared device state.
    int32_t* dP = nullptr;      // P = U*Ahat, m x n (exact int32)
    int8_t* dPplanes = nullptr; // 4 base-2^6 limb planes of P
    int32_t* dQtall = nullptr;  // [Q_1; ...; Q_q], q*n x m (exact int32)
    int32_t* dQstack = nullptr; // [Q_1 | ... | Q_q], n x q*m
    int8_t* dQplanes = nullptr; // 4 base-2^6 limb planes of Qstack
    int32_t* dS = nullptr;      // one limb-pair product, m x q*m
    uint64_t* dChat = nullptr;  // Chat_wide accumulator, m x q*m
    void* workspace = nullptr;
    cudaStream_t stream = nullptr;
    cublasLtHandle_t lt = nullptr;
    constexpr size_t kWorkspaceBytes = size_t{32} << 20;

    // INT8-tier device state.
    int8_t* dA = nullptr;      // dequantized Ahat, n x n (|.| <= 48)
    int8_t* dU = nullptr;      // U, m x n
    int8_t* dV = nullptr;      // V, n x m
    int8_t* dBstack = nullptr; // dequantized [Bhat_1; ...; Bhat_q]

    // Native-tier device state.
#if BTX_BMX4C_HAVE_MXF4
    uint8_t* dOpq = nullptr;       // packed E2M1 operand slice (reused per e)
    uint8_t* dUq = nullptr;        // packed U
    uint8_t* dVq = nullptr;        // packed V
    uint8_t* dUnitScales = nullptr; // constant 0x7F block-scale tensor
    float* dDf32 = nullptr;        // mxf4 FP32 output staging
    int* dErr = nullptr;           // promotion-kernel exactness flag
#endif

    std::string error;
    bool ok = false;
    do {
        // G2: bind this entire call -- stream, cuBLASLt handle, EVERY device
        // allocation, and the qualification probes -- to the SELECTED physical
        // device. Eligibility is resolved per BTX_MATMUL_CUDA_DEVICES
        // (ProbeCudaRuntime -> device_index, the same selection the per-nonce
        // backend binds to); without this the backend would allocate and
        // execute on the ambient device (ordinal 0) even when the operator
        // selected another GPU, and the t=24 verdict would be attributed to the
        // wrong silicon. device_index < 0 (no explicit selection) keeps the
        // process-default device.
        {
            const btx::cuda::CudaRuntimeProbe runtime = btx::cuda::ProbeCudaRuntime();
            if (runtime.device_index >= 0 &&
                !CudaOk(cudaSetDevice(runtime.device_index), "cudaSetDevice(selected)", error)) {
                break;
            }
        }
        if (!CudaOk(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreate", error)) break;

        // Template-scoped, NOT window-scoped (independent of Q): allocated once.
        if (!CudaOk(cudaMalloc(&dP, mn * sizeof(int32_t)), "cudaMalloc P", error)) break;
        if (!CudaOk(cudaMalloc(&dPplanes, mn * ref::kCombineLimbs), "cudaMalloc Pplanes", error)) break;
        // The window (Q) working set is allocated adaptively AFTER tier
        // selection -- see the G6 block below.

        // cuBLASLt is required by the native tier and best-effort for the INT8
        // tier (whose scalar fallback is also bit-exact).
        if (!force_scalar) {
            if (cublasLtCreate(&lt) != CUBLAS_STATUS_SUCCESS) {
                lt = nullptr;
            } else if (cudaMalloc(&workspace, kWorkspaceBytes) != cudaSuccess) {
                workspace = nullptr;
            }
        }

        // ------------------------------------------------------------------
        // TIER SELECTION (see the file header). Native FP4 requires the
        // compile-time API, a Blackwell-class device, layout-conformant
        // shapes, a live cuBLASLt handle, and the t = 24 qualification PASS.
        // ------------------------------------------------------------------
        bool use_native = false;
#if BTX_BMX4C_HAVE_MXF4
        if (forced == ForcedPath::kAuto || forced == ForcedPath::kNative) {
            bool eligible = lt != nullptr && workspace != nullptr &&
                            (n % 32) == 0 && (m % 32) == 0;
            cudaDeviceProp prop{};
            int dev = 0;
            if (eligible) {
                eligible = cudaGetDevice(&dev) == cudaSuccess &&
                           cudaGetDeviceProperties(&prop, dev) == cudaSuccess &&
                           prop.major >= 10; // Blackwell tcgen05 block-scaled units
            }
            if (eligible) {
                // Unit-scale tensor sized for the largest GEMM of this call
                // AND the qualification probes; content constant 0x7F.
                const size_t sf_bytes = std::max({UnitScaleBytes(static_cast<size_t>(chunk_cap) * n, n),
                                                  UnitScaleBytes(n, n),
                                                  UnitScaleBytes(m, n),
                                                  UnitScaleBytes(128, 1'864'128)});
                if (cudaMalloc(&dUnitScales, sf_bytes) != cudaSuccess ||
                    cudaMemsetAsync(dUnitScales, 0x7F, sf_bytes, stream) != cudaSuccess ||
                    cudaStreamSynchronize(stream) != cudaSuccess) {
                    eligible = false;
                }
            }
            if (eligible) {
                // G2: cache the t=24 verdict per PHYSICAL device (PCI id of the
                // device bound above), not process-wide, so a mixed-GPU host
                // qualifies each part once and never reuses one part's verdict
                // for another. `dev` is the ambient/selected device set by the
                // cudaSetDevice at the top of this call.
                const std::string dev_key = DevicePhysicalKey(dev);
                std::lock_guard<std::mutex> lock(g_mxf4_qual_mutex);
                auto it = g_mxf4_qualified.find(dev_key);
                int state;
                if (it == g_mxf4_qualified.end()) {
                    std::string qual_err;
                    state = RunMxf4Qualification(lt, stream, workspace, kWorkspaceBytes,
                                                 dUnitScales, qual_err)
                                ? 1
                                : 0;
                    g_mxf4_qualified.emplace(dev_key, state);
                } else {
                    state = it->second;
                }
                eligible = state == 1;
                if (eligible) {
                    // G1: the device PROVED M-t24 / high-magnitude exactness on
                    // the block-scaled FP4 path. Emit the marker verify-backend.sh
                    // requires, keyed by physical device id (never a CPU stub).
                    EmitHighMagnitudePassMarker("native-mxf4", dev_key);
                }
            }
            use_native = eligible;
        }
        if (forced == ForcedPath::kNative && !use_native) {
            // The caller demanded the native tier and the device cannot prove
            // it. Decline loudly (dispatcher -> CPU) instead of silently
            // running INT8: the override exists for qualification runs.
            error = "BTX_MATMUL_BMX4C_CUDA_PATH=fp4 but the native mxf4 tier is unavailable or failed t=24 qualification";
            break;
        }
#else
        if (forced == ForcedPath::kNative) {
            error = "BTX_MATMUL_BMX4C_CUDA_PATH=fp4 but this build lacks the cuBLASLt >= 12.8 block-scaled FP4 API";
            break;
        }
#endif

        // ------------------------------------------------------------------
        // G6: adaptive window (Q) allocation. The per-window working set scales
        // with chunk_cap -- the shared Qtall/Qstack/Qplanes/S/Chat buffers plus
        // the chosen tier's Q-dependent operands (native dOpq/dDf32, or INT8
        // dBstack). On a memory-constrained or shared device the configured Q
        // can exceed free VRAM; rather than abandoning the whole window (which
        // fails closed to the CPU miner) we HALVE Q on cudaErrorMemoryAllocation
        // and retry, down to kMinBatchedWindow. The reduction is byte-
        // transparent: per-nonce results are independent, so a smaller window
        // just means more internal chunks with identical digests. Buffers are
        // freed+reallocated once at the fitted Q, then REUSED across every
        // chunk of the window (no per-chunk malloc traffic).
        {
            auto free_q_buffers = [&]() {
                if (dChat) { cudaFree(dChat); dChat = nullptr; }
                if (dS) { cudaFree(dS); dS = nullptr; }
                if (dQplanes) { cudaFree(dQplanes); dQplanes = nullptr; }
                if (dQstack) { cudaFree(dQstack); dQstack = nullptr; }
                if (dQtall) { cudaFree(dQtall); dQtall = nullptr; }
#if BTX_BMX4C_HAVE_MXF4
                if (dDf32) { cudaFree(dDf32); dDf32 = nullptr; }
                if (dOpq) { cudaFree(dOpq); dOpq = nullptr; }
#endif
                if (dBstack) { cudaFree(dBstack); dBstack = nullptr; }
            };
            // Allocate every Q-dependent buffer for `cap`. Returns cudaSuccess,
            // or the first failing error with all Q buffers freed (nulled).
            auto try_alloc_q = [&](uint32_t cap) -> cudaError_t {
                const size_t q_cols = static_cast<size_t>(cap) * m;
                const size_t stack = static_cast<size_t>(n) * q_cols; // Qtall/Qstack elems
                const size_t out = static_cast<size_t>(m) * q_cols;   // Chat_wide elems
                cudaError_t e;
                if ((e = cudaMalloc(&dQtall, stack * sizeof(int32_t))) != cudaSuccess) { free_q_buffers(); return e; }
                if ((e = cudaMalloc(&dQstack, stack * sizeof(int32_t))) != cudaSuccess) { free_q_buffers(); return e; }
                if ((e = cudaMalloc(&dQplanes, stack * ref::kCombineLimbs)) != cudaSuccess) { free_q_buffers(); return e; }
                if ((e = cudaMalloc(&dS, out * sizeof(int32_t))) != cudaSuccess) { free_q_buffers(); return e; }
                if ((e = cudaMalloc(&dChat, out * sizeof(uint64_t))) != cudaSuccess) { free_q_buffers(); return e; }
#if BTX_BMX4C_HAVE_MXF4
                if (use_native) {
                    const size_t packed_nn = (nn + 1) / 2;
                    const size_t packed_stack = (static_cast<size_t>(cap) * nn + 1) / 2;
                    if ((e = cudaMalloc(&dOpq, std::max(packed_nn, packed_stack))) != cudaSuccess) { free_q_buffers(); return e; }
                    if ((e = cudaMalloc(&dDf32, std::max(mn, stack) * sizeof(float))) != cudaSuccess) { free_q_buffers(); return e; }
                }
#endif
                if (!use_native) {
                    if ((e = cudaMalloc(&dBstack, static_cast<size_t>(cap) * nn)) != cudaSuccess) { free_q_buffers(); return e; }
                }
                return cudaSuccess;
            };

            cudaError_t qe = cudaSuccess;
            for (;;) {
                qe = try_alloc_q(chunk_cap);
                if (qe == cudaSuccess) break;
                if (qe == cudaErrorMemoryAllocation && chunk_cap > kMinBatchedWindow) {
                    cudaGetLastError(); // clear the non-sticky OOM before retrying
                    chunk_cap = std::max<uint32_t>(chunk_cap / 2, kMinBatchedWindow);
                    continue;
                }
                break; // success handled above; here: non-OOM error, or OOM already at the floor
            }
            if (qe != cudaSuccess) {
                error = std::string("cudaMalloc window working set (Q reduced to ") +
                        std::to_string(chunk_cap) + "): " + cudaGetErrorString(qe);
                break; // fail closed -> dispatcher runs the CPU reference
            }
            if (chunk_cap < configured_window) {
                // Report the EFFECTIVE Q. A shrink is a device-capacity signal,
                // not an error -- the digests are unaffected (byte-transparent).
                std::fprintf(stderr,
                             "[bmx4c-cuda] window reduced to Q=%u (configured %u) to fit device memory\n",
                             chunk_cap, configured_window);
            }
        }

        // ------------------------------------------------------------------
        // STAGE P = U*Ahat (template-scoped, once per call) and its limb
        // planes. Exact int32 either way; identical bytes either way.
        // ------------------------------------------------------------------
        if (use_native) {
#if BTX_BMX4C_HAVE_MXF4
            // Raw committed planes (the exact streams ExpandOperandA consumes,
            // so sum_e 2^e * A_e == Ahat entry-for-entry by construction).
            std::vector<int8_t> mu_a(nn);
            ref::ExpandMantissaStream(seed_a, nn, mu_a.data());
            std::vector<uint8_t> scale_a(static_cast<size_t>(n) * (n / ref::kBlockLen));
            ref::ExpandScaleStream(seed_a, scale_a.size(), scale_a.data());

            std::vector<uint8_t> a_planes[ref::kNumScaleCodes];
            PackOperandAMaskedPlanes(mu_a, scale_a, n, a_planes);
            std::vector<uint8_t> u_packed;
            PackProjectorU(U, m, n, u_packed);

            // dUq/dVq/dErr are Q-INDEPENDENT (template-scoped); dOpq/dDf32 are
            // Q-dependent and already allocated by the G6 adaptive block above.
            if (!CudaOk(cudaMalloc(&dUq, u_packed.size()), "cudaMalloc Uq", error)) break;
            if (!CudaOk(cudaMalloc(&dVq, (nm + 1) / 2), "cudaMalloc Vq", error)) break;
            if (!CudaOk(cudaMalloc(&dErr, sizeof(int)), "cudaMalloc Err", error)) break;
            if (!CudaOk(cudaMemsetAsync(dErr, 0, sizeof(int), stream), "Err memset", error)) break;
            if (!CudaOk(cudaMemcpyAsync(dUq, u_packed.data(), u_packed.size(), cudaMemcpyHostToDevice, stream), "H2D Uq", error)) break;
            {
                std::vector<uint8_t> v_packed;
                PackProjectorV(V, n, m, v_packed);
                if (!CudaOk(cudaMemcpyAsync(dVq, v_packed.data(), v_packed.size(), cudaMemcpyHostToDevice, stream), "H2D Vq", error)) break;
                if (!CudaOk(cudaStreamSynchronize(stream), "Vq sync", error)) break; // v_packed goes out of scope
            }

            // P = sum_e 2^e * (U * A_e): 4 mxf4 GEMMs, exact shift recombine.
            if (!CudaOk(cudaMemsetAsync(dP, 0, mn * sizeof(int32_t), stream), "P memset", error)) break;
            const float per_gemm_bound = 36.0f * static_cast<float>(n); // spec §2.2, exact in FP32
            bool stage_failed = false;
            for (uint32_t e = 0; e < ref::kNumScaleCodes; ++e) {
                if (!CudaOk(cudaMemcpyAsync(dOpq, a_planes[e].data(), a_planes[e].size(),
                                            cudaMemcpyHostToDevice, stream), "H2D A_e", error) ||
                    !CudaOk(cudaStreamSynchronize(stream), "A_e sync", error) || // host buffer reused next e
                    !RunMxf4Gemm(lt, stream, workspace, kWorkspaceBytes, dUq, dOpq,
                                 dUnitScales, dUnitScales, dDf32, m, n, n, error)) {
                    stage_failed = true;
                    break;
                }
                Bmx4PromoteShiftedKernel<<<BlocksFor(mn), kThreads, 0, stream>>>(
                    dDf32, dP, m, n, e, per_gemm_bound, dErr);
                if (!CudaOk(cudaGetLastError(), "P promote launch", error)) {
                    stage_failed = true;
                    break;
                }
            }
            if (stage_failed) break;
            int err_flag = 0;
            if (!CudaOk(cudaMemcpyAsync(&err_flag, dErr, sizeof(int), cudaMemcpyDeviceToHost, stream), "Err D2H", error) ||
                !CudaOk(cudaStreamSynchronize(stream), "P stage sync", error)) {
                break;
            }
            if (err_flag != 0) {
                error = "mxf4 P-stage produced a non-integral or out-of-bound value (C-1' violation)";
                break;
            }
#endif
        } else {
            // INT8 tier: 1 GEMM on pre-shifted operands. The exact dequant
            // (mu * 2^e, |.| <= 48) is the committed ExpandOperandA routine
            // itself, so the s8 bytes are the reference's bytes.
            const std::vector<int8_t> Ahat = ref::ExpandOperandA(seed_a, n);
            // dA/dU/dV are Q-INDEPENDENT; dBstack is Q-dependent and already
            // allocated by the G6 adaptive block above.
            if (!CudaOk(cudaMalloc(&dA, nn), "cudaMalloc A", error)) break;
            if (!CudaOk(cudaMalloc(&dU, mn), "cudaMalloc U", error)) break;
            if (!CudaOk(cudaMalloc(&dV, nm), "cudaMalloc V", error)) break;
            if (!CudaOk(cudaMemcpyAsync(dA, Ahat.data(), nn, cudaMemcpyHostToDevice, stream), "H2D A", error)) break;
            if (!CudaOk(cudaMemcpyAsync(dU, U.data(), mn, cudaMemcpyHostToDevice, stream), "H2D U", error)) break;
            if (!CudaOk(cudaMemcpyAsync(dV, V.data(), nm, cudaMemcpyHostToDevice, stream), "H2D V", error)) break;
            if (!CudaOk(cudaStreamSynchronize(stream), "operand sync", error)) break; // Ahat goes out of scope
            if (!RunGemmAuto(lt, stream, workspace, kWorkspaceBytes, force_scalar,
                             dU, dA, dP, m, n, n, error)) {
                break;
            }
        }
        Bmx4DecomposeLimbPlanesKernel<<<BlocksFor(mn), kThreads, 0, stream>>>(dP, dPplanes, mn);
        if (!CudaOk(cudaGetLastError(), "P limb decompose launch", error)) break;

        // ------------------------------------------------------------------
        // WINDOW CHUNKS. Per-nonce results are independent, so chunking is
        // byte-transparent (v4.1 precedent).
        // ------------------------------------------------------------------
        std::vector<int8_t> bstack_host;
#if BTX_BMX4C_HAVE_MXF4
        std::vector<uint8_t> b_planes[ref::kNumScaleCodes];
        std::vector<int8_t> mu_b;
        std::vector<uint8_t> scale_b;
#endif
        if (!use_native) {
            bstack_host.resize(static_cast<size_t>(chunk_cap) * nn);
        }

        bool chunk_failed = false;
        for (uint32_t start = 0; start < count; start += chunk_cap) {
            const uint32_t q = std::min(chunk_cap, count - start);
            const size_t q_cols = static_cast<size_t>(q) * m;
            const size_t stack_elems = static_cast<size_t>(n) * q_cols;
            const size_t out_elems = static_cast<size_t>(m) * q_cols;
            const size_t tall_elems = static_cast<size_t>(q) * n * m;
            (void)tall_elems; // consumed by the native tier only (compiled out pre-CUDA-12.8)

            if (use_native) {
#if BTX_BMX4C_HAVE_MXF4
                // HOST: expand each nonce's committed (mu, e) planes (exact
                // routines; nonce-fresh seed_B) and pack the four
                // exponent-masked E2M1 stacks in one pass.
                const size_t packed_q = (static_cast<size_t>(q) * nn + 1) / 2;
                for (auto& plane : b_planes) plane.assign(packed_q, 0);
                mu_b.resize(nn);
                scale_b.resize(static_cast<size_t>(n / ref::kBlockLen) * n);
                for (uint32_t idx = 0; idx < q; ++idx) {
                    const uint256 seed_b =
                        ref::DeriveOperandSeedBMX4C(headers[start + idx], matmul::v4::Operand::B);
                    ref::ExpandMantissaStream(seed_b, nn, mu_b.data());
                    ref::ExpandScaleStream(seed_b, scale_b.size(), scale_b.data());
                    PackOperandBMaskedPlanes(mu_b, scale_b, n, static_cast<size_t>(idx) * n, b_planes);
                }

                // Qtall = sum_e 2^e * ([B_1;...;B_q]_e * V): 4 stacked mxf4
                // GEMMs (M = q*n, N = m, K = n) + exact shift recombine.
                if (!CudaOk(cudaMemsetAsync(dQtall, 0, tall_elems * sizeof(int32_t), stream), "Qtall memset", error) ||
                    !CudaOk(cudaMemsetAsync(dErr, 0, sizeof(int), stream), "Err memset", error)) {
                    chunk_failed = true;
                    break;
                }
                const float per_gemm_bound = 36.0f * static_cast<float>(n);
                for (uint32_t e = 0; e < ref::kNumScaleCodes; ++e) {
                    if (!CudaOk(cudaMemcpyAsync(dOpq, b_planes[e].data(), b_planes[e].size(),
                                                cudaMemcpyHostToDevice, stream), "H2D B_e", error) ||
                        !RunMxf4Gemm(lt, stream, workspace, kWorkspaceBytes, dOpq, dVq,
                                     dUnitScales, dUnitScales, dDf32, q * n, m, n, error) ||
                        !CudaOk(cudaStreamSynchronize(stream), "B_e sync", error)) { // host plane reused next chunk
                        chunk_failed = true;
                        break;
                    }
                    Bmx4PromoteShiftedKernel<<<BlocksFor(tall_elems), kThreads, 0, stream>>>(
                        dDf32, dQtall, q * n, m, e, per_gemm_bound, dErr);
                    if (!CudaOk(cudaGetLastError(), "Q promote launch", error)) {
                        chunk_failed = true;
                        break;
                    }
                }
                if (chunk_failed) break;
                int err_flag = 0;
                if (!CudaOk(cudaMemcpyAsync(&err_flag, dErr, sizeof(int), cudaMemcpyDeviceToHost, stream), "Err D2H", error) ||
                    !CudaOk(cudaStreamSynchronize(stream), "Q stage sync", error)) {
                    chunk_failed = true;
                    break;
                }
                if (err_flag != 0) {
                    error = "mxf4 Q-stage produced a non-integral or out-of-bound value (C-1' violation)";
                    chunk_failed = true;
                    break;
                }
#endif
            } else {
                // HOST: dequantized nonce-fresh Bhat via the exact committed
                // routine, staged as the vertical stack (v4.1 shape).
                for (uint32_t idx = 0; idx < q; ++idx) {
                    const uint256 seed_b =
                        ref::DeriveOperandSeedBMX4C(headers[start + idx], matmul::v4::Operand::B);
                    const std::vector<int8_t> Bhat = ref::ExpandOperandB(seed_b, n);
                    std::copy(Bhat.begin(), Bhat.end(), bstack_host.begin() + static_cast<size_t>(idx) * nn);
                }
                if (!CudaOk(cudaMemcpyAsync(dBstack, bstack_host.data(), static_cast<size_t>(q) * nn,
                                            cudaMemcpyHostToDevice, stream), "H2D Bstack", error)) {
                    chunk_failed = true;
                    break;
                }
                // ONE stacked s8 GEMM Qtall = [Bhat_1;...;Bhat_q] * V — the
                // full-rate 1-GEMM INT8 path (spec §5.2): row block i of Qtall
                // is exactly Q_i = Bhat_i*V (exact INT32).
                if (!RunGemmAuto(lt, stream, workspace, kWorkspaceBytes, force_scalar,
                                 dBstack, dV, dQtall, q * n, m, n, error)) {
                    chunk_failed = true;
                    break;
                }
            }

            // Qtall -> Qstack permutation, then the entrywise base-2^6 limb
            // planes (both tiers converge here; every value is the exact
            // integer the CPU reference holds at the same point).
            Bmx4ScatterQStackKernel<<<BlocksFor(stack_elems), kThreads, 0, stream>>>(dQtall, dQstack, n, m, q);
            if (!CudaOk(cudaGetLastError(), "Qstack scatter launch", error)) {
                chunk_failed = true;
                break;
            }
            Bmx4DecomposeLimbPlanesKernel<<<BlocksFor(stack_elems), kThreads, 0, stream>>>(
                dQstack, dQplanes, stack_elems);
            if (!CudaOk(cudaGetLastError(), "Q limb decompose launch", error)) {
                chunk_failed = true;
                break;
            }

            // Chat_wide = 0, then the 16 limb-pair combine GEMMs
            // S_ij = P_i * Qstack_j (m x q*m x n, per-entry |.| <= 1024n
            // < 2^31 — true int32, IMMA-native) with the shifted mod-q fold,
            // in the CPU's (i outer, j inner) order.
            if (!CudaOk(cudaMemsetAsync(dChat, 0, out_elems * sizeof(uint64_t), stream), "Chat memset", error)) {
                chunk_failed = true;
                break;
            }
            for (uint32_t i = 0; i < ref::kCombineLimbs && !chunk_failed; ++i) {
                for (uint32_t j = 0; j < ref::kCombineLimbs; ++j) {
                    const int8_t* Pi = dPplanes + static_cast<size_t>(i) * mn;
                    const int8_t* Qj = dQplanes + static_cast<size_t>(j) * stack_elems;
                    if (!RunGemmAuto(lt, stream, workspace, kWorkspaceBytes, force_scalar,
                                     Pi, Qj, dS, m, static_cast<uint32_t>(q_cols), n, error)) {
                        chunk_failed = true;
                        break;
                    }
                    // weight = 2^(6*(i+j)) mod q; exponent <= 36 < 61 so the
                    // canonical weight is the plain power of two (CPU-equal,
                    // matmul_v4_bmx4.cpp weight table).
                    const uint64_t w = static_cast<uint64_t>(1) << (6 * (i + j));
                    Bmx4LimbRecombineKernel<<<BlocksFor(out_elems), kThreads, 0, stream>>>(dS, dChat, w, out_elems);
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
            // digest with the exact CPU routines — the same tail as
            // ComputeDigestBMX4C (SerializeSketch + H(sigma || payload)).
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

#if BTX_BMX4C_HAVE_MXF4
    if (dErr) cudaFree(dErr);
    if (dDf32) cudaFree(dDf32);
    if (dUnitScales) cudaFree(dUnitScales);
    if (dOpq) cudaFree(dOpq);
    if (dVq) cudaFree(dVq);
    if (dUq) cudaFree(dUq);
#endif
    if (dBstack) cudaFree(dBstack);
    if (dV) cudaFree(dV);
    if (dU) cudaFree(dU);
    if (dA) cudaFree(dA);
    if (workspace) cudaFree(workspace);
    if (lt) cublasLtDestroy(lt);
    if (dChat) cudaFree(dChat);
    if (dS) cudaFree(dS);
    if (dQplanes) cudaFree(dQplanes);
    if (dQstack) cudaFree(dQstack);
    if (dQtall) cudaFree(dQtall);
    if (dPplanes) cudaFree(dPplanes);
    if (dP) cudaFree(dP);
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
