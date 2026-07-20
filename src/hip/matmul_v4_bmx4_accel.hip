// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_bmx4_accel.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <hip/hip_runtime.h>

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

// ===========================================================================
// AMD ROCm/HIP ENC-BMX4C MatMul v4.2 backend.
//
// See matmul_v4_bmx4_accel.h for the full algorithm/contract writeup. Summary:
// this is the structural sibling of src/hip/matmul_v4_accel.hip (the reviewed
// v4.1 ENC-S8 batched HIP backend) retargeted to the ENC-BMX4C profile
// (src/matmul/matmul_v4_bmx4.{h,cpp}): dequantized mu*2^e integer operands
// (|Ahat|,|Bhat| <= 48), scale-free M11 projectors U/V (|.| <= 6), and a
// 4-limb balanced BASE-2^6 (not base-2^7) remainder-top combine.
//
// COMPUTE MODEL (mirrors matmul::v4::bmx4::ComputeDigestBMX4C exactly):
//   Chat = (U*Ahat)(Bhat*V) mod q,  q = 2^61-1,  never materializing n x n C.
//   P = U*Ahat   (m x n, exact INT32, |P_ij| <= 288*n <= 2^23-1)
//   Q_i = Bhat_i*V (n x m, exact INT32, same bound)
//   Chat_i[a][c] = sum_j P[a][j]*Q_i[j][c] mod q.
// Because reduction mod q is a ring homomorphism and the underlying exact
// integer matrix (U*Ahat)(Bhat_i*V) is identical to the CPU's for every
// header i, the canonical F_q residues -- hence SerializeSketch's bytes and
// the digest -- are byte-identical to matmul::v4::bmx4::ComputeDigestBMX4C
// regardless of GEMM tiling/accumulation order (integer add is associative).
//
// TEMPLATE AMORTIZATION (I1', same rule the CPU seed derivation already
// implies via ComputeTemplateHash): Ahat, U, V, and P = U*Ahat are derived
// from headers[0] and computed ONCE per call; every header MUST project onto
// that same template hash (fail-closed, checked up front, no partial output)
// exactly like matmul_v4::hip::ComputeDigestsBatchedAccel's v4.1 analogue.
// Only Bhat_i (nonce-fresh), Q_i, and the per-header combine slice are
// marginal per-nonce cost.
//
// COMBINE (base-2^6 limb tensor, matmul_v4_bmx4.cpp::ComputeCombineLimbTensorBMX4C
// / DecomposeLimbPlanesBMX4C, bit-for-bit device port): every P/Q entry is
// decomposed into 4 balanced base-64 digits with the REMAINDER-TOP rule (3
// masked low digits d in [-32,31] via d=((x+32)&63)-32, x=(x-d)/64, then an
// UNMASKED top digit carrying the exact remainder) -- this is what makes the
// decomposition TOTAL for the whole |x| <= 2^23-1 window (not just the
// smaller pure-balanced range a 4-digit scheme would otherwise cover; see
// matmul_v4_bmx4.h's kCombinePureBalancedPositiveExtreme commentary). The 16
// limb-pair products S_ij (each |.| <= 1024*n <= 2^22 at n=4096, 2^23 at
// n=8192 -- fits exact int32) fold as
//     Chat = sum_ij 64^(i+j) * S_ij mod q = sum_ij 2^(6(i+j)) * S_ij mod q,
// weights precomputed (every exponent 6*(i+j) <= 36 < 61, so the weight is
// the literal power of two, no reduction needed -- matches the CPU's
// `weight[i][j] = Fq(1) << (6*(i+j))` exactly).
//
// TWO COMPUTE TIERS FOR THE GEMMS (P = U*Ahat, Q_i = Bhat_i*V, and the 16
// limb-pair S_ij products) -- see SelectComputeTier below:
//   (a) native CDNA4 block-scaled MXFP4 (E8M0 exact power-of-two scale),
//       eligible only once a device is t=24-proven (design spec §5.2/§5.3);
//   (b) INT8 MFMA fallback: pre-shifted dequantized int8 operands run as ONE
//       s8xs8->s32 GEMM family at full INT8 rate, true int32 accumulate.
// This backend implements and always dispatches tier (b) -- see
// SelectComputeTier's comment for exactly why tier (a) cannot be safely wired
// in this development environment.
// ===========================================================================

namespace matmul_v4::bmx4::hip {

bool Bmx4CHipBackendCompiled() { return true; }

namespace {

using matmul::int8_field::Fq;

// q = 2^61 - 1, mirrored on the device (matches int8_field.h::kFieldPrime).
// Duplicated verbatim from matmul_v4_accel.hip's device Fq arithmetic: this
// is a separate translation unit (its own .hip compile), so the anonymous-
// namespace device helpers there are not visible here; the bodies are kept
// byte-for-byte identical to that reviewed copy (and to int8_field.cpp) on
// purpose -- there is exactly one correct F_q implementation.
__device__ __host__ __forceinline__ uint64_t DevFieldPrime()
{
    return (static_cast<uint64_t>(1) << 61) - 1;
}

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

__device__ __forceinline__ Fq DevFqFromSigned(int64_t x)
{
    if (x >= 0) {
        return DevFqReduce(static_cast<unsigned __int128>(static_cast<uint64_t>(x)));
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(x + 1)) + 1; // safe for INT64_MIN
    const uint64_t q = DevFieldPrime();
    const uint64_t reduced = static_cast<uint64_t>(DevFqReduce(static_cast<unsigned __int128>(magnitude)));
    return reduced == 0 ? 0 : q - reduced; // DevFqNeg inlined (unused standalone here)
}

// Amendment v2 §1.D D4: MFMA only on CDNA; never emit MFMA for gfx1200/RDNA4.
#include <hip/btx_hip_mfma_guard.h>

using int32x4 = int32_t __attribute__((ext_vector_type(4)));

// Pack this lane's four consecutive-K int8 operands into one 32-bit register
// (byte p holds K index kBase+p, lowest K in the least-significant byte -- the
// standard CDNA A/B packing along K). Identical convention to the v4.1 file.
__device__ __forceinline__ int PackI8x4(int8_t v0, int8_t v1, int8_t v2, int8_t v3)
{
    return static_cast<int>((static_cast<uint32_t>(static_cast<uint8_t>(v0))) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v1)) << 8) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v2)) << 16) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(v3)) << 24));
}

// Exact INT8xINT8 -> INT32 GEMM D(MxN) = A(MxK) * B(KxN), all row-major, exact
// integer accumulate. Verbatim-duplicated body from matmul_v4_accel.hip's
// I8GemmTiled (own translation unit, own anonymous namespace -- no link
// clash): one wavefront (blockDim = {16,4,1}) computes one 16x16 output tile;
// grid = {ceil(N/16), ceil(M/16)}. Ragged M/N/K are zero-padded (int8 zero
// contributes nothing, exact). This is tier (b)'s workhorse for both
// P = U*Ahat and Q_i = Bhat_i*V and the 16 limb-pair S_ij products -- all four
// GEMM shapes this backend needs share this one kernel.
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

#if defined(BTX_HIP_BMX4C_HAVE_MFMA)
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
    // Portable scalar-integer twin producing the identical integer result.
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

// Same GEMM math as I8GemmTiled, but the MxN output tile is written at
// row-stride `ldD` starting at column `colOffset` -- lets Q_i = Bhat_i*V land
// directly in its column block [colOffset, colOffset+m) of the horizontal
// stack Qstack (n x count*m, ldD = count*m), no separate copy/reshape kernel.
// Verbatim-duplicated shape from matmul_v4_accel.hip's I8GemmTiledOffset.
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

#if defined(BTX_HIP_BMX4C_HAVE_MFMA)
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

static_assert(matmul::v4::bmx4::kCombineLimbs == 4 && matmul::v4::bmx4::kCombineLimbBase == 64,
             "DecomposeLimbPlanesBase64Kernel/AccumulateChatKernel hard-code the 4-limb "
             "balanced base-2^6 remainder-top decomposition; keep in sync with "
             "matmul_v4_bmx4.h");

// Entrywise 4-digit balanced BASE-2^6 decomposition with the REMAINDER-TOP
// rule -- a bit-for-bit device port of matmul::v4::bmx4::
// DecomposeLimbPlanesBMX4C (matmul_v4_bmx4.cpp, anonymous namespace). For
// each element x: extract 3 balanced digits d in [-32,31] via the recurrence
//   d = ((x + 32) & 63) - 32;  x = (x - d) / 64;
// (exact: x-d is always a multiple of 64), THEN store the remaining x
// UNMASKED as the 4th ("top") digit -- NOT run through the same balanced-
// digit formula again. This is the load-bearing difference from a "pure"
// 4-digit balanced base-2^6 scheme (which would only totally cover
// |x| <= 8,255,455, i.e. n <= 28,664 at the 288n projection bound): the
// remainder-top digit instead carries the EXACT remainder in [-32,+32],
// giving totality for the whole |x| <= 2^23-1 window (n <= 29,127,
// CheckCombineLimbBoundBMX4C) that this backend's caller validates before any
// kernel launch. Every element is decomposed independently of every other
// (no cross-thread state), so parallelizing over elements reproduces the CPU
// decomposition digit-for-digit for every entry.
__global__ void DecomposeLimbPlanesBase64Kernel(const int32_t* __restrict__ M,
                                                int8_t* __restrict__ plane0,
                                                int8_t* __restrict__ plane1,
                                                int8_t* __restrict__ plane2,
                                                int8_t* __restrict__ plane3,
                                                size_t count)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    int32_t x = M[idx];

    int32_t d = ((x + 32) & 63) - 32;
    plane0[idx] = static_cast<int8_t>(d);
    x = (x - d) / 64; // exact: (x - d) is a multiple of 64

    d = ((x + 32) & 63) - 32;
    plane1[idx] = static_cast<int8_t>(d);
    x = (x - d) / 64;

    d = ((x + 32) & 63) - 32;
    plane2[idx] = static_cast<int8_t>(d);
    x = (x - d) / 64;

    // Remainder-top digit: whatever remains, in [-32, +32] under the bound
    // the host validated (CheckCombineLimbBoundBMX4C) -- NOT masked with
    // ((x+32)&63)-32 again, matching DecomposeLimbPlanesBMX4C exactly.
    plane3[idx] = static_cast<int8_t>(x);
}

// Chat[idx] = FqAdd(Chat[idx], FqMul(weight, FqFromSigned(S[idx]))). Verbatim
// same kernel as matmul_v4_accel.hip's AccumulateChatKernel (the fold step is
// identical regardless of limb base): invoked once per limb pair (i,j) with
// weight = 64^(i+j) mod q = 2^(6*(i+j)) mod q (every exponent 6*(i+j) <= 36 <
// 61, so the weight is just the literal power of two, matching the CPU's
// `weight[i][j] = Fq(1) << (6*(i+j))`). F_q addition is commutative and
// associative over the exact integer sum
//     sum_k P[a][k]*Qstack[k][c] = sum_ij 64^(i+j) * S_ij[a][c],
// so accumulating the 16 limb-pair contributions here (any launch order)
// reproduces the identical canonical F_q residue as
// matmul::v4::bmx4::ComputeCombineLimbTensorBMX4C.
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

// RAII-ish device buffer so every early return frees cleanly. Identical to
// the v4.1 sibling's DeviceBuffer.
struct DeviceBuffer {
    void* ptr{nullptr};
    ~DeviceBuffer() { if (ptr) hipFree(ptr); }
    bool Alloc(size_t bytes)
    {
        if (bytes == 0) { ptr = nullptr; return true; }
        return hipMalloc(&ptr, bytes) == hipSuccess;
    }
};

// ===========================================================================
// Tier (a) native CDNA4 block-scaled MXFP4 gate (design spec §5.1/§5.2, C-1').
// ===========================================================================
//
// The ENC-BMX4C sampler's accepted nibble IS the element's OCP E2M1 bit
// pattern (matmul_v4_bmx4.cpp::SampleMantissaNibble: sign | 2-bit exp | 1-bit
// mantissa, identity decode) and the scale plane is already E8M0 codes
// 127..130 (e in {0..3}) at OCP block length L = 32 along each projection's
// contraction dimension: A uses e_A(i/32,k) in U*A and B uses e_B(k,j/32)
// in B*V. The committed values and scale semantics therefore match an OCP MX
// block-scaled tensor without transposition. A native kernel must still pack
// the vendor's physical scale layout and qualify it on silicon. On CDNA4
// (gfx950, e.g. MI355X) this is exactly the native "mxf4"/E8M0-scaled block
// FP4 GEMM datapath hipBLASLt exposes (block-scaled matmul with an
// HIPBLASLT_R_4F_E2M1-class element type and an E8M0 scale type, per ROCm
// 6.x+ hipBLASLt's OCP-microscaling support) or a future
// v_mfma_scale_*_f8f6f4-class compiler intrinsic once one is architected and
// documented for gfx950.
//
// Native-path GEMM shapes this would replace (identical math to tier (b),
// just executed at the device's native block-scaled FP4 rate instead of via
// a pre-shifted s8 GEMM): P = U*Ahat and each Q_i = Bhat_i*V would run as one
// block-scaled FP4 GEMM apiece (U/V are scale-free M11, i.e. block scale
// identically 2^0 -- still a valid, degenerate MX block); the 16 limb-pair
// S_ij products stay INT8 (the limb planes are exact base-64 digits in
// [-32,31], not FP4-representable, so the combine is deliberately NOT run
// native per doc/btx-matmul-v4.2-bmx4c-spec.md §3's closing paragraph: a
// 4-bit-native combine would cost ~64 pair-GEMMs vs 16 s8 GEMMs, strictly
// worse on every part with an INT8 pipe).
//
// THE GATE. Per C-1' (design spec §5.1) a device is eligible for the native
// block-scaled path only if it has PROVEN (not merely claimed on a datasheet)
// a true >= 24-bit exact accumulator on that datapath -- the §5.3 M-t24
// vectors run and passing on real silicon
// (nMatMulBMX4CMinProvenAccumulatorBits, consensus/params.h). This function
// returns that proof state for the current build/device.
//
// It returns false UNCONDITIONALLY here. Reasons, stated per this task's
// "unverifiable without hardware" requirement:
//   1. No AMD GPU and no ROCm toolchain are available in this development
//      environment -- there is no way to compile, launch, or observe a
//      real hipBLASLt block-scaled MXFP4 GEMM, let alone confirm its
//      accumulator proves t=24 (design doc §5.3/§9: M-t24 PASS on >= 2
//      independent vendors' frontier parts is a hard activation
//      precondition, not an implementation detail this backend can assert
//      on its own).
//   2. The exact hipBLASLt/rocBLAS enum names, call signature, and required
//      MX-block memory layout for gfx942/gfx950 vary across ROCm releases;
//      hard-coding a guess here without a header to compile against risks
//      shipping code that silently does the wrong thing (or nothing) on
//      real hardware -- worse than the explicit, honest "not wired" state.
//   3. This file may not add a hipBLASLt/rocBLAS link dependency (no
//      CMakeLists changes are in scope for this task), so even a correct
//      enum name could not be dispatched through the real library from here.
// Flip this to a real per-device query (and wire the actual dispatch) only
// after M-t24 passes on real MI300/MI355-class silicon per
// doc/btx-matmul-v4.2-bmx4c-spec.md §5.3/§9, with real ROCm headers in hand.
[[nodiscard]] constexpr bool NativeMxfp4PathProvenT24Eligible()
{
    return false;
}

// ===========================================================================
// Tier selection.
// ===========================================================================
enum class ComputeTier { kNativeMxfp4, kInt8Mfma };

[[nodiscard]] ComputeTier SelectComputeTier()
{
    // design spec §5.2 fallback ladder: FP4 block-scaled (t=24) -> FP8 fold
    // (t>=17) -> INT8 1-GEMM (true int32, this backend's only implemented
    // GEMM kernel) -> mantissa-plane extraction -> CPU. This backend
    // implements the two ends of that ladder that matter for a real CDNA
    // part: the native block-scaled path (gated off, see
    // NativeMxfp4PathProvenT24Eligible) and the INT8 MFMA fallback (always
    // available, true int32 accumulate, E_max=48 fits s8 natively so it is
    // ALWAYS a single GEMM family, never a multi-slice schedule).
    if (NativeMxfp4PathProvenT24Eligible()) {
        return ComputeTier::kNativeMxfp4; // unreachable today; see the gate's comment
    }
    return ComputeTier::kInt8Mfma;
}

} // namespace

bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                              std::vector<uint256>& digests_out,
                              std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();

    // Identical validation to matmul::v4::bmx4::ComputeDigestBMX4C: n%32==0
    // (E8M0 blocks), the base-2^6 combine's 288*n <= 2^23-1 bound, and the
    // shared v4 (n,b) dimension bound.
    uint32_t m = 0;
    if (!matmul::v4::bmx4::ValidateDimsBMX4C(n, matmul::v4::kTileB, m)) {
        return false;
    }
    if (rounds == 0) {
        return false;
    }
    if (headers.empty()) {
        return false;
    }

    const uint32_t count = static_cast<uint32_t>(headers.size());

    // Fail-closed template gate (I1', matching the CPU seed derivation's
    // ComputeTemplateHash scoping and the v4.1 batched HIP backend exactly):
    // every header MUST project onto headers[0]'s template hash before any
    // device work is issued, or this call returns false with no partial
    // output. sigma (nonce-fresh) is derived here too, unchanged from v4.1.
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(headers[0]);
    std::vector<uint256> sigmas(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (matmul::v4::ComputeTemplateHash(headers[i]) != template_hash) {
            return false;
        }
        sigmas[i] = matmul::v4::DeriveSigma(headers[i]); // UNCHANGED from v4.1
    }

    const ComputeTier tier = SelectComputeTier();
    (void)tier; // both tiers would use identical GEMM shapes/kernels below;
                // only kNativeMxfp4's dispatch differs, and it is unreachable
                // (see NativeMxfp4PathProvenT24Eligible) -- kInt8Mfma is what
                // actually runs, via the I8GemmTiled(Offset) kernels.

    // --- TEMPLATE-scoped derivation, ONCE per window: Ahat, U, V from
    // headers[0]'s template (byte-identical to CPU via the SHARED reference
    // routines), then P = U*Ahat on the MFMA cores. ---
    const uint256 seed_a = matmul::v4::bmx4::DeriveOperandSeedBMX4C(headers[0], matmul::v4::Operand::A);
    const auto [seed_u, seed_v] = matmul::v4::bmx4::DeriveProjectorSeedsBMX4C(headers[0]);
    const std::vector<int8_t> Ahat = matmul::v4::bmx4::ExpandOperandA(seed_a, n);            // n x n, |.| <= 48
    const std::vector<int8_t> U = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_u, m, n);      // m x n, |.| <= 6
    const std::vector<int8_t> V = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_v, n, m);      // n x m, |.| <= 6

    const size_t nn = static_cast<size_t>(n) * n;
    const size_t mn = static_cast<size_t>(m) * n;

    DeviceBuffer dAhat, dU, dV, dP;
    DeviceBuffer dPPlane[matmul::v4::bmx4::kCombineLimbs];
    if (!dAhat.Alloc(nn * sizeof(int8_t)) ||
        !dU.Alloc(mn * sizeof(int8_t)) ||
        !dV.Alloc(mn * sizeof(int8_t)) ||
        !dP.Alloc(mn * sizeof(int32_t))) {
        return false;
    }
    for (uint32_t l = 0; l < matmul::v4::bmx4::kCombineLimbs; ++l) {
        if (!dPPlane[l].Alloc(mn * sizeof(int8_t))) return false;
    }

    if (hipMemcpy(dAhat.ptr, Ahat.data(), nn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dU.ptr, U.data(), mn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess ||
        hipMemcpy(dV.ptr, V.data(), mn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess) {
        return false;
    }

    const dim3 mfmaBlock(16, 4, 1);
    auto ceilDiv = [](uint32_t a, uint32_t b) -> unsigned { return (a + b - 1) / b; };
    constexpr unsigned kElemThreads = 256;

    // P = U*Ahat -> M=m, K=n, N=n (P is m x n). Template-scoped: paid ONCE.
    {
        const dim3 grid(ceilDiv(n, 16), ceilDiv(m, 16), 1);
        hipLaunchKernelGGL(I8GemmTiled, grid, mfmaBlock, 0, 0,
                           static_cast<const int8_t*>(dU.ptr),
                           static_cast<const int8_t*>(dAhat.ptr),
                           static_cast<int32_t*>(dP.ptr),
                           static_cast<int>(m), static_cast<int>(n), static_cast<int>(n));
    }
    if (hipGetLastError() != hipSuccess) {
        return false;
    }

    // 4-limb base-64 remainder-top decomposition of P, also template-scoped:
    // P does not change across the header window.
    {
        const unsigned blocks = static_cast<unsigned>((mn + kElemThreads - 1) / kElemThreads);
        hipLaunchKernelGGL(DecomposeLimbPlanesBase64Kernel, dim3(blocks), dim3(kElemThreads), 0, 0,
                           static_cast<const int32_t*>(dP.ptr),
                           static_cast<int8_t*>(dPPlane[0].ptr), static_cast<int8_t*>(dPPlane[1].ptr),
                           static_cast<int8_t*>(dPPlane[2].ptr), static_cast<int8_t*>(dPPlane[3].ptr),
                           mn);
    }
    if (hipGetLastError() != hipSuccess || hipDeviceSynchronize() != hipSuccess) {
        return false;
    }

    // --- Device-memory-bounded chunking over the header window. Same shape
    // of formula as matmul_v4::hip::ComputeDigestsBatchedAccel (byte widths
    // are identical across profiles: int8 for Ahat/Bhat/U/V/planes, int32 for
    // P/Q/S, uint64/Fq for Chat -- only the limb BASE numeric value differs,
    // which does not change any buffer's byte size). Per-nonce variable
    // device bytes:
    //   Qstack column block: n int32           = 4n
    //   its 4 limb planes:   n int8 x 4         = 4n
    //   S (one limb-pair product, sized for the whole chunk): m int32       = 4m
    //   Chat column block:   m int64            = 8m
    // total per-nonce variable bytes = m*(8n + 12m).
    // Fixed (window-wide, already allocated above + the reused per-nonce
    // Bhat buffer below) bytes: dAhat+dBhat (2*n^2) plus
    // dU+dV+dP+dPPlane (m*n*(1+1+4+4) = 10*m*n). ---
    size_t free_bytes = 0, total_bytes = 0;
    if (hipMemGetInfo(&free_bytes, &total_bytes) != hipSuccess || free_bytes == 0) {
        free_bytes = size_t{512} << 20; // conservative 512 MiB if the query is unavailable
    }
    const size_t fixed_bytes = 2 * nn + 10 * mn;
    // 256 MiB headroom for the HIP runtime / other untracked allocations;
    // spend at most half of whatever is left on one chunk's variable buffers
    // so at least two chunks' worth of slack always remains.
    constexpr size_t kSafetyMargin = size_t{256} << 20;
    size_t budget = 0;
    if (free_bytes > fixed_bytes + kSafetyMargin) {
        budget = (free_bytes - fixed_bytes - kSafetyMargin) / 2;
    }
    const size_t per_nonce_bytes = static_cast<size_t>(m) * (8ull * n + 12ull * m);
    uint32_t chunk_q = (per_nonce_bytes == 0)
        ? count
        : static_cast<uint32_t>(std::max<size_t>(1, budget / per_nonce_bytes));
    // Final sanity clamp, mirroring the v4.1 sibling's fixed cap.
    chunk_q = std::min(chunk_q, kMaxBatchedWindowBMX4C);
    chunk_q = std::max<uint32_t>(1, std::min(chunk_q, count));

    // Fail-closed contract (matches the CPU per-header reference and the
    // v4.1 batched HIP backend): no partial windows. Results accumulate in
    // LOCAL vectors and only move into digests_out/payloads_out once the
    // ENTIRE window has succeeded; every early `return false` below therefore
    // leaves digests_out/payloads_out cleared, with no caller-visible partial
    // output.
    std::vector<uint256> local_digests(count);
    std::vector<std::vector<unsigned char>> local_payloads(count);

    // Per-nonce transient operand Bhat (n x n s8), reused for every nonce in
    // every chunk -- Bhat is nonce-fresh and never needed after its
    // Q_i = Bhat_i*V GEMM.
    DeviceBuffer dBhat;
    if (!dBhat.Alloc(nn * sizeof(int8_t))) {
        return false;
    }

    for (uint32_t chunk_start = 0; chunk_start < count; chunk_start += chunk_q) {
        const uint32_t this_chunk = std::min(chunk_q, count - chunk_start);
        const uint32_t q_cols = this_chunk * m;
        const size_t n_qcols = static_cast<size_t>(n) * q_cols;
        const size_t m_qcols = static_cast<size_t>(m) * q_cols;

        DeviceBuffer dQstack, dS, dChat;
        DeviceBuffer dQPlane[matmul::v4::bmx4::kCombineLimbs];
        if (!dQstack.Alloc(n_qcols * sizeof(int32_t)) ||
            !dS.Alloc(m_qcols * sizeof(int32_t)) ||
            !dChat.Alloc(m_qcols * sizeof(uint64_t))) {
            return false;
        }
        for (uint32_t l = 0; l < matmul::v4::bmx4::kCombineLimbs; ++l) {
            if (!dQPlane[l].Alloc(n_qcols * sizeof(int8_t))) return false;
        }

        // Per-nonce Q_i = Bhat_i*V (M=n, K=n, N=m), written directly into
        // column block `local_idx` of Qstack (ldD = q_cols,
        // colOffset = local_idx*m).
        for (uint32_t local_idx = 0; local_idx < this_chunk; ++local_idx) {
            const CBlockHeader& header = headers[chunk_start + local_idx];
            const uint256 seed_b = matmul::v4::bmx4::DeriveOperandSeedBMX4C(header, matmul::v4::Operand::B);
            const std::vector<int8_t> Bhat = matmul::v4::bmx4::ExpandOperandB(seed_b, n); // |.| <= 48
            if (hipMemcpy(dBhat.ptr, Bhat.data(), nn * sizeof(int8_t), hipMemcpyHostToDevice) != hipSuccess) {
                return false;
            }

            const dim3 grid(ceilDiv(m, 16), ceilDiv(n, 16), 1); // N=m cols, M=n rows
            hipLaunchKernelGGL(I8GemmTiledOffset, grid, mfmaBlock, 0, 0,
                               static_cast<const int8_t*>(dBhat.ptr),
                               static_cast<const int8_t*>(dV.ptr),
                               static_cast<int32_t*>(dQstack.ptr),
                               static_cast<int>(n), static_cast<int>(m), static_cast<int>(n),
                               static_cast<int>(q_cols), static_cast<int>(local_idx * m));
            if (hipGetLastError() != hipSuccess) {
                return false;
            }
        }

        // Decompose Qstack into its 4 base-64 remainder-top limb planes.
        {
            const unsigned blocks = static_cast<unsigned>((n_qcols + kElemThreads - 1) / kElemThreads);
            hipLaunchKernelGGL(DecomposeLimbPlanesBase64Kernel, dim3(blocks), dim3(kElemThreads), 0, 0,
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

        // ONE LARGE DENSE COMBINE: Chat_wide = P * Qstack (m x q_cols), via
        // the 16 limb-pair MFMA GEMMs S_ij = Pi*Qj (m x q_cols x n) each
        // immediately folded into Chat with weight 64^(i+j) = 2^(6(i+j)).
        for (uint32_t i = 0; i < matmul::v4::bmx4::kCombineLimbs; ++i) {
            for (uint32_t j = 0; j < matmul::v4::bmx4::kCombineLimbs; ++j) {
                const dim3 grid(ceilDiv(q_cols, 16), ceilDiv(m, 16), 1);
                hipLaunchKernelGGL(I8GemmTiled, grid, mfmaBlock, 0, 0,
                                   static_cast<const int8_t*>(dPPlane[i].ptr),
                                   static_cast<const int8_t*>(dQPlane[j].ptr),
                                   static_cast<int32_t*>(dS.ptr),
                                   static_cast<int>(m), static_cast<int>(q_cols), static_cast<int>(n));
                if (hipGetLastError() != hipSuccess) {
                    return false;
                }

                const uint64_t weight = static_cast<uint64_t>(1) << (6 * (i + j));
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
        // dQstack/dS/dChat/dQPlane go out of scope here and free before the
        // next chunk allocates -- peak device memory stays bounded by ONE
        // chunk's variable footprint plus the window-wide fixed buffers.
    }

    digests_out = std::move(local_digests);
    payloads_out = std::move(local_payloads);
    return true;
}

} // namespace matmul_v4::bmx4::hip

// ---------------------------------------------------------------------------
// Dispatcher-integration adapter (see the matching comment in
// matmul_v4_bmx4_accel.h): src/matmul/accel_v4.h / accel_v4_stub.cpp already
// declare and weakly stub the ENC-BMX4C HIP entry point as
// `matmul_v4::hip::ComputeDigestsBMX4CAccel`. This strong forwarding
// definition is what the real dispatch layer (ComputeDigestsBMX4CDispatched)
// actually resolves to once this translation unit is linked in; it is a pure
// pass-through to the implementation above, so there is exactly one code path
// and one place the algorithm/comments live.
namespace matmul_v4::hip {
bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                              std::vector<uint256>& digests_out,
                              std::vector<std::vector<unsigned char>>& payloads_out)
{
    return matmul_v4::bmx4::hip::ComputeDigestsBMX4CAccel(headers, n, rounds, digests_out, payloads_out);
}
} // namespace matmul_v4::hip
