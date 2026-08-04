// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_exact_float.h>

#include <matmul/int8_field.h>

#include <cstdint>
#include <cstdlib>
#include <vector>

namespace matmul::v4::exact_float {
namespace {

using int8_field::Fq;

// Balanced base-2^`digit_bits` digit extraction: d = ((x + h) mod 2^w) - h,
// h = 2^(w-1); then x <- (x - d) / 2^w exactly. Identical digit rule to the
// C-13 DecomposeLimbPlanes (matmul_v4.cpp, w=7) — pure integer, deterministic,
// unique for every input the digit count covers.
inline int32_t ExtractBalancedDigit(int32_t& x, uint32_t digit_bits)
{
    const int32_t base = static_cast<int32_t>(1) << digit_bits;
    const int32_t half = base >> 1;
    const int32_t d = ((x + half) & (base - 1)) - half;
    x = (x - d) / base; // exact: (x - d) is a multiple of 2^w
    return d;
}

// C-13 limb decomposition of an exact-int32 matrix into kCombineLimbs balanced
// base-2^7 digit planes (each a valid s8 operand in [-64,63]). Re-stated here
// because matmul_v4.cpp keeps its DecomposeLimbPlanes file-local; the digit
// rule is pinned normatively by Appendix C-13 and the byte-identity tests
// (ComputeCombineLimbTensorViaFloat == ComputeCombineLimbTensor) pin this
// restatement against the consensus reference.
void DecomposeC13LimbPlanes(const std::vector<int32_t>& M,
                            std::vector<int8_t> (&planes)[matmul::v4::kCombineLimbs])
{
    for (uint32_t l = 0; l < matmul::v4::kCombineLimbs; ++l) {
        planes[l].resize(M.size());
    }
    for (size_t idx = 0; idx < M.size(); ++idx) {
        int32_t x = M[idx];
        for (uint32_t l = 0; l < matmul::v4::kCombineLimbs; ++l) {
            planes[l][idx] = static_cast<int8_t>(ExtractBalancedDigit(x, 7));
        }
        // Total under CheckCombineLimbBound (|x| < 2^27); pinned by the tests.
    }
}

} // namespace

SliceScheme SchemeFor(FpFormat fmt)
{
    switch (fmt) {
    case FpFormat::FP8_E4M3:
        // p = 4 significand bits (3 stored + implicit), max finite 448 (OCP
        // OFP8 v1.0). w = 4, k = 2: one balanced digit in [-8, 7] plus the
        // remainder top slice in [-8, 8]; |slice| <= 8 = 2^3 has one
        // significand bit -> every slice value is exact in E4M3. Total for
        // all s8 inputs [-128, 127].
        return SliceScheme{/*significand_bits=*/4, /*max_finite=*/448,
                           /*slice_bits=*/4, /*slice_count=*/2};
    case FpFormat::FP4_E2M1:
        // p = 2 significand bits (1 stored + implicit), max finite 6 (OCP MX
        // v1.0). The exactly representable E2M1 values are
        // {0, ±0.5, ±1, ±1.5, ±2, ±3, ±4, ±6}. w = 3, k = 3: two balanced
        // digits in [-4, 3] plus the remainder top slice (in [-2, 2] for s8
        // inputs); every slice is in [-4, 4] ⊂ the exact set (5 — the first
        // integer E2M1 cannot hold — never occurs). Total for [-128, 127].
        return SliceScheme{/*significand_bits=*/2, /*max_finite=*/6,
                           /*slice_bits=*/3, /*slice_count=*/3};
    }
    // Unreachable for valid enum values.
    std::abort();
}

bool IsExactInFormat(int32_t v, FpFormat fmt)
{
    if (v == 0) return true;
    const SliceScheme s = SchemeFor(fmt);
    int64_t a = v < 0 ? -static_cast<int64_t>(v) : static_cast<int64_t>(v);
    if (a > s.max_finite) return false; // beyond the format's finite range
    while ((a & 1) == 0) a >>= 1;       // odd part = minimal significand
    return a < (static_cast<int64_t>(1) << s.significand_bits);
}

uint32_t MaxExactAccumBlock(FpFormat fmt, uint32_t accum_significand_bits)
{
    const SliceScheme s = SchemeFor(fmt);
    const uint32_t product_bits = 2 * (s.slice_bits - 1); // |d*e| <= 2^(2(w-1))
    if (accum_significand_bits < product_bits) return 0;  // cannot hold even one product exactly
    // K' * 2^(2(w-1)) <= 2^t  <=>  K' <= 2^(t - 2(w-1)): every in-block
    // partial sum is an integer <= 2^t, exactly representable with t
    // significand bits -> the FP accumulator never rounds (no-rounding-ever).
    const uint32_t shift = accum_significand_bits - product_bits;
    if (shift >= 31) return (static_cast<uint32_t>(1) << 31); // never binding at header dims
    return static_cast<uint32_t>(1) << shift;
}

std::vector<std::vector<int8_t>> DecomposeSlicePlanes(const int8_t* vals, size_t count, FpFormat fmt)
{
    const SliceScheme s = SchemeFor(fmt);
    std::vector<std::vector<int8_t>> planes(s.slice_count, std::vector<int8_t>(count));
    for (size_t idx = 0; idx < count; ++idx) {
        int32_t x = vals[idx];
        // k-1 balanced digits, then the TOP slice carries the exact remainder.
        // (Pure balanced digits would cover the ASYMMETRIC range
        // [-h*(b^k-1)/(b-1), (h-1)*(b^k-1)/(b-1)] — e.g. [-136, 119] for
        // FP8 w=4/k=2, which MISSES s8 inputs 120..127. The remainder-top
        // scheme is total for all of [-128, 127]: the top slice lands in
        // [-2^(w-1), +2^(w-1)] — 8/4, both endpoints exact format values —
        // so the slice-product bound 2^(2(w-1)) is unchanged.)
        for (uint32_t sl = 0; sl + 1 < s.slice_count; ++sl) {
            planes[sl][idx] = static_cast<int8_t>(ExtractBalancedDigit(x, s.slice_bits));
        }
        planes[s.slice_count - 1][idx] = static_cast<int8_t>(x);
        // |x| <= 2^(w-1) here for every s8 input (totality/exactness pinned
        // exhaustively by the unit tests over all 256 input bytes).
    }
    return planes;
}

std::vector<int32_t> ExactGemmViaFloatSlices(const std::vector<int8_t>& A, const std::vector<int8_t>& B,
                                             uint32_t rows, uint32_t inner, uint32_t cols, FpFormat fmt,
                                             uint32_t accum_significand_bits)
{
    const SliceScheme s = SchemeFor(fmt);
    const uint32_t kprime = MaxExactAccumBlock(fmt, accum_significand_bits);
    // K' == 0 means the claimed accumulator cannot hold even one slice-pair
    // product exactly: the format/width pair is unusable. Fail deterministically
    // to the caller-visible empty result (the accel dispatcher treats any
    // backend error as CPU fallback; the CPU reference never hits this).
    if (kprime == 0 || rows == 0 || inner == 0 || cols == 0) return {};

    const auto a_planes = DecomposeSlicePlanes(A.data(), A.size(), fmt);
    const auto b_planes = DecomposeSlicePlanes(B.data(), B.size(), fmt);

    const size_t out_size = static_cast<size_t>(rows) * cols;
    // Wide integer recombination accumulator (int ALU/VPU on device). int64
    // holds every partial recombination sum with headroom; the final value is
    // the exact integer GEMM entry, |.| <= inner * 127^2 < 2^31 (§B.4
    // analogue), cast back to int32 exactly.
    std::vector<int64_t> acc(out_size, 0);

    for (uint32_t si = 0; si < s.slice_count; ++si) {
        const std::vector<int8_t>& Ai = a_planes[si]; // rows x inner
        for (uint32_t tj = 0; tj < s.slice_count; ++tj) {
            const std::vector<int8_t>& Bj = b_planes[tj]; // inner x cols
            // Slice-pair GEMM S = Ai * Bj — on device ONE native FP8/FP4 MMA
            // GEMM per (si, tj). The blocked schedule below mirrors, in exact
            // integer arithmetic, precisely what the FP unit provably returns:
            //   * every product |d*e| <= 2^(2(w-1)) — exact in the MMA product
            //     datapath (at most 2p significant bits);
            //   * every in-block partial sum is an integer <= K'*2^(2(w-1))
            //     <= 2^t — exactly representable in the accumulator format, so
            //     ANY rounding mode / accumulation order / FMA fusion returns
            //     the same integer (no-rounding-ever theorem);
            //   * at each block boundary the exact block sum is extracted
            //     (exact FP->int conversion) and PROMOTED into the integer
            //     total — the DeepSeek-V3-style promotion (arXiv:2412.19437
            //     §3.3.2), here with K' derived so promotion happens BEFORE
            //     exactness can be lost rather than merely often enough to
            //     limit error.
            // On this CPU reference integer addition is associative, so the
            // blocking changes no byte — pinned by the schedule-independence
            // unit test (identical output across accumulator widths).
            const int64_t weight = static_cast<int64_t>(1)
                                   << (s.slice_bits * (si + tj)); // 2^(w(si+tj))
            for (uint32_t r = 0; r < rows; ++r) {
                const int8_t* a_row = &Ai[static_cast<size_t>(r) * inner];
                int64_t* acc_row = &acc[static_cast<size_t>(r) * cols];
                for (uint32_t c = 0; c < cols; ++c) {
                    int32_t total = 0; // promoted exact integer accumulator
                    for (uint32_t k0 = 0; k0 < inner; k0 += kprime) {
                        const uint32_t kend = (inner - k0 < kprime) ? inner : k0 + kprime;
                        int32_t block = 0; // image of the FP accumulator: |block| <= 2^t always
                        for (uint32_t kk = k0; kk < kend; ++kk) {
                            block += static_cast<int32_t>(a_row[kk]) *
                                     static_cast<int32_t>(Bj[static_cast<size_t>(kk) * cols + c]);
                        }
                        total += block; // extract + promote (exact, int ALU)
                    }
                    // Exact integer recombination shift (int ALU, never FP).
                    acc_row[c] += weight * static_cast<int64_t>(total);
                }
            }
        }
    }

    std::vector<int32_t> out(out_size);
    for (size_t i = 0; i < out_size; ++i) {
        out[i] = static_cast<int32_t>(acc[i]); // exact: |value| < 2^31 by the §B.4 analogue
    }
    return out;
}

std::vector<int32_t> ComputeExactProductViaFloat(const std::vector<int8_t>& A,
                                                 const std::vector<int8_t>& B, uint32_t n,
                                                 FpFormat fmt, uint32_t accum_significand_bits)
{
    // Same operands, same exact integers, same row-major int32 layout as
    // matmul::v4::ComputeExactProduct — only the evaluation engine differs.
    return ExactGemmViaFloatSlices(A, B, n, n, n, fmt, accum_significand_bits);
}

std::vector<int32_t> ComputeProjectedLeftViaFloat(const std::vector<int8_t>& U,
                                                  const std::vector<int8_t>& A, uint32_t n, uint32_t m,
                                                  FpFormat fmt, uint32_t accum_significand_bits)
{
    return ExactGemmViaFloatSlices(U, A, m, n, n, fmt, accum_significand_bits);
}

std::vector<int32_t> ComputeProjectedRightViaFloat(const std::vector<int8_t>& B,
                                                   const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                                   FpFormat fmt, uint32_t accum_significand_bits)
{
    return ExactGemmViaFloatSlices(B, V, n, n, m, fmt, accum_significand_bits);
}

std::vector<Fq> ComputeCombineLimbTensorViaFloat(const std::vector<int32_t>& P,
                                                 const std::vector<int32_t>& Q, uint32_t n, uint32_t m,
                                                 FpFormat fmt, uint32_t accum_significand_bits)
{
    // Appendix C-13 combine with the 16 limb-pair s8 GEMMs routed through the
    // FP slice engine. Every limb-pair product matrix S_ij is the identical
    // exact int32 the native s8xs8->s32 path produces (|S_ij| <= n*64^2 <
    // 2^31), and the shifted mod-q fold below is the identical
    // FqFromSigned/FqMul/FqAdd sequence as ComputeCombineLimbTensorStacked —
    // hence the result is byte-identical to ComputeCombineLimbTensor and
    // ComputeCombineModQ (canonical residues are unique).
    std::vector<int8_t> p_planes[matmul::v4::kCombineLimbs];
    std::vector<int8_t> q_planes[matmul::v4::kCombineLimbs];
    DecomposeC13LimbPlanes(P, p_planes);
    DecomposeC13LimbPlanes(Q, q_planes);

    // Canonical weights w_ij = 128^(i+j) mod q; exponents 7*(i+j) <= 42 < 61,
    // so each weight is the small power of two itself (as in matmul_v4.cpp).
    Fq weight[matmul::v4::kCombineLimbs][matmul::v4::kCombineLimbs];
    for (uint32_t i = 0; i < matmul::v4::kCombineLimbs; ++i) {
        for (uint32_t j = 0; j < matmul::v4::kCombineLimbs; ++j) {
            weight[i][j] = static_cast<Fq>(1) << (7 * (i + j));
        }
    }

    const size_t out_size = static_cast<size_t>(m) * m;
    std::vector<Fq> Chat(out_size, 0);
    for (uint32_t i = 0; i < matmul::v4::kCombineLimbs; ++i) {
        for (uint32_t j = 0; j < matmul::v4::kCombineLimbs; ++j) {
            // S = P_i * Q_j via the FP slice engine (on device: k^2 FP MMA
            // GEMMs recombined on the int ALU; here: the exact integers).
            const std::vector<int32_t> S = ExactGemmViaFloatSlices(
                p_planes[i], q_planes[j], m, n, m, fmt, accum_significand_bits);
            if (S.empty()) return {};
            const Fq w = weight[i][j];
            for (size_t idx = 0; idx < out_size; ++idx) {
                Chat[idx] = int8_field::FqAdd(
                    Chat[idx], int8_field::FqMul(w, int8_field::FqFromSigned(S[idx])));
            }
        }
    }
    return Chat;
}

std::vector<Fq> ComputeSketchViaFloat(const std::vector<int8_t>& U, const std::vector<int8_t>& A,
                                      const std::vector<int8_t>& B, const std::vector<int8_t>& V,
                                      uint32_t n, uint32_t m, FpFormat fmt,
                                      uint32_t accum_significand_bits)
{
    // Optimal-miner factoring Chat = (U*A)(B*V) (§E.3) with every GEMM on the
    // FP slice engine. P and Q are the identical exact int32 matrices as
    // ComputeProjectedLeft/Right, and the combine is byte-identical to the
    // C-13 limb-tensor combine, so the result equals ComputeSketchOptimal —
    // and, by integer-matrix associativity, ComputeSketch(U, A*B, V) — byte
    // for byte (identical integers -> identical unique canonical residues ->
    // identical SerializeSketch bytes -> identical digest).
    const std::vector<int32_t> P = ComputeProjectedLeftViaFloat(U, A, n, m, fmt, accum_significand_bits);
    const std::vector<int32_t> Q = ComputeProjectedRightViaFloat(B, V, n, m, fmt, accum_significand_bits);
    if (P.empty() || Q.empty()) return {};
    return ComputeCombineLimbTensorViaFloat(P, Q, n, m, fmt, accum_significand_bits);
}

} // namespace matmul::v4::exact_float
