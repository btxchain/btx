// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Exact-integer-on-float (Ozaki-scheme) miner-path tests
// (doc/btx-matmul-v4-exact-int-on-float.md; roadmap §3.3 Option C / O-1):
//
//   1. Slice decomposition: for BOTH formats (FP8 E4M3, FP4 E2M1) every slice
//      digit of every s8 value (k-1 balanced base-2^w digits + remainder top
//      slice) is exactly representable in the format, and the slices
//      recompose the value uniquely.
//   2. The blocked extract-and-promote accumulation bounds: K' derivation,
//      including the conservative 14-bit (DeepSeek-V3 / Hopper FP8) width and
//      full FP32 accumulate, and the fail-closed K' = 0 case.
//   3. BYTE-IDENTITY of the FP slice path to the integer consensus reference:
//      C = A*B vs ComputeExactProduct, P/Q vs ComputeProjectedLeft/Right, the
//      combine vs ComputeCombineLimbTensor/ComputeCombineModQ, and the full
//      committed sketch (payload bytes + digest) vs ComputeSketch /
//      ComputeSketchOptimal — across dimensions, XOF-derived and adversarial
//      operands, the HIGH-MAGNITUDE regime (accumulations crossing 2^24, the
//      roadmap §4.1 hazard boundary), and the block-boundary regime (partial
//      sums hitting exactly 2^t).
//   4. Schedule-independence: identical bytes for every legal accumulator
//      width / block length K' (exactness, not a pinned schedule, is what
//      delivers determinism).

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_exact_float.h>

#include <primitives/block.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

using matmul::v4::exact_float::FpFormat;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_exact_float_tests, BasicTestingSetup)

namespace {

constexpr uint32_t kTestDim = 256; // fast unit-suite dimension (b=4 -> m=64)
constexpr FpFormat kFormats[] = {FpFormat::FP8_E4M3, FpFormat::FP4_E2M1};

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

CBlockHeader MakeV4Header(uint64_t nonce, uint32_t n)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.hashPrevBlock = ParseUint256("6363636363636363636363636363636363636363636363636363636363636363");
    header.hashMerkleRoot = ParseUint256("b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5");
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    header.seed_b = ParseUint256("2222222222222222222222222222222222222222222222222222222222222222");
    return header;
}

// Plain integer GEMM oracle (rows x inner by inner x cols, row-major s8 ->
// exact int32), independent of both code paths under test.
std::vector<int32_t> NaiveGemm(const std::vector<int8_t>& A, const std::vector<int8_t>& B,
                               uint32_t rows, uint32_t inner, uint32_t cols)
{
    std::vector<int32_t> out(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t k = 0; k < inner; ++k) {
            const int32_t a = A[static_cast<size_t>(r) * inner + k];
            for (uint32_t c = 0; c < cols; ++c) {
                out[static_cast<size_t>(r) * cols + c] +=
                    a * static_cast<int32_t>(B[static_cast<size_t>(k) * cols + c]);
            }
        }
    }
    return out;
}

std::vector<int8_t> RandomBalancedS8(FastRandomContext& rng, size_t count)
{
    std::vector<int8_t> out(count);
    for (auto& v : out) {
        v = static_cast<int8_t>(static_cast<int32_t>(rng.randrange(251)) - 125); // balanced [-125,125]
    }
    return out;
}

} // namespace

// --- 1. Slice decomposition: exact digits, unique recomposition --------------

BOOST_AUTO_TEST_CASE(slice_digits_exact_and_recompose_for_all_s8_values)
{
    for (const FpFormat fmt : kFormats) {
        const auto scheme = matmul::v4::exact_float::SchemeFor(fmt);
        const int32_t half = static_cast<int32_t>(1) << (scheme.slice_bits - 1);

        // All 256 s8 values (superset of the balanced-s8 operand range
        // [-125,125] and of the C-13 limb-digit range [-64,63]).
        std::vector<int8_t> vals(256);
        for (int v = -128; v <= 127; ++v) vals[static_cast<size_t>(v + 128)] = static_cast<int8_t>(v);

        const auto planes = matmul::v4::exact_float::DecomposeSlicePlanes(vals.data(), vals.size(), fmt);
        BOOST_REQUIRE_EQUAL(planes.size(), scheme.slice_count);

        for (size_t idx = 0; idx < vals.size(); ++idx) {
            int64_t recomposed = 0;
            for (uint32_t s = 0; s < scheme.slice_count; ++s) {
                const int32_t d = planes[s][idx];
                // Balanced digit range [-2^(w-1), 2^(w-1)-1] for the low
                // slices; the remainder top slice may also hit +2^(w-1)...
                const bool top = (s + 1 == scheme.slice_count);
                BOOST_REQUIRE(d >= -half && (top ? d <= half : d < half));
                // ...and every digit is an exact value of the FP format: the
                // per-op no-rounding proof starts with exact operand encoding.
                BOOST_REQUIRE(matmul::v4::exact_float::IsExactInFormat(d, fmt));
                // The slice-pair PRODUCT bound 2^(2(w-1)) is also exact in the
                // format's accumulation datapath (checked via IsExactInFormat
                // against FP8 whose max_finite covers it; for FP4 the product
                // goes straight to the wider accumulator, bound 16 <= 2^t).
                recomposed += static_cast<int64_t>(d) << (scheme.slice_bits * s);
            }
            // Unique recomposition: sum_s d_s * 2^(w s) == value.
            BOOST_REQUIRE_EQUAL(recomposed, static_cast<int64_t>(vals[idx]));
        }
    }
}

BOOST_AUTO_TEST_CASE(format_exactness_predicate)
{
    using matmul::v4::exact_float::IsExactInFormat;
    // FP4 E2M1: representable integers are {0, ±1, ±2, ±3, ±4, ±6} (OCP MX).
    BOOST_CHECK(IsExactInFormat(0, FpFormat::FP4_E2M1));
    BOOST_CHECK(IsExactInFormat(3, FpFormat::FP4_E2M1));
    BOOST_CHECK(IsExactInFormat(-4, FpFormat::FP4_E2M1));
    BOOST_CHECK(IsExactInFormat(6, FpFormat::FP4_E2M1));
    BOOST_CHECK(!IsExactInFormat(5, FpFormat::FP4_E2M1));  // 5 = odd, needs 3 significand bits
    BOOST_CHECK(!IsExactInFormat(8, FpFormat::FP4_E2M1));  // beyond max finite 6
    // FP8 E4M3: max finite 448; odd part must fit 4 significand bits.
    BOOST_CHECK(IsExactInFormat(-8, FpFormat::FP8_E4M3));
    BOOST_CHECK(IsExactInFormat(7, FpFormat::FP8_E4M3));
    BOOST_CHECK(IsExactInFormat(16, FpFormat::FP8_E4M3));
    BOOST_CHECK(IsExactInFormat(448, FpFormat::FP8_E4M3)); // 7 * 2^6
    BOOST_CHECK(!IsExactInFormat(17, FpFormat::FP8_E4M3)); // odd, 5 significand bits
    BOOST_CHECK(!IsExactInFormat(449, FpFormat::FP8_E4M3));
    // Slice-pair product bounds are exact in FP8's range: 64 = 2^6 <= 448.
    BOOST_CHECK(IsExactInFormat(64, FpFormat::FP8_E4M3));
}

// --- 2. Blocked extract-and-promote accumulation bounds ----------------------

BOOST_AUTO_TEST_CASE(max_exact_accum_block_derivation)
{
    using matmul::v4::exact_float::MaxExactAccumBlock;
    using matmul::v4::exact_float::kConservativeAccumSignificandBits;
    using matmul::v4::exact_float::kFp32AccumSignificandBits;

    // FP8/w=4: products <= 2^6. Conservative t=14 (the Hopper FP8 effective
    // accumulator width per DeepSeek-V3, arXiv:2412.19437 §3.3.2) -> K' = 2^8;
    // proven-FP32 accumulate t=24 -> K' = 2^18.
    BOOST_CHECK_EQUAL(MaxExactAccumBlock(FpFormat::FP8_E4M3, kConservativeAccumSignificandBits), 256U);
    BOOST_CHECK_EQUAL(MaxExactAccumBlock(FpFormat::FP8_E4M3, kFp32AccumSignificandBits), 1U << 18);
    // FP4/w=3: products <= 2^4 -> K' = 2^10 at t=14, 2^20 at t=24.
    BOOST_CHECK_EQUAL(MaxExactAccumBlock(FpFormat::FP4_E2M1, kConservativeAccumSignificandBits), 1U << 10);
    BOOST_CHECK_EQUAL(MaxExactAccumBlock(FpFormat::FP4_E2M1, kFp32AccumSignificandBits), 1U << 20);
    // Fail closed: an accumulator too narrow to hold one product exactly.
    BOOST_CHECK_EQUAL(MaxExactAccumBlock(FpFormat::FP8_E4M3, 5), 0U);
    BOOST_CHECK_EQUAL(MaxExactAccumBlock(FpFormat::FP4_E2M1, 3), 0U);
    // And the GEMM entry point refuses to run on such a pair.
    const std::vector<int8_t> one(1, 1);
    BOOST_CHECK(matmul::v4::exact_float::ExactGemmViaFloatSlices(one, one, 1, 1, 1,
                                                                 FpFormat::FP8_E4M3, /*t=*/5)
                    .empty());
}

// --- 3. Byte-identity to the integer consensus reference ---------------------

BOOST_AUTO_TEST_CASE(gemm_via_slices_matches_integer_gemm_random)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t rows = 16, inner = 96, cols = 24;
    // Full s8 range (not just [-125,125]): the helper is also used on C-13
    // limb planes; exercise every representable input byte.
    std::vector<int8_t> A(static_cast<size_t>(rows) * inner);
    std::vector<int8_t> B(static_cast<size_t>(inner) * cols);
    for (auto& v : A) v = static_cast<int8_t>(rng.randrange(256));
    for (auto& v : B) v = static_cast<int8_t>(rng.randrange(256));

    const auto oracle = NaiveGemm(A, B, rows, inner, cols);
    for (const FpFormat fmt : kFormats) {
        // Schedule-independence: minimum legal width (K' = 1, promote every
        // element), the conservative 14-bit width, and full FP32 accumulate
        // must all yield the identical integers.
        const auto scheme = matmul::v4::exact_float::SchemeFor(fmt);
        const uint32_t widths[] = {2 * (scheme.slice_bits - 1), 14, 24};
        for (const uint32_t t : widths) {
            const auto got = matmul::v4::exact_float::ExactGemmViaFloatSlices(A, B, rows, inner, cols, fmt, t);
            BOOST_REQUIRE_EQUAL(got.size(), oracle.size());
            BOOST_CHECK(got == oracle);
        }
    }
}

BOOST_AUTO_TEST_CASE(gemm_via_slices_high_magnitude_and_block_boundary)
{
    // (a) HIGH-MAGNITUDE regime at the header-max inner dimension: all-(+/-125)
    // operands drive dot products to 65,535 * 15,625 = 1,024,046,875 — past
    // 2^24 (the FP32-mantissa hazard of roadmap §4.1) and close to the §B.4
    // int32 ceiling. The FP path's promoted integer totals must reproduce them
    // exactly; only the recombined int-ALU value crosses 2^24 (every FP-held
    // partial sum stays <= 2^t by construction).
    const uint32_t rows = 4, cols = 4;
    const uint32_t inner = matmul::int8_field::kMaxHeaderDim; // 65,535
    std::vector<int8_t> A(static_cast<size_t>(rows) * inner);
    std::vector<int8_t> B(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < A.size(); ++i) A[i] = (i % 3 == 0) ? int8_t{-125} : int8_t{125};
    for (size_t i = 0; i < B.size(); ++i) B[i] = (i % 5 == 0) ? int8_t{125} : int8_t{-125};

    const auto oracle = NaiveGemm(A, B, rows, inner, cols);
    // Sanity: the regime really is high-magnitude.
    int64_t peak = 0;
    for (const int32_t v : oracle) peak = std::max<int64_t>(peak, v < 0 ? -static_cast<int64_t>(v) : v);
    BOOST_REQUIRE_GT(peak, int64_t{1} << 24);

    for (const FpFormat fmt : kFormats) {
        const auto got = matmul::v4::exact_float::ExactGemmViaFloatSlices(A, B, rows, inner, cols, fmt);
        BOOST_CHECK(got == oracle);
    }

    // (b) BLOCK-BOUNDARY regime (FP8, t=14, K'=256): value -8 decomposes to
    // slice digits (-8, 0), so all-(-8) operands make every slice(0,0)-pair
    // product exactly 64 = 2^6 and the in-block partial sum hits exactly
    // 256 * 64 = 2^14 = 2^t at the block end — the largest value the FP
    // accumulator is ever asked to hold. Byte-identity must survive the
    // boundary, and be independent of whether blocks are 256 or 2^18 long.
    const uint32_t n2 = 2048; // multiple blocks of 256
    std::vector<int8_t> A2(static_cast<size_t>(rows) * n2, int8_t{-8});
    std::vector<int8_t> B2(static_cast<size_t>(n2) * cols, int8_t{-8});
    const auto oracle2 = NaiveGemm(A2, B2, rows, n2, cols);
    const auto got14 = matmul::v4::exact_float::ExactGemmViaFloatSlices(A2, B2, rows, n2, cols,
                                                                        FpFormat::FP8_E4M3, /*t=*/14);
    const auto got24 = matmul::v4::exact_float::ExactGemmViaFloatSlices(A2, B2, rows, n2, cols,
                                                                        FpFormat::FP8_E4M3, /*t=*/24);
    BOOST_CHECK(got14 == oracle2);
    BOOST_CHECK(got24 == oracle2);
}

BOOST_AUTO_TEST_CASE(exact_product_via_float_matches_reference)
{
    // XOF-derived operands (the real consensus derivation) at two dimensions.
    for (const uint32_t n : {64U, kTestDim}) {
        const CBlockHeader header = MakeV4Header(/*nonce=*/7, n);
        const auto A = matmul::v4::ExpandOperand(matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A), n);
        const auto B = matmul::v4::ExpandOperand(matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B), n);
        const auto C_ref = matmul::v4::ComputeExactProduct(A, B, n);
        for (const FpFormat fmt : kFormats) {
            const auto C_fp = matmul::v4::exact_float::ComputeExactProductViaFloat(A, B, n, fmt);
            BOOST_REQUIRE_EQUAL(C_fp.size(), C_ref.size());
            BOOST_CHECK(C_fp == C_ref); // byte-identical committed C
        }
    }

    // Adversarial sign-extreme operands: C entries at +/- n * 125^2.
    const uint32_t n = 128;
    std::vector<int8_t> A(static_cast<size_t>(n) * n);
    std::vector<int8_t> B(static_cast<size_t>(n) * n, int8_t{125});
    for (size_t i = 0; i < A.size(); ++i) A[i] = ((i / n) % 2 == 0) ? int8_t{125} : int8_t{-125};
    const auto C_ref = matmul::v4::ComputeExactProduct(A, B, n);
    for (const FpFormat fmt : kFormats) {
        BOOST_CHECK(matmul::v4::exact_float::ComputeExactProductViaFloat(A, B, n, fmt) == C_ref);
    }
}

BOOST_AUTO_TEST_CASE(combine_via_float_matches_limb_tensor_high_magnitude)
{
    // The 2^24-crossing combine regime the roadmap §4.1 flags: at inner
    // dimension n = 4096 the all-(-64) limb plane drives the S_00 limb-pair
    // entries to exactly 4096 * 64 * 64 = 2^24 — the boundary where an
    // FP32-mantissa-bounded integer path breaks. P/Q entries of -64 decompose
    // to C-13 limbs (-64, 0, 0, 0), so this pins that exact boundary.
    {
        const uint32_t n = 4096, m = 4;
        BOOST_REQUIRE(matmul::v4::CheckCombineLimbBound(n));
        const std::vector<int32_t> P(static_cast<size_t>(m) * n, -64);
        const std::vector<int32_t> Q(static_cast<size_t>(n) * m, -64);
        const auto ref = matmul::v4::ComputeCombineLimbTensor(P, Q, n, m);
        const auto direct = matmul::v4::ComputeCombineModQ(P, Q, n, m);
        BOOST_REQUIRE(ref == direct);
        for (const FpFormat fmt : kFormats) {
            BOOST_CHECK(matmul::v4::exact_float::ComputeCombineLimbTensorViaFloat(P, Q, n, m, fmt) == ref);
        }
    }

    // Random P/Q at the full legal magnitude |x| <= 15,625 * 8192 < 2^27 (the
    // largest-entry regime of the whole supported dimension window), inner
    // n = 4096 so limb-pair sums cross 2^24 with mixed signs.
    {
        FastRandomContext rng{/*fDeterministic=*/true};
        const uint32_t n = 4096, m = 4;
        const int64_t bound = static_cast<int64_t>(15625) * 8192;
        std::vector<int32_t> P(static_cast<size_t>(m) * n);
        std::vector<int32_t> Q(static_cast<size_t>(n) * m);
        for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
        for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
        const auto ref = matmul::v4::ComputeCombineLimbTensor(P, Q, n, m);
        for (const FpFormat fmt : kFormats) {
            BOOST_CHECK(matmul::v4::exact_float::ComputeCombineLimbTensorViaFloat(P, Q, n, m, fmt) == ref);
        }
    }
}

BOOST_AUTO_TEST_CASE(sketch_via_float_matches_consensus_reference)
{
    // The headline byte-identity: the COMMITTED OBJECT — sketch residues,
    // serialized payload bytes, and the digest H(sigma || Chat) — is identical
    // whether the miner used the integer path or the FP slice path, for the
    // real header-derived operands and projectors.
    const uint32_t n = kTestDim;
    uint32_t m = 0;
    BOOST_REQUIRE(matmul::v4::ValidateDims(n, matmul::v4::kTileB, m));

    const CBlockHeader header = MakeV4Header(/*nonce=*/99, n);
    const auto A = matmul::v4::ExpandOperand(matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A), n);
    const auto B = matmul::v4::ExpandOperand(matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B), n);
    const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);
    const auto U = matmul::v4::ExpandProjector(seed_u, m, n);
    const auto V = matmul::v4::ExpandProjector(seed_v, n, m);

    // Consensus definition (full C) and the integer optimal-miner path.
    const auto C = matmul::v4::ComputeExactProduct(A, B, n);
    const auto sketch_full = matmul::v4::ComputeSketch(U, C, V, n, m);
    const auto sketch_opt = matmul::v4::ComputeSketchOptimal(U, A, B, V, n, m);
    BOOST_REQUIRE(sketch_full == sketch_opt);

    const auto payload_ref = matmul::v4::SerializeSketch(sketch_full);
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint256 digest_ref = matmul::v4::ComputeSketchDigest(sigma, payload_ref);

    for (const FpFormat fmt : kFormats) {
        // P and Q byte-identical first (isolates any failure)...
        const auto P_ref = matmul::v4::ComputeProjectedLeft(U, A, n, m);
        const auto Q_ref = matmul::v4::ComputeProjectedRight(B, V, n, m);
        BOOST_CHECK(matmul::v4::exact_float::ComputeProjectedLeftViaFloat(U, A, n, m, fmt) == P_ref);
        BOOST_CHECK(matmul::v4::exact_float::ComputeProjectedRightViaFloat(B, V, n, m, fmt) == Q_ref);

        // ...then the committed sketch, payload bytes, and digest.
        const auto sketch_fp = matmul::v4::exact_float::ComputeSketchViaFloat(U, A, B, V, n, m, fmt);
        BOOST_REQUIRE_EQUAL(sketch_fp.size(), sketch_full.size());
        BOOST_CHECK(sketch_fp == sketch_full);
        const auto payload_fp = matmul::v4::SerializeSketch(sketch_fp);
        BOOST_CHECK(payload_fp == payload_ref);
        BOOST_CHECK(matmul::v4::ComputeSketchDigest(sigma, payload_fp) == digest_ref);
    }

    // Schedule-independence on the full pipeline (FP8): the conservative
    // 14-bit and full 24-bit accumulator widths produce identical bytes.
    const auto sketch_t14 = matmul::v4::exact_float::ComputeSketchViaFloat(
        U, A, B, V, n, m, FpFormat::FP8_E4M3, /*accum_significand_bits=*/14);
    const auto sketch_t24 = matmul::v4::exact_float::ComputeSketchViaFloat(
        U, A, B, V, n, m, FpFormat::FP8_E4M3, /*accum_significand_bits=*/24);
    BOOST_CHECK(sketch_t14 == sketch_full);
    BOOST_CHECK(sketch_t24 == sketch_full);
}

BOOST_AUTO_TEST_SUITE_END()
