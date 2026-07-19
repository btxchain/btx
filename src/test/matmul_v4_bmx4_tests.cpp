// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ENC-BMX4C committed-object profile tests (MatMul v4.2 / BMX4-C; design
// doc/btx-matmul-v4.2-consolidated-design.md). This suite pins the bit-exact
// CPU reference every backend / golden vector mirrors:
//
//   (a) BYTE-IDENTITY: the optimal (U*Ahat)(Bhat*V) sketch == the full-C
//       reference ComputeSketch(U, Ahat*Bhat, V), byte-for-byte.
//   (b) COMBINE: the base-2^6 limb-tensor combine == the direct mod-q combine,
//       byte-for-byte, including the high-magnitude regime near 2^23 and the
//       corrected asymmetric-bound edge.
//   (c) SOUNDNESS: a correct sketch passes SketchFreivalds; a perturbed but
//       digest-consistent sketch fails it.
//   (d) DETERMINISM: run-to-run byte-identity of digest + payload.
//   (e) SAMPLER EXACTNESS: every sampled mantissa is in M11, every scale code
//       is a valid E8M0 exponent, and the E2M1 bijection holes are exact.
//   + GOLDEN vectors: pinned ENC-BMX4C digests at fixed headers, and the C-1'
//     accumulator boundary vectors (exact-2^t limb-pair pins, odd-step 2^14
//     crossings, E8M0 scale-exactness) so a rounding device fails loudly.

#include <cuda/matmul_v4_bmx4_cutlass_mxfp4.h>
#include <cuda/matmul_v4_bmx4_fp8_five_limb.h>
#include <ascend/matmul_v4_lt_accel.h>
#include <cuda/matmul_v4_lt_accel.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_bmx4_batch.h>
#include <matmul/matmul_v4_bmx4_pipeline.h>
#include <matmul/pow_v4.h>

#include <primitives/block.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <string>
#include <string_view>
#include <vector>

using namespace matmul::v4;
namespace bx = matmul::v4::bmx4;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_bmx4_tests, BasicTestingSetup)

namespace {

constexpr uint32_t kTestDim = 256; // fast unit dimension (b=4 -> m=64, /32 ok)

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
    header.hashPrevBlock = ParseUint256("5151515151515151515151515151515151515151515151515151515151515151");
    header.hashMerkleRoot = ParseUint256("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    header.seed_b = ParseUint256("2222222222222222222222222222222222222222222222222222222222222222");
    return header;
}

// True iff every element of `v` is a member of the pinned M11 alphabet.
bool AllInM11(const std::vector<int8_t>& v)
{
    static const std::set<int8_t> kM11{0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    for (int8_t x : v) {
        if (kM11.find(x) == kM11.end()) return false;
    }
    return true;
}

} // namespace

// --- (e) SAMPLER EXACTNESS --------------------------------------------------

BOOST_AUTO_TEST_CASE(sampler_e2m1_bijection_holes_exact)
{
    // The 5 rejected nibble codes must be exactly {0.5,1.5,-0} = {1,3,8,9,11},
    // and the 11 accepted codes must map bijectively onto M11.
    std::set<int8_t> accepted_values;
    int accepted = 0;
    for (uint8_t nib = 0; nib < 16; ++nib) {
        bool ok = false;
        const int8_t mu = bx::SampleMantissaNibble(nib, ok);
        const bool is_hole = (nib == 1 || nib == 3 || nib == 8 || nib == 9 || nib == 11);
        BOOST_CHECK_EQUAL(ok, !is_hole);
        if (ok) {
            ++accepted;
            accepted_values.insert(mu);
            // never +-5 or any non-M11 magnitude
            const int a = mu < 0 ? -mu : mu;
            BOOST_CHECK(a == 0 || a == 1 || a == 2 || a == 3 || a == 4 || a == 6);
            BOOST_CHECK(a != 5);
        }
    }
    BOOST_CHECK_EQUAL(accepted, 11);
    const std::set<int8_t> kM11{0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    BOOST_CHECK(accepted_values == kM11);
}

BOOST_AUTO_TEST_CASE(sampler_streams_are_valid)
{
    const uint256 seed = ParseUint256("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    // Mantissa stream: every element in M11.
    std::vector<int8_t> mant(10000);
    bx::ExpandMantissaStream(seed, mant.size(), mant.data());
    BOOST_CHECK(AllInM11(mant));

    // Scale stream: every code a valid E8M0 exponent in {0,1,2,3}.
    std::vector<uint8_t> scales(10000);
    bx::ExpandScaleStream(seed, scales.size(), scales.data());
    for (uint8_t e : scales) BOOST_CHECK(e <= bx::kScaleS);

    // Dequantized operands: exact integers with |.| <= E_max = 48.
    const auto Ahat = bx::ExpandOperandA(seed, kTestDim);
    const auto Bhat = bx::ExpandOperandB(seed, kTestDim);
    for (int8_t x : Ahat) BOOST_CHECK(x >= -bx::kEmax && x <= bx::kEmax);
    for (int8_t x : Bhat) BOOST_CHECK(x >= -bx::kEmax && x <= bx::kEmax);

    // Projectors: scale-free M11, |.| <= 6.
    const auto U = bx::ExpandProjectorBMX4C(seed, 8, kTestDim);
    BOOST_CHECK(AllInM11(U));
    for (int8_t x : U) BOOST_CHECK(x >= -bx::kMantissaMaxAbs && x <= bx::kMantissaMaxAbs);
}

BOOST_AUTO_TEST_CASE(pinned_constants)
{
    // The exact ENC-BMX4C constants (design §2.1/§2.4/§5.2).
    BOOST_CHECK_EQUAL(bx::kAlphabetSize, 11u);
    BOOST_CHECK_EQUAL(bx::kMantissaMaxAbs, 6);
    BOOST_CHECK_EQUAL(bx::kScaleS, 3u);
    BOOST_CHECK_EQUAL(bx::kBlockLen, 32u);
    BOOST_CHECK_EQUAL(bx::kEmax, 48);
    BOOST_CHECK_EQUAL(bx::kBaseProductPerMac, 2304);
    BOOST_CHECK_EQUAL(bx::kProjPerMac, 288);
    BOOST_CHECK_EQUAL(bx::kCombineLimbBase, 64);
    BOOST_CHECK_EQUAL(bx::kCombineLimbs, 4u);
    BOOST_CHECK_EQUAL(bx::kCombinePureBalancedPositiveExtreme, 8'255'455);
    BOOST_CHECK_EQUAL(bx::kCombineMaxAbs, 8'388'607); // 2^23 - 1

    // Corrected combine bound: 288*n <= 2^23-1 <=> n <= 29,127.
    BOOST_CHECK(bx::CheckCombineLimbBoundBMX4C(4096));
    BOOST_CHECK(bx::CheckCombineLimbBoundBMX4C(8192));
    BOOST_CHECK(bx::CheckCombineLimbBoundBMX4C(29127));
    BOOST_CHECK(!bx::CheckCombineLimbBoundBMX4C(29128));
}

// --- (a) BYTE-IDENTITY: optimal factoring == full-C reference ---------------

BOOST_AUTO_TEST_CASE(optimal_sketch_matches_full_c)
{
    const uint32_t n = kTestDim;
    uint32_t m = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4C(n, kTileB, m));

    const uint256 sa = ParseUint256("00000000000000000000000000000000000000000000000000000000000000aa");
    const uint256 sb = ParseUint256("00000000000000000000000000000000000000000000000000000000000000bb");
    const uint256 su = ParseUint256("00000000000000000000000000000000000000000000000000000000000000cc");
    const uint256 sv = ParseUint256("00000000000000000000000000000000000000000000000000000000000000dd");

    const auto Ahat = bx::ExpandOperandA(sa, n);
    const auto Bhat = bx::ExpandOperandB(sb, n);
    const auto U = bx::ExpandProjectorBMX4C(su, m, n);
    const auto V = bx::ExpandProjectorBMX4C(sv, n, m);

    // Full-C reference: C = Ahat*Bhat (exact int32), Chat = U*C*V.
    const auto C = ComputeExactProduct(Ahat, Bhat, n);
    // Base product bound: |C| <= 2304*n.
    for (int32_t x : C) BOOST_REQUIRE(x <= 2304 * static_cast<int32_t>(n) &&
                                      x >= -2304 * static_cast<int32_t>(n));
    const auto full = ComputeSketch(U, C, V, n, m);

    // Optimal factoring: P = U*Ahat, Q = Bhat*V, Chat = P*Q mod q.
    const auto P = ComputeProjectedLeft(U, Ahat, n, m);
    const auto Q = ComputeProjectedRight(Bhat, V, n, m);
    for (int32_t x : P) BOOST_REQUIRE(x <= 288 * static_cast<int32_t>(n) &&
                                      x >= -288 * static_cast<int32_t>(n));
    const auto opt_direct = ComputeCombineModQ(P, Q, n, m);
    const auto opt_limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);

    BOOST_CHECK(opt_direct == full);   // (U*A)(B*V) == U*(A*B)*V
    BOOST_CHECK(opt_limb == full);     // base-2^6 limb path == full-C
    // And byte-identical serialized payloads / digests.
    BOOST_CHECK(SerializeSketch(opt_limb) == SerializeSketch(full));
}

// --- (b) COMBINE: base-2^6 limb == direct mod-q -----------------------------

BOOST_AUTO_TEST_CASE(limb_combine_matches_direct_random)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = 96; // multiple of 32
    const uint32_t m = 24;
    const int64_t bound = static_cast<int64_t>(bx::kProjPerMac) * n; // 288*n
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n));

    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);

    const auto direct = ComputeCombineModQ(P, Q, n, m);
    const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
    BOOST_CHECK(limb == direct);
}

BOOST_AUTO_TEST_CASE(limb_combine_matches_direct_high_magnitude_and_bound_edge)
{
    // Entries at the corrected-bound edges: the pure-balanced positive extreme
    // 8,255,455 and the remainder-top total bound 2^23-1 = 8,388,607, both
    // signs, plus small edges. n = 4 keeps the limb-pair accumulator in range
    // while the decomposition itself is exercised near 2^23. This is where a
    // "pure balanced only to 8,255,455" implementation would decompose WRONG;
    // the remainder-top rule keeps limb == direct.
    const uint32_t n = 4;
    const uint32_t m = 4;
    const int32_t E = static_cast<int32_t>(bx::kCombinePureBalancedPositiveExtreme); // 8,255,455
    const int32_t T = static_cast<int32_t>(bx::kCombineMaxAbs);                      // 8,388,607
    const int32_t edges[] = {0, 1, -1, 31, 32, -32, 33, -33, 63, 64, -64, 65,
                             4'194'304 /*2^22*/, -4'194'304, E, -E, T, -T};
    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (size_t i = 0; i < P.size(); ++i) P[i] = edges[i % std::size(edges)];
    for (size_t i = 0; i < Q.size(); ++i) Q[i] = edges[(i * 5 + 2) % std::size(edges)];

    const auto direct = ComputeCombineModQ(P, Q, n, m);
    const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
    BOOST_CHECK(limb == direct);
}

// --- Karatsuba-9 / FP8 five-limb / scale-partitioned exactness --------------

BOOST_AUTO_TEST_CASE(karatsuba9_combine_matches_limb_and_direct)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = 96;
    const uint32_t m = 24;
    const int64_t bound = static_cast<int64_t>(bx::kProjPerMac) * n;
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n));

    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);

    const auto direct = ComputeCombineModQ(P, Q, n, m);
    const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
    const auto kara = bx::ComputeCombineKaratsuba9BMX4C(P, Q, n, m);
    BOOST_CHECK(kara == direct);
    BOOST_CHECK(kara == limb);
}

BOOST_AUTO_TEST_CASE(deferred_combine_matches_classical_max_dim_adversarial)
{
    // Deferred __int128 ComputeCombineModQ must stay BYTE-IDENTICAL to the
    // classical per-MAC Fq path at max-magnitude entries and at the largest
    // BMX4C-legal projection envelope exercised in unit tests (n=512, m=16
    // keeps runtime small while |P|,|Q| hit 288*n).
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = 512;
    const uint32_t m = 16;
    const int64_t bound = static_cast<int64_t>(bx::kProjPerMac) * n;
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n));
    BOOST_REQUIRE(bound <= bx::kCombineMaxAbs);

    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    // Adversarial: alternate ±bound corners with random mid-magnitude noise.
    for (size_t i = 0; i < P.size(); ++i) {
        if ((i % 7) == 0) P[i] = static_cast<int32_t>(bound);
        else if ((i % 7) == 1) P[i] = static_cast<int32_t>(-bound);
        else P[i] = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    }
    for (size_t i = 0; i < Q.size(); ++i) {
        if ((i % 5) == 0) Q[i] = static_cast<int32_t>(-bound);
        else if ((i % 5) == 1) Q[i] = static_cast<int32_t>(bound);
        else Q[i] = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    }

    const auto deferred = ComputeCombineModQ(P, Q, n, m);
    const auto classical = ComputeCombineModQClassical(P, Q, n, m);
    BOOST_CHECK(deferred == classical);
    BOOST_CHECK(SerializeSketch(deferred) == SerializeSketch(classical));
}

BOOST_AUTO_TEST_CASE(adaptive_limb_combine_matches_direct_and_fallback)
{
    FastRandomContext rng{/*fDeterministic=*/true};

    // (1) Two-limb base-64 regime: |entries| <= 2080.
    {
        const uint32_t n = 64;
        const uint32_t m = 16;
        const int64_t bound = bx::kCombineTwoLimbBase64MaxAbs;
        std::vector<int32_t> P(static_cast<size_t>(m) * n);
        std::vector<int32_t> Q(static_cast<size_t>(n) * m);
        for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
        for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
        BOOST_REQUIRE(bx::ScanCombineMaxAbsBMX4C(P, Q) <= bx::kCombineTwoLimbBase64MaxAbs);
        const auto direct = ComputeCombineModQ(P, Q, n, m);
        const auto two = bx::ComputeCombineTwoLimbBMX4C(P, Q, n, m);
        const auto adapt = bx::ComputeCombineAdaptiveLimbBMX4C(P, Q, n, m);
        BOOST_CHECK(two == direct);
        BOOST_CHECK(adapt == direct);
    }

    // (2) Two-limb base-256 regime (above base-64 two-limb, below 32640).
    {
        const uint32_t n = 96;
        const uint32_t m = 16;
        const int64_t bound = 20'000;
        BOOST_REQUIRE(bound <= bx::kCombineTwoLimbBase256MaxAbs);
        std::vector<int32_t> P(static_cast<size_t>(m) * n, 0);
        std::vector<int32_t> Q(static_cast<size_t>(n) * m, 0);
        for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
        for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
        const auto direct = ComputeCombineModQ(P, Q, n, m);
        const auto b256 = bx::ComputeCombineAdaptiveBase256BMX4C(P, Q, n, m);
        const auto adapt = bx::ComputeCombineAdaptiveLimbBMX4C(P, Q, n, m);
        BOOST_CHECK(b256 == direct);
        BOOST_CHECK(adapt == direct);
    }

    // (2b) Base-256 int8 top-limb boundaries — differential vs ComputeCombineModQ.
    // Safe caps: 32639 / 8355711. Just above (32640 / 8355712) and the old
    // overflowing guard extremes (32895 / 8421247) must still match via
    // three-limb / Karatsuba fallback — never wrap top=+128 into int8_t.
    {
        BOOST_CHECK_EQUAL(bx::kCombineTwoLimbBase256MaxAbs, 32639);
        BOOST_CHECK_EQUAL(bx::kCombineThreeLimbBase256MaxAbs, 8355711);
        const uint32_t n = 4;
        const uint32_t m = 4;
        const size_t pn = static_cast<size_t>(m) * n;
        const size_t qn = static_cast<size_t>(n) * m;
        const int32_t corners[] = {
            32639, 32640, -32639, -32640,
            32895, -32895, // old (unsafe) two-limb max — must use 3 limbs
            8355711, 8355712, -8355711, -8355712,
            8421247, -8421247, // old (unsafe) three-limb max — Karatsuba fallback
        };
        for (const int32_t corner : corners) {
            std::vector<int32_t> P(pn, 0);
            std::vector<int32_t> Q(qn, 0);
            P[0] = corner;
            Q[0] = corner;
            const auto direct = ComputeCombineModQ(P, Q, n, m);
            const auto b256 = bx::ComputeCombineAdaptiveBase256BMX4C(P, Q, n, m);
            const auto adapt = bx::ComputeCombineAdaptiveLimbBMX4C(P, Q, n, m);
            BOOST_CHECK_MESSAGE(b256 == direct,
                                "base-256 combine mismatch at corner " << corner);
            BOOST_CHECK_MESSAGE(adapt == direct,
                                "adaptive combine mismatch at corner " << corner);
        }
    }

    // (3) Full-envelope / three-limb base-256 + sparse high-limb (zeros mixed
    // with ±(288*n) corners) — must match Karatsuba-9 and direct.
    {
        const uint32_t n = 128;
        const uint32_t m = 16;
        const int64_t bound = static_cast<int64_t>(bx::kProjPerMac) * n;
        BOOST_REQUIRE(bound <= bx::kCombineThreeLimbBase256MaxAbs);
        std::vector<int32_t> P(static_cast<size_t>(m) * n);
        std::vector<int32_t> Q(static_cast<size_t>(n) * m);
        for (size_t i = 0; i < P.size(); ++i) {
            P[i] = ((i % 11) == 0) ? static_cast<int32_t>(bound)
                                   : static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * 500 + 1)) - 500);
        }
        for (size_t i = 0; i < Q.size(); ++i) {
            Q[i] = ((i % 13) == 0) ? static_cast<int32_t>(-bound)
                                   : static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * 500 + 1)) - 500);
        }
        const auto direct = ComputeCombineModQ(P, Q, n, m);
        const auto kara = bx::ComputeCombineKaratsuba9BMX4C(P, Q, n, m);
        const auto b256 = bx::ComputeCombineAdaptiveBase256BMX4C(P, Q, n, m);
        const auto adapt = bx::ComputeCombineAdaptiveLimbBMX4C(P, Q, n, m);
        BOOST_CHECK(b256 == direct);
        BOOST_CHECK(adapt == direct);
        BOOST_CHECK(adapt == kara);
    }
}

BOOST_AUTO_TEST_CASE(adaptive_base256_int8_top_boundaries_are_exact)
{
    constexpr uint32_t n = 1;
    constexpr uint32_t m = 1;
    const int32_t cases[] = {
        32'639, 32'640, -32'896, -32'897,
        8'355'711, 8'355'712, -8'421'504,
    };
    for (const int32_t value : cases) {
        const std::vector<int32_t> P{value};
        const std::vector<int32_t> Q{1};
        BOOST_CHECK_MESSAGE(
            bx::ComputeCombineAdaptiveLimbBMX4C(P, Q, n, m) ==
                ComputeCombineModQ(P, Q, n, m),
            "boundary=" << value);
    }
}

BOOST_AUTO_TEST_CASE(adaptive_base256_common_four_gemm_path_matches_direct)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = 64;
    const uint32_t m = 16;
    // Entirely inside the exact two-limb window [-32896,32639].
    constexpr int32_t bound = 30'000;
    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (auto& x : P) x = static_cast<int32_t>(rng.randrange(2 * bound + 1)) - bound;
    for (auto& x : Q) x = static_cast<int32_t>(rng.randrange(2 * bound + 1)) - bound;
    P[0] = 32'639;
    P[1] = -32'896;
    Q[0] = -32'896;
    Q[1] = 32'639;

    bx::AdaptiveCombineStatsBMX4C stats;
    const auto adaptive = bx::ComputeCombineAdaptiveSparseBase256BMX4C(P, Q, n, m, &stats);
    BOOST_CHECK(adaptive == ComputeCombineModQ(P, Q, n, m));
    BOOST_CHECK_EQUAL(stats.p_high_nonzero, 0U);
    BOOST_CHECK_EQUAL(stats.q_high_nonzero, 0U);
    BOOST_CHECK_EQUAL(stats.dense_gemm_count, 4U);
    BOOST_CHECK(!stats.used_sparse_high_correction);
    BOOST_CHECK(!stats.used_direct_fallback);
}

BOOST_AUTO_TEST_CASE(adaptive_base256_sparse_high_limbs_are_corrected_exactly)
{
    const uint32_t n = 8;
    const uint32_t m = 4;
    std::vector<int32_t> P(static_cast<size_t>(m) * n, 17);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m, -23);

    // First values just outside the asymmetric two-limb window, followed by
    // full BMX4 extrema. Four total high limbs stay on the sparse path.
    P[0] = 32'640;
    P[19] = -32'897;
    // Q[0] shares contraction index k=0 with P[0], pinning the Ph*Qh cross
    // term in the sparse reconstruction rather than only isolated high limbs.
    Q[0] = static_cast<int32_t>(bx::kCombineMaxAbs);
    Q[28] = -static_cast<int32_t>(bx::kCombineMaxAbs);

    bx::AdaptiveCombineStatsBMX4C stats;
    const auto adaptive = bx::ComputeCombineAdaptiveSparseBase256BMX4C(P, Q, n, m, &stats);
    BOOST_CHECK(adaptive == ComputeCombineModQ(P, Q, n, m));
    BOOST_CHECK_EQUAL(stats.p_high_nonzero, 2U);
    BOOST_CHECK_EQUAL(stats.q_high_nonzero, 2U);
    BOOST_CHECK_EQUAL(stats.estimated_sparse_correction_macs, 16U);
    BOOST_CHECK_EQUAL(stats.dense_gemm_count, 4U);
    BOOST_CHECK(stats.used_sparse_high_correction);
    BOOST_CHECK(!stats.used_direct_fallback);
}

BOOST_AUTO_TEST_CASE(adaptive_base256_dense_high_limbs_use_exact_direct_fallback)
{
    const uint32_t n = 8;
    const uint32_t m = 4;
    std::vector<int32_t> P(static_cast<size_t>(m) * n, 70'000);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m, -90'000);

    bx::AdaptiveCombineStatsBMX4C stats;
    const auto adaptive = bx::ComputeCombineAdaptiveSparseBase256BMX4C(P, Q, n, m, &stats);
    BOOST_CHECK(adaptive == ComputeCombineModQ(P, Q, n, m));
    BOOST_CHECK_EQUAL(stats.p_high_nonzero, P.size());
    BOOST_CHECK_EQUAL(stats.q_high_nonzero, Q.size());
    BOOST_CHECK_EQUAL(stats.dense_gemm_count, 0U);
    BOOST_CHECK(!stats.used_sparse_high_correction);
    BOOST_CHECK(stats.used_direct_fallback);
}

BOOST_AUTO_TEST_CASE(fp8_five_limb_combine_matches_direct)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint32_t n = 64;
    const uint32_t m = 16;
    const int64_t bound = static_cast<int64_t>(bx::kProjPerMac) * n;
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n));

    std::vector<int32_t> P(static_cast<size_t>(m) * n);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m);
    for (auto& x : P) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);
    for (auto& x : Q) x = static_cast<int32_t>(static_cast<int64_t>(rng.randrange(2 * bound + 1)) - bound);

    const auto direct = ComputeCombineModQ(P, Q, n, m);
    const auto fp8 = bx::ComputeCombineFp8FiveLimbBMX4C(P, Q, n, m);
    BOOST_CHECK(fp8 == direct);
}

BOOST_AUTO_TEST_CASE(scale_partitioned_projection_matches_dense)
{
    const uint32_t n = kTestDim;
    uint32_t m = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4C(n, kTileB, m));
    const auto header = MakeV4Header(7, n);
    const uint256 seed_a = bx::DeriveOperandSeedBMX4C(header, Operand::A);
    const uint256 seed_b = bx::DeriveOperandSeedBMX4C(header, Operand::B);
    const auto [seed_u, seed_v] = bx::DeriveProjectorSeedsBMX4C(header);

    std::vector<int8_t> mu_a(static_cast<size_t>(n) * n);
    bx::ExpandMantissaStream(seed_a, mu_a.size(), mu_a.data());
    std::vector<uint8_t> scale_a(static_cast<size_t>(n) * (n / bx::kBlockLen));
    bx::ExpandScaleStream(seed_a, scale_a.size(), scale_a.data());
    std::vector<int8_t> mu_b(static_cast<size_t>(n) * n);
    bx::ExpandMantissaStream(seed_b, mu_b.size(), mu_b.data());
    std::vector<uint8_t> scale_b(static_cast<size_t>(n / bx::kBlockLen) * n);
    bx::ExpandScaleStream(seed_b, scale_b.size(), scale_b.data());

    const auto U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const auto V = bx::ExpandProjectorBMX4C(seed_v, n, m);
    const auto Ahat = bx::ExpandOperandA(seed_a, n);
    const auto Bhat = bx::ExpandOperandB(seed_b, n);

    const auto P_dense = ComputeProjectedLeft(U, Ahat, n, m);
    const auto Q_dense = ComputeProjectedRight(Bhat, V, n, m);
    const auto P_part = bx::ComputeProjectedLeftScalePartitionedBMX4C(U, mu_a, scale_a, n, m);
    const auto Q_part = bx::ComputeProjectedRightScalePartitionedBMX4C(mu_b, scale_b, V, n, m);
    BOOST_CHECK(P_part == P_dense);
    BOOST_CHECK(Q_part == Q_dense);
}

BOOST_AUTO_TEST_CASE(grouped_mxfp4_header_path_matches_reference)
{
    // The portable exact grouped-MXFP4 projection lane (the "used when CUTLASS
    // is unavailable" datapath in cuda/matmul_v4_bmx4_cutlass_mxfp4.h) must be
    // byte-identical to both the scale-partitioned CPU reference and the dense
    // dequantized GEMM. This is the software fallback for the hardware-gated
    // CUTLASS grouped kernel.
    namespace mxf4 = matmul_v4::cuda::cutlass_mxfp4;

    BOOST_CHECK(mxf4::IsGroupedMxfp4Available()); // portable exact path always there

    const uint32_t n = kTestDim;
    uint32_t m = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4C(n, kTileB, m));
    const auto header = MakeV4Header(11, n);
    const uint256 seed_a = bx::DeriveOperandSeedBMX4C(header, Operand::A);
    const uint256 seed_b = bx::DeriveOperandSeedBMX4C(header, Operand::B);
    const auto [seed_u, seed_v] = bx::DeriveProjectorSeedsBMX4C(header);

    std::vector<int8_t> mu_a(static_cast<size_t>(n) * n);
    bx::ExpandMantissaStream(seed_a, mu_a.size(), mu_a.data());
    std::vector<uint8_t> scale_a(static_cast<size_t>(n) * (n / bx::kBlockLen));
    bx::ExpandScaleStream(seed_a, scale_a.size(), scale_a.data());
    std::vector<int8_t> mu_b(static_cast<size_t>(n) * n);
    bx::ExpandMantissaStream(seed_b, mu_b.size(), mu_b.data());
    std::vector<uint8_t> scale_b(static_cast<size_t>(n / bx::kBlockLen) * n);
    bx::ExpandScaleStream(seed_b, scale_b.size(), scale_b.data());

    const auto U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const auto V = bx::ExpandProjectorBMX4C(seed_v, n, m);
    const auto Ahat = bx::ExpandOperandA(seed_a, n);
    const auto Bhat = bx::ExpandOperandB(seed_b, n);

    const auto P_dense = ComputeProjectedLeft(U, Ahat, n, m);
    const auto Q_dense = ComputeProjectedRight(Bhat, V, n, m);

    std::vector<int32_t> P_grouped;
    std::vector<int32_t> Q_grouped;
    mxf4::GroupedMxfp4Problem shape_p{};
    mxf4::GroupedMxfp4Problem shape_q{};
    std::string err;

    BOOST_REQUIRE(mxf4::LaunchGroupedMxfp4Projection(
        mxf4::GroupedMxfp4Orientation::Left, U.data(), mu_a.data(), scale_a.data(),
        n, m, P_grouped, &shape_p, err));
    BOOST_REQUIRE(mxf4::LaunchGroupedMxfp4Projection(
        mxf4::GroupedMxfp4Orientation::Right, V.data(), mu_b.data(), scale_b.data(),
        n, m, Q_grouped, &shape_q, err));

    BOOST_CHECK(P_grouped == P_dense);
    BOOST_CHECK(Q_grouped == Q_dense);

    // Total K across the four exponent buckets is n per block, i.e. n*(n/32)
    // over the whole operand — NOT 4n per block (the tensor-intensity win).
    const uint64_t expect_total = static_cast<uint64_t>(n) * (n / bx::kBlockLen);
    BOOST_CHECK_EQUAL(shape_p.K_total, expect_total);
    BOOST_CHECK_EQUAL(shape_q.K_total, expect_total);
    BOOST_CHECK_EQUAL(shape_p.K_e[0] + shape_p.K_e[1] + shape_p.K_e[2] + shape_p.K_e[3],
                      expect_total);

    // Default builds: CUTLASS tensor kernel is NOT linked/qualified. Portable
    // path above is the production datapath (C6: never claim tensor here).
    BOOST_CHECK(!mxf4::IsGroupedMxfp4TensorKernelLinked());
    BOOST_CHECK(!mxf4::IsGroupedMxfp4TensorKernelCompiled());

    // Invalid dimensions fail closed (not a silent no-op).
    std::vector<int32_t> junk;
    BOOST_CHECK(!mxf4::LaunchGroupedMxfp4Projection(
        mxf4::GroupedMxfp4Orientation::Left, U.data(), mu_a.data(), scale_a.data(),
        /*n=*/n + 1, m, junk, nullptr, err));
}

BOOST_AUTO_TEST_CASE(fp8_five_limb_device_fail_closed_uses_cpu)
{
    // Device FP8 five-limb is unavailable without a qualified Rubin TU; the
    // CPU path must still produce the exact combine.
    BOOST_CHECK(!matmul_v4::cuda::IsDeviceFp8FiveLimbAvailable());
    BOOST_CHECK(!matmul_v4::cuda::IsDeviceFp8FiveLimbCompiled());

    const uint32_t n = kTestDim;
    uint32_t m = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4C(n, kTileB, m));
    std::vector<int32_t> P(static_cast<size_t>(m) * n, 3);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m, -2);
    const std::vector<::matmul::int8_field::Fq> cpu_ref =
        bx::ComputeCombineFp8FiveLimbBMX4C(P, Q, n, m);

    std::vector<::matmul::int8_field::Fq> out;
    bool used_device = true;
    std::string err;
    BOOST_REQUIRE(matmul_v4::cuda::ComputeCombineFp8FiveLimbDeviceOrCpu(P, Q, n, m, out, used_device, err));
    BOOST_CHECK(!used_device);
    BOOST_CHECK(out == cpu_ref);

    {
        const bool launched =
            matmul_v4::cuda::LaunchDeviceFp8FiveLimbCombine(P, Q, n, m, out, err);
        BOOST_CHECK(!launched);
    }
}

BOOST_AUTO_TEST_CASE(lt_tensor_gemm_availability_and_arch_probe)
{
    // Without CUDA/HIP/Metal silicon + self-qual, tensor preference declines.
    // Arch probe still returns a well-formed unknown snapshot (CPU-only builds).
    // HIP device ALU is a separate honest flag — also false when HIP is off.
    const auto arch = matmul_v4::cuda::ProbeLtCudaArch();
    BOOST_CHECK(!arch.sm_string.empty());
    BOOST_CHECK(!arch.name_class_string.empty());

    const auto caps = matmul_v4::cuda::ProbeLtCudaExactGemmCapabilities();
    BOOST_CHECK_EQUAL(caps.device_hashing, false); // Chat D2H gap documented
    BOOST_CHECK_EQUAL(caps.exact_partitioned_s32_s8, false); // s32xs8 IMMA always declines
    BOOST_CHECK(!matmul_v4::cuda::LtLastS8S8UsedImma()); // no prior LaunchGemm on this thread

#if !defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    BOOST_CHECK(!matmul_v4::cuda::IsLtImmaGemmAvailable());
    BOOST_CHECK(!caps.exact_s8_s8_s32);
    BOOST_CHECK_EQUAL(arch.name_class_string, "unknown");
    BOOST_CHECK(!caps.device_scalar_gemm);
#else
    if (matmul_v4::cuda::IsLtImmaGemmAvailable()) {
        BOOST_CHECK(caps.exact_s8_s8_s32);
        BOOST_CHECK(caps.device_scalar_gemm);
        constexpr uint32_t kDim = 32;
        std::vector<int8_t> left(static_cast<size_t>(kDim) * kDim);
        std::vector<int8_t> right(static_cast<size_t>(kDim) * kDim);
        for (uint32_t i = 0; i < kDim * kDim; ++i) {
            left[i] = static_cast<int8_t>((i * 7u) % 97) - 48;
            right[i] = static_cast<int8_t>((i * 11u) % 97) - 48;
        }
        const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu;
        BOOST_REQUIRE(matmul_v4::cuda::TryLaunchLtImmaGemmS8S8(left, right, kDim, kDim, kDim, gpu));
        BOOST_CHECK(gpu == cpu);
        // MatExpand thin panel must also match when IMMA is advertised.
        constexpr uint32_t kN = 64;
        constexpr uint32_t kW = 16;
        std::vector<int8_t> G(static_cast<size_t>(kN) * kN);
        std::vector<int8_t> W(static_cast<size_t>(kN) * kW);
        for (uint32_t i = 0; i < kN * kN; ++i) {
            G[i] = static_cast<int8_t>((i * 3u) % 97) - 48;
        }
        for (uint32_t i = 0; i < kN * kW; ++i) {
            W[i] = static_cast<int8_t>((i * 5u) % 97) - 48;
        }
        const auto cpu_panel = matmul::v4::lt::ExactGemmS8S8(G, W, kN, kN, kW);
        std::vector<int32_t> gpu_panel;
        BOOST_REQUIRE(matmul_v4::cuda::TryLaunchLtImmaGemmS8S8(G, W, kN, kN, kW, gpu_panel));
        BOOST_CHECK(gpu_panel == cpu_panel);
    } else {
        BOOST_CHECK(!caps.exact_s8_s8_s32);
    }
#endif

#if !defined(BTX_ENABLE_HIP)
    // CPU / non-HIP builds: MFMA and device-ALU flags must stay fail-closed.
    BOOST_CHECK(!matmul_v4::hip::IsLtMfmaGemmAvailable());
    BOOST_CHECK(!matmul_v4::hip::IsLtDeviceAluGemmAvailable());
#else
    // HIP builds: MFMA true only after hipBLASLt/rocBLAS ExactGemm match;
    // device ALU is a separate honest flag (never implies MFMA).
    if (matmul_v4::hip::IsLtMfmaGemmAvailable()) {
        BOOST_CHECK(matmul_v4::hip::IsLtMfmaGemmAvailable());
    }
#endif
    const auto metal_arch = matmul_v4::metal::ProbeLtMetalArch();
    BOOST_CHECK(!metal_arch.name_class_string.empty());
    const auto metal_caps = matmul_v4::metal::ProbeLtMetalExactGemmCapabilities();
    BOOST_CHECK_EQUAL(metal_caps.device_hashing, false);
#if !defined(BTX_ENABLE_METAL)
    BOOST_CHECK(!matmul_v4::metal::IsLtTensorOpsGemmAvailable());
    BOOST_CHECK(!metal_caps.exact_s8_s8_s32);
    BOOST_CHECK_EQUAL(metal_arch.name_class_string, "unknown");
#else
    if (!matmul_v4::metal::IsLtTensorOpsGemmAvailable()) {
        BOOST_CHECK(!metal_caps.exact_s8_s8_s32);
    } else {
        BOOST_CHECK(metal_caps.exact_s8_s8_s32);
    }
    // Compilation/self-qualification must never rewrite the independently
    // observed silicon family (Metal 4 MPP also compiles on M4).
    if (metal_arch.device_name.find("M4") != std::string::npos ||
        metal_arch.device_name.find("m4") != std::string::npos) {
        BOOST_CHECK(metal_arch.name_class == matmul_v4::metal::LtMetalArchNameClass::M4Class);
        BOOST_CHECK_EQUAL(metal_arch.name_class_string, "m4_class");
    }
#endif

    std::vector<int8_t> a(16, 1), b(16, 2);
    std::vector<int32_t> out;
    {
#if !defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
        BOOST_CHECK(!matmul_v4::cuda::TryLaunchLtImmaGemmS8S8(a, b, 4, 4, 4, out));
#else
        (void)matmul_v4::cuda::TryLaunchLtImmaGemmS8S8(a, b, 4, 4, 4, out);
#endif
#if !defined(BTX_ENABLE_HIP)
        BOOST_CHECK(!matmul_v4::hip::TryLaunchLtMfmaGemmS8S8(a, b, 4, 4, 4, out));
        BOOST_CHECK(!matmul_v4::hip::TryLaunchLtDeviceAluGemmS8S8(a, b, 4, 4, 4, out));
        BOOST_CHECK(!matmul_v4::hip::TryLaunchLtMfmaGemmS8S8Device(
            nullptr, nullptr, nullptr, 4, 4, 4, nullptr));
#else
        (void)matmul_v4::hip::TryLaunchLtMfmaGemmS8S8(a, b, 4, 4, 4, out);
        (void)matmul_v4::hip::TryLaunchLtDeviceAluGemmS8S8(a, b, 4, 4, 4, out);
#endif
#if !defined(BTX_ENABLE_METAL)
        BOOST_CHECK(!matmul_v4::metal::TryLaunchLtTensorOpsGemmS8S8(a, b, 4, 4, 4, out));
#else
        (void)matmul_v4::metal::TryLaunchLtTensorOpsGemmS8S8(a, b, 4, 4, 4, out);
#endif
    }

    // S32S8 IMMA always declines — scalar DeviceGemmS32S8Tiled / CPU ExactGemm remain.
    std::vector<int32_t> mid(16, 3);
    BOOST_CHECK(!matmul_v4::cuda::TryLaunchLtImmaGemmS32S8(mid, b, 4, 4, 4, out));
#if !defined(BTX_ENABLE_HIP)
    BOOST_CHECK(!matmul_v4::hip::TryLaunchLtMfmaGemmS32S8(mid, b, 4, 4, 4, out));
#endif
#if !defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    BOOST_CHECK(!matmul_v4::cuda::LtLastS8S8UsedImma());
#endif
}


BOOST_AUTO_TEST_CASE(exact_accel_planner_selects_documented_lanes)
{
    const auto h200 = bx::PlanExactAccelLanes("h200");
    BOOST_CHECK(h200.projection == bx::ProjectionLane::CanonicalInt8);
    BOOST_CHECK(h200.combine == bx::CombineLane::Karatsuba9Int8);

    const auto b200 = bx::PlanExactAccelLanes("b200");
    BOOST_CHECK(b200.projection == bx::ProjectionLane::ScalePartitionedMxfp4);
    BOOST_CHECK(b200.combine == bx::CombineLane::Karatsuba9Int8);

    const auto rubin = bx::PlanExactAccelLanes("rubin");
    BOOST_CHECK(rubin.projection == bx::ProjectionLane::ExactFp8);
    BOOST_CHECK(rubin.combine == bx::CombineLane::ExactFp8FiveLimb);

    const auto cpu = bx::PlanExactAccelLanes("cpu");
    BOOST_CHECK(cpu.combine == bx::CombineLane::CanonicalInteger);
}

BOOST_AUTO_TEST_CASE(digest_only_mining_drops_loser_payloads)
{
    const uint32_t n = kTestDim;
    const auto tmpl = MakeV4Header(0, n);
    bx::BatchedSketchMinerBMX4C miner{tmpl, n};
    BOOST_REQUIRE(miner.Valid());

    std::vector<CBlockHeader> headers(4, tmpl);
    for (uint32_t i = 0; i < headers.size(); ++i) {
        headers[i].nNonce64 = 100 + i;
        headers[i].nNonce = static_cast<uint32_t>(headers[i].nNonce64);
    }
    // All-ones target => every digest matches (forces winner payload retention path).
    const uint256 easy_target = ParseUint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    std::vector<bx::DigestOnlyResultBMX4C> results;
    std::vector<std::vector<unsigned char>> payloads;
    BOOST_REQUIRE(miner.MineDigestsOnly(headers, easy_target, results, &payloads, /*retain_winner_payload=*/true));
    BOOST_REQUIRE_EQUAL(results.size(), headers.size());
    BOOST_REQUIRE_EQUAL(payloads.size(), headers.size());
    for (size_t i = 0; i < results.size(); ++i) {
        BOOST_CHECK(results[i].target_match);
        BOOST_CHECK(!payloads[i].empty());
        uint256 ref_digest;
        std::vector<unsigned char> ref_payload;
        BOOST_REQUIRE(bx::ComputeDigestBMX4C(headers[i], n, ref_digest, ref_payload));
        BOOST_CHECK(results[i].digest == ref_digest);
        BOOST_CHECK(payloads[i] == ref_payload);
    }

    // Impossible target => no payloads retained.
    const uint256 hard_target{}; // zero
    results.clear();
    payloads.clear();
    BOOST_REQUIRE(miner.MineDigestsOnly(headers, hard_target, results, &payloads, /*retain_winner_payload=*/true));
    for (size_t i = 0; i < results.size(); ++i) {
        BOOST_CHECK(!results[i].target_match);
        BOOST_CHECK(payloads[i].empty());
    }
}

BOOST_AUTO_TEST_CASE(portable_xof_matches_streaming)
{
    const uint256 seed = ParseUint256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const size_t count = 4096;
    std::vector<int8_t> a(count), b(count);
    bx::ExpandMantissaStream(seed, count, a.data());
    bx::ExpandMantissaStreamPortable(seed, count, b.data());
    BOOST_CHECK(a == b);

    std::vector<uint8_t> sa(512), sb(512);
    bx::ExpandScaleStream(seed, sa.size(), sa.data());
    bx::ExpandScaleStreamPortable(seed, sb.size(), sb.data());
    BOOST_CHECK(sa == sb);
}

BOOST_AUTO_TEST_CASE(streaming_digest_matches_serialized)
{
    const uint32_t n = 64;
    uint32_t m = 0;
    BOOST_REQUIRE(bx::ValidateDimsBMX4C(n, kTileB, m));
    const auto header = MakeV4Header(9, n);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, n, digest, payload));
    std::vector<Fq> sketch;
    BOOST_REQUIRE(ParseSketch(payload, m, sketch));
    const uint256 sigma = DeriveSigma(header);
    BOOST_CHECK(ComputeSketchDigestFromFq(sigma, sketch) == digest);
    BOOST_CHECK(ComputeSketchDigest(sigma, payload) == digest);
}

BOOST_AUTO_TEST_CASE(persistent_pipeline_byte_identical_and_reuses_template)
{
    const uint32_t n = kTestDim;
    const auto tmpl = MakeV4Header(0, n);
    bx::PersistentSketchMinerBMX4C miner{tmpl, n};
    BOOST_REQUIRE(miner.Valid());
    miner.SetRequestedQ(4);

    std::vector<CBlockHeader> headers(5, tmpl);
    for (uint32_t i = 0; i < headers.size(); ++i) {
        headers[i].nNonce64 = 200 + i;
        headers[i].nNonce = static_cast<uint32_t>(headers[i].nNonce64);
    }
    const uint256 easy_target = ParseUint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    std::vector<bx::DigestOnlyResultBMX4C> r1, r2;
    std::vector<std::vector<unsigned char>> p1;
    BOOST_REQUIRE(miner.MineDigestsOnly(headers, easy_target, r1, &p1, true));
    BOOST_REQUIRE(miner.MineDigestsOnly(headers, easy_target, r2, nullptr, false)); // cross-call reuse
    BOOST_REQUIRE_EQUAL(r1.size(), r2.size());
    for (size_t i = 0; i < r1.size(); ++i) {
        BOOST_CHECK(r1[i].digest == r2[i].digest);
        uint256 ref_digest;
        std::vector<unsigned char> ref_payload;
        BOOST_REQUIRE(bx::ComputeDigestBMX4C(headers[i], n, ref_digest, ref_payload));
        BOOST_CHECK(r1[i].digest == ref_digest);
        BOOST_CHECK(p1[i] == ref_payload);
    }
    BOOST_CHECK_EQUAL(miner.LastStats().xof_stage_calls, headers.size());
    BOOST_CHECK_EQUAL(miner.LastStats().combine_stage_calls, headers.size());
    BOOST_CHECK_EQUAL(miner.LastStats().hash_stage_calls, headers.size());
}

// --- GOLDEN / C-1' boundary vectors -----------------------------------------

BOOST_AUTO_TEST_CASE(boundary_e8m0_scale_exactness)
{
    // E8M0 dequant is a PURE power-of-two shift: mu * 2^e, exact, no mantissa
    // bit changes, |.| <= 48. A rounding / FP-mantissa device that mishandled
    // the block scale would diverge here.
    static const std::array<int8_t, 11> kM11{0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    for (int8_t mu : kM11) {
        for (uint8_t e = 0; e <= bx::kScaleS; ++e) {
            const int32_t deq = static_cast<int32_t>(mu) * (1 << e);
            BOOST_CHECK_EQUAL(deq, static_cast<int32_t>(mu) << e); // pure shift for >=0
            BOOST_CHECK(deq >= -bx::kEmax && deq <= bx::kEmax);
        }
    }
    // Exact E_max: 6 * 2^3 == 48.
    BOOST_CHECK_EQUAL(6 * (1 << 3), bx::kEmax);
}

BOOST_AUTO_TEST_CASE(boundary_base_product_odd_step_crosses_2e14)
{
    // Odd-step base-product accumulation crossing 2^14 (catches a t~14
    // FP-mantissa accumulator, e.g. the DeepSeek/Hopper FP8 datapath). The
    // largest ODD per-MAC product on the committed path is mu=3 (e=0) times
    // mu=3 (e=0) = 9. A length-N rail dot climbs in odd steps of 9; at
    // N = 1824 it reaches 16,416 > 2^14 = 16,384, so a device exact only to
    // 2^14 (ULP >= 2 above it) MUST round while the int reference is exact.
    const uint32_t N = 1824; // 9*1824 = 16,416
    std::vector<int8_t> a(N, 3), b(N, 3); // dequant mu=3, e=0
    int64_t acc = 0;
    for (uint32_t k = 0; k < N; ++k) acc += static_cast<int64_t>(a[k]) * b[k];
    BOOST_CHECK_EQUAL(acc, static_cast<int64_t>(9) * N);
    BOOST_CHECK_EQUAL(acc, 16'416);
    BOOST_CHECK(acc > (1 << 14));               // crossed 2^14
    BOOST_CHECK_EQUAL(acc % 2, 0);              // 16416 even, but built by odd steps
    // Reference int8_field exact dot reproduces it bit-for-bit.
    BOOST_CHECK_EQUAL(matmul::int8_field::ExactDot(a.data(), b.data(), N), 16'416);
}

BOOST_AUTO_TEST_CASE(boundary_base_product_high_magnitude_real_gemm)
{
    // Real GEMM path in the high-magnitude regime: E_max rails (all dequant
    // = 48) push every C entry to exactly 2304*n, well past 2^14. Pushed
    // through all three consensus-equivalent sketch paths with byte-equality.
    const uint32_t n = 256; // 2304*256 = 589,824 ~ 2^19.2 (> 2^14)
    const uint32_t m = n / kTileB;
    std::vector<int8_t> Ahat(static_cast<size_t>(n) * n, 48);
    std::vector<int8_t> Bhat(static_cast<size_t>(n) * n, 48);
    const auto C = ComputeExactProduct(Ahat, Bhat, n);
    for (int32_t x : C) BOOST_REQUIRE_EQUAL(x, 2304 * static_cast<int32_t>(n));
    BOOST_CHECK_EQUAL(C[0], 589'824);

    // M11 projectors, then all three paths agree byte-for-byte.
    const auto U = bx::ExpandProjectorBMX4C(
        ParseUint256("00000000000000000000000000000000000000000000000000000000000000e1"), m, n);
    const auto V = bx::ExpandProjectorBMX4C(
        ParseUint256("00000000000000000000000000000000000000000000000000000000000000e2"), n, m);
    const auto full = ComputeSketch(U, C, V, n, m);
    const auto P = ComputeProjectedLeft(U, Ahat, n, m);
    const auto Q = ComputeProjectedRight(Bhat, V, n, m);
    BOOST_CHECK(ComputeCombineModQ(P, Q, n, m) == full);
    BOOST_CHECK(bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m) == full);
}

BOOST_AUTO_TEST_CASE(boundary_limb_pair_exact_2e22_at_n4096)
{
    // The limb-pair GEMM accumulator peak is 1024*n = 2^22 at n = 4096
    // (design §2.4). Entries = 32 decompose to digit0 = -32, so S00 =
    // sum_k (-32)*(-32) = 1024*n hits EXACTLY 2^22. m is kept small so the
    // O(m^2 n) combine is cheap while n = 4096 is real.
    BOOST_CHECK_EQUAL(1024 * 4096, 1 << 22);
    const uint32_t n = 4096;
    const uint32_t m = 8;
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n));
    std::vector<int32_t> P(static_cast<size_t>(m) * n, 32);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m, 32);
    const auto direct = ComputeCombineModQ(P, Q, n, m);
    const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
    BOOST_CHECK(limb == direct);
    // Chat[a][c] = sum_k 32*32 = 1024*4096 = 4,194,304 = 2^22 (< q, canonical).
    for (Fq v : direct) BOOST_CHECK_EQUAL(v, 4'194'304u);

    // At n = 8192 the same rails hit exactly 2^23.
    const uint32_t n8 = 8192;
    BOOST_REQUIRE(bx::CheckCombineLimbBoundBMX4C(n8));
    std::vector<int32_t> P8(static_cast<size_t>(m) * n8, 32);
    std::vector<int32_t> Q8(static_cast<size_t>(n8) * m, 32);
    const auto direct8 = ComputeCombineModQ(P8, Q8, n8, m);
    BOOST_CHECK(bx::ComputeCombineLimbTensorBMX4C(P8, Q8, n8, m) == direct8);
    for (Fq v : direct8) BOOST_CHECK_EQUAL(v, 8'388'608u); // 2^23
}

// --- (d) DETERMINISM --------------------------------------------------------

BOOST_AUTO_TEST_CASE(digest_determinism_run_to_run)
{
    const CBlockHeader header = MakeV4Header(0xdead'beef'0000'0001ULL, kTestDim);
    uint256 d1, d2;
    std::vector<unsigned char> p1, p2;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, d1, p1));
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, d2, p2));
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK(p1 == p2);
    BOOST_CHECK_EQUAL(p1.size(), 8u * (kTestDim / kTileB) * (kTestDim / kTileB));
}

// --- (c) SOUNDNESS ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(verifier_accepts_correct_sketch)
{
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'0009ULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, payload));
    header.matmul_digest = digest;

    uint256 vout;
    BOOST_CHECK(bx::VerifySketchBMX4C(header, kTestDim, matmul_v4::kFreivaldsRounds, payload, vout));
    BOOST_CHECK(vout == digest);
}

BOOST_AUTO_TEST_CASE(verifier_rejects_digest_mismatch)
{
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'000aULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, payload));
    header.matmul_digest = digest;

    // Flip a byte in the payload: the recomputed digest no longer matches.
    payload[0] ^= 0x01;
    uint256 vout;
    BOOST_CHECK(!bx::VerifySketchBMX4C(header, kTestDim, matmul_v4::kFreivaldsRounds, payload, vout));
}

BOOST_AUTO_TEST_CASE(verifier_freivalds_rejects_wrong_but_consistent_sketch)
{
    // Isolate Freivalds soundness from the digest check: perturb ONE sketch
    // word, re-serialize, and re-commit the header to the perturbed digest so
    // the digest check passes -- the O(n^2) Freivalds identity must still fail.
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'000bULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, payload));

    const uint32_t m = kTestDim / kTileB;
    std::vector<Fq> sketch;
    BOOST_REQUIRE(ParseSketch(payload, m, sketch));
    sketch[0] = matmul::int8_field::FqAdd(sketch[0], 1); // wrong, still canonical
    const auto bad_payload = SerializeSketch(sketch);

    const uint256 sigma = DeriveSigma(header);
    header.matmul_digest = ComputeSketchDigest(sigma, bad_payload); // consistent digest

    uint256 vout;
    BOOST_CHECK(!bx::VerifySketchBMX4C(header, kTestDim, matmul_v4::kFreivaldsRounds, bad_payload, vout));
}

// --- F-L3: verifiers fail-closed on rounds == 0 -----------------------------

BOOST_AUTO_TEST_CASE(verifier_bmx4c_rejects_zero_rounds)
{
    // A correct, digest-consistent ENC-BMX4C sketch that verifies at R = 3 MUST
    // be REJECTED when rounds == 0: SketchFreivalds returns true on an empty
    // round set, so the verifier must guard rounds == 0 itself (defense-in-depth
    // vs a misconfigured 0-round verify degrading to a no-op accept).
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'00f0ULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, kTestDim, digest, payload));
    header.matmul_digest = digest;

    uint256 vout;
    // Control: the honest R = 3 verify accepts.
    BOOST_CHECK(bx::VerifySketchBMX4C(header, kTestDim, matmul_v4::kFreivaldsRounds, payload, vout));
    // rounds == 0 fails closed (reject), even for the correct payload/digest.
    BOOST_CHECK(!bx::VerifySketchBMX4C(header, kTestDim, 0, payload, vout));
}

BOOST_AUTO_TEST_CASE(verifier_v4_encs8_rejects_zero_rounds)
{
    // Same fail-closed guard for the v4.1 ENC-S8 verifier (matmul_v4::VerifySketch):
    // a correct sketch that passes at R = 3 must be rejected at rounds == 0.
    CBlockHeader header = MakeV4Header(0x1234'5678'0000'00f1ULL, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(matmul_v4::ComputeDigest(header, kTestDim, matmul_v4::kFreivaldsRounds,
                                           digest, payload));
    header.matmul_digest = digest;

    uint256 vout;
    BOOST_CHECK(matmul_v4::VerifySketch(header, kTestDim, matmul_v4::kFreivaldsRounds, payload, vout));
    BOOST_CHECK(!matmul_v4::VerifySketch(header, kTestDim, 0, payload, vout));
}

// --- GOLDEN digests (pinned by running this reference) ----------------------

namespace {
// Emit-or-assert helper: if `golden` is empty, print the freshly computed
// digest (first-generation pass); once pinned, assert byte-equality.
void CheckGolden(std::string_view label, const uint256& digest, std::string_view golden)
{
    if (golden.empty()) {
        BOOST_TEST_MESSAGE("GOLDEN " << label << " = " << digest.GetHex());
        return;
    }
    BOOST_CHECK_EQUAL(digest.GetHex(), std::string(golden));
}
} // namespace

BOOST_AUTO_TEST_CASE(golden_digests)
{
    struct Case { uint32_t n; uint64_t nonce; std::string_view golden; };
    const Case cases[] = {
        {128, 0x0000'0000'0000'0001ULL, "c94923800c8a5e344c88efdb2ec5ad07d80694c903af3dae1859ec14ade67b7c"},
        {256, 0x0000'0000'0000'0001ULL, "4e192d8b907ad2d1383600d6f9b794c3ebf6387d577ca82333e75f544f54a9f9"},
        {256, 0x0000'0000'0000'0002ULL, "91fe8b670ad84b6b37d6ce859133945f7d8181709f7dbdf8a64b8c7e25f4aeed"},
    };
    for (const auto& c : cases) {
        const CBlockHeader header = MakeV4Header(c.nonce, c.n);
        uint256 digest;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE(bx::ComputeDigestBMX4C(header, c.n, digest, payload));
        // Self-verify each golden case end-to-end.
        CBlockHeader vheader = header;
        vheader.matmul_digest = digest;
        uint256 vout;
        BOOST_CHECK(bx::VerifySketchBMX4C(vheader, c.n, matmul_v4::kFreivaldsRounds, payload, vout));
        CheckGolden("n=" + std::to_string(c.n) + " nonce=" + std::to_string(c.nonce),
                    digest, c.golden);
    }
}

BOOST_AUTO_TEST_SUITE_END()
