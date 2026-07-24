// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Gate tests for Freivalds GEMM verification over Goldilocks
// (matmul_v4_rc_freivalds.{h,cpp}):
//   (a) an honest small GEMM (8×5×7, PRNG entries) passes all reps;
//   (b) flipping ONE Y entry by ±1 fails with reps ≥ 1, across several seeds;
//   (c) flipping one A or one B entry fails (Y stays the honest product);
//   (d) high-magnitude ±127 entries with large k still verify honest and
//       reject tampered — the signed embedding is exact, no wraparound;
//   (e) FreivaldsChallengeVector is exact-rejection sampled over Goldilocks and
//       remains deterministic, rep/seed-separated, prefix-consistent in n;
//   (f) differential: the O(mk+kn+mn) verdict equals the naive triple-loop
//       A·B == Y verdict on random honest and tampered instances.

#include <matmul/matmul_v4_rc_freivalds.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace frv = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_freivalds_tests, BasicTestingSetup)

namespace {

/** Deterministic PRNG (splitmix64) so failures are reproducible. */
uint64_t SplitMix64(uint64_t& state)
{
    state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

uint256 SeedFromByte(unsigned char b)
{
    uint256 s;
    s.data()[0] = b;
    return s;
}

/** Exact reference product over int64 (no overflow: |entry| ≤ k·2^14). */
std::vector<int64_t> NaiveGemm(const std::vector<int8_t>& A,
                               const std::vector<int8_t>& B,
                               uint32_t m, uint32_t k, uint32_t n)
{
    std::vector<int64_t> Y(static_cast<size_t>(m) * n, 0);
    for (uint32_t i = 0; i < m; ++i) {
        for (uint32_t t = 0; t < k; ++t) {
            const int64_t a = A[static_cast<size_t>(i) * k + t];
            for (uint32_t j = 0; j < n; ++j) {
                Y[static_cast<size_t>(i) * n + j] +=
                    a * B[static_cast<size_t>(t) * n + j];
            }
        }
    }
    return Y;
}

void FillInt8(std::vector<int8_t>& v, uint64_t& st)
{
    for (auto& x : v) x = static_cast<int8_t>(SplitMix64(st) & 0xFF);
}

} // namespace

// (a) Honest 8×5×7 GEMM passes with several rep counts.
BOOST_AUTO_TEST_CASE(honest_small_gemm_passes)
{
    const uint32_t m = 8, k = 5, n = 7;
    uint64_t st = 0xA11CE;
    std::vector<int8_t> A(m * k), B(k * n);
    FillInt8(A, st);
    FillInt8(B, st);
    const std::vector<int64_t> Y = NaiveGemm(A, B, m, k, n);
    for (uint32_t reps : {1u, 2u, 3u}) {
        std::string why;
        BOOST_CHECK_MESSAGE(
            frv::FreivaldsCheckGemm(A, B, Y, m, k, n, SeedFromByte(1), reps, &why),
            "honest reject: " << why);
    }
}

// (b) A single ±1 flip in Y is caught with reps = 1, across several seeds.
BOOST_AUTO_TEST_CASE(single_y_flip_rejected)
{
    const uint32_t m = 8, k = 5, n = 7;
    uint64_t st = 0xB0B;
    std::vector<int8_t> A(m * k), B(k * n);
    FillInt8(A, st);
    FillInt8(B, st);
    const std::vector<int64_t> Y = NaiveGemm(A, B, m, k, n);
    for (unsigned char seed_byte = 0; seed_byte < 8; ++seed_byte) {
        for (int delta : {+1, -1}) {
            std::vector<int64_t> Ybad = Y;
            const size_t idx = SplitMix64(st) % Ybad.size();
            Ybad[idx] += delta;
            BOOST_CHECK(!frv::FreivaldsCheckGemm(A, B, Ybad, m, k, n,
                                                 SeedFromByte(seed_byte), 1,
                                                 nullptr));
        }
    }
}

// (c) A single flip in A or in B (honest Y unchanged) is caught.
BOOST_AUTO_TEST_CASE(single_a_or_b_flip_rejected)
{
    const uint32_t m = 8, k = 5, n = 7;
    uint64_t st = 0xC4A7;
    std::vector<int8_t> A(m * k), B(k * n);
    FillInt8(A, st);
    FillInt8(B, st);
    const std::vector<int64_t> Y = NaiveGemm(A, B, m, k, n);

    std::vector<int8_t> Abad = A;
    Abad[SplitMix64(st) % Abad.size()] ^= 1; // change one entry
    BOOST_CHECK(!frv::FreivaldsCheckGemm(Abad, B, Y, m, k, n, SeedFromByte(2), 1,
                                         nullptr));

    std::vector<int8_t> Bbad = B;
    Bbad[SplitMix64(st) % Bbad.size()] ^= 1;
    BOOST_CHECK(!frv::FreivaldsCheckGemm(A, Bbad, Y, m, k, n, SeedFromByte(2), 1,
                                         nullptr));
}

// (d) High-magnitude regime: k = 2^15, all entries ±127, so |Y_ij| up to
// k·127·127 ≈ 2^28.98 — an exact int64 whose signed embedding agrees with the
// integer value (|Y_ij| ≤ k·2^14 < p for all k ≤ 2^40). Honest verifies,
// a ±1 tamper is rejected: the check is exact, no mod-p wraparound.
BOOST_AUTO_TEST_CASE(high_magnitude_embedding_exact)
{
    const uint32_t m = 2, k = 1u << 15, n = 3;
    uint64_t st = 0xD00D;
    std::vector<int8_t> A(static_cast<size_t>(m) * k), B(static_cast<size_t>(k) * n);
    for (auto& x : A) x = (SplitMix64(st) & 1) ? int8_t{127} : int8_t{-127};
    for (auto& x : B) x = (SplitMix64(st) & 1) ? int8_t{127} : int8_t{-127};
    const std::vector<int64_t> Y = NaiveGemm(A, B, m, k, n);
    std::string why;
    BOOST_CHECK_MESSAGE(
        frv::FreivaldsCheckGemm(A, B, Y, m, k, n, SeedFromByte(3), 1, &why),
        "honest high-magnitude reject: " << why);
    for (int delta : {+1, -1}) {
        std::vector<int64_t> Ybad = Y;
        Ybad[0] += delta;
        BOOST_CHECK(!frv::FreivaldsCheckGemm(A, B, Ybad, m, k, n, SeedFromByte(3),
                                             1, nullptr));
    }
}

// (e) Challenge vector: exact rejection-sampled Fp output; pure function of
// (seed, rep, n); distinct across rep and seed; r_j independent of n
// (prefix-consistent).
BOOST_AUTO_TEST_CASE(challenge_vector_deterministic)
{
    const auto r0 = frv::FreivaldsChallengeVector(SeedFromByte(7), 0, 16);
    const auto r0b = frv::FreivaldsChallengeVector(SeedFromByte(7), 0, 16);
    BOOST_CHECK(r0 == r0b);
    for (const gf::Fp x : r0) BOOST_CHECK(x < gf::kP); // canonical range

    const auto r1 = frv::FreivaldsChallengeVector(SeedFromByte(7), 1, 16);
    BOOST_CHECK(r0 != r1); // rep domain separation
    const auto q0 = frv::FreivaldsChallengeVector(SeedFromByte(8), 0, 16);
    BOOST_CHECK(r0 != q0); // seed separation

    const auto r0short = frv::FreivaldsChallengeVector(SeedFromByte(7), 0, 5);
    for (uint32_t j = 0; j < 5; ++j) BOOST_CHECK_EQUAL(r0short[j], r0[j]);
}

// Fail-closed on malformed shapes and reps == 0.
BOOST_AUTO_TEST_CASE(shape_validation_fail_closed)
{
    const uint32_t m = 2, k = 3, n = 4;
    std::vector<int8_t> A(m * k, 1), B(k * n, 1);
    const std::vector<int64_t> Y = NaiveGemm(A, B, m, k, n);
    std::string why;
    BOOST_CHECK(frv::FreivaldsCheckGemm(A, B, Y, m, k, n, SeedFromByte(4), 1, &why));

    std::vector<int8_t> Ashort(A.begin(), A.end() - 1);
    BOOST_CHECK(!frv::FreivaldsCheckGemm(Ashort, B, Y, m, k, n, SeedFromByte(4), 1, &why));
    BOOST_CHECK(why.find("A.size()") != std::string::npos);
    std::vector<int8_t> Blong = B;
    Blong.push_back(0);
    BOOST_CHECK(!frv::FreivaldsCheckGemm(A, Blong, Y, m, k, n, SeedFromByte(4), 1, &why));
    BOOST_CHECK(why.find("B.size()") != std::string::npos);
    std::vector<int64_t> Yshort(Y.begin(), Y.end() - 1);
    BOOST_CHECK(!frv::FreivaldsCheckGemm(A, B, Yshort, m, k, n, SeedFromByte(4), 1, &why));
    BOOST_CHECK(why.find("Y.size()") != std::string::npos);
    BOOST_CHECK(!frv::FreivaldsCheckGemm(A, B, Y, m, k, n, SeedFromByte(4), 0, &why));
    BOOST_CHECK(why.find("reps") != std::string::npos);
}

// (f) Differential: Freivalds verdict == naive A·B == Y verdict on random
// honest and tampered instances (tamper delta forced nonzero, so the naive
// verdict is definitively false there; false-accept odds ≤ 2^-63 per rep).
BOOST_AUTO_TEST_CASE(differential_vs_naive)
{
    uint64_t st = 0xF00F;
    for (int iter = 0; iter < 64; ++iter) {
        const uint32_t m = 1 + SplitMix64(st) % 6;
        const uint32_t k = 1 + SplitMix64(st) % 6;
        const uint32_t n = 1 + SplitMix64(st) % 6;
        std::vector<int8_t> A(static_cast<size_t>(m) * k), B(static_cast<size_t>(k) * n);
        FillInt8(A, st);
        FillInt8(B, st);
        std::vector<int64_t> Y = NaiveGemm(A, B, m, k, n);
        const bool tamper = (iter & 1) != 0;
        if (tamper) {
            const size_t idx = SplitMix64(st) % Y.size();
            int64_t delta = 0;
            while (delta == 0) delta = static_cast<int64_t>(SplitMix64(st) % 257) - 128;
            Y[idx] += delta;
        }
        const bool naive_ok = (Y == NaiveGemm(A, B, m, k, n));
        const uint256 seed = SeedFromByte(static_cast<unsigned char>(iter));
        BOOST_CHECK_EQUAL(frv::FreivaldsCheckGemm(A, B, Y, m, k, n, seed, 1, nullptr),
                          naive_ok);
        BOOST_CHECK_EQUAL(naive_ok, !tamper);
    }
}

BOOST_AUTO_TEST_SUITE_END()
