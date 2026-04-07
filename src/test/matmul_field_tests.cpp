// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/field.h>

#include <crypto/common.h>
#include <hash.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <array>
#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

namespace matmul::field {
Element Reduce64ForTest(uint64_t x);
} // namespace matmul::field

namespace {
using matmul::field::Element;

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

std::vector<Element> FromSeedFlat(const uint256& seed, uint32_t n)
{
    std::vector<Element> out;
    out.reserve(static_cast<size_t>(n) * static_cast<size_t>(n));
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            out.push_back(matmul::field::from_oracle(seed, row * n + col));
        }
    }
    return out;
}

std::array<uint8_t, CSHA256::OUTPUT_SIZE> Sha256(std::span<const uint8_t> bytes)
{
    std::array<uint8_t, CSHA256::OUTPUT_SIZE> out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(out.data());
    return out;
}

bool IsPrime(uint32_t n)
{
    if (n < 2) return false;
    if ((n % 2U) == 0) return n == 2;
    for (uint32_t d = 3; static_cast<uint64_t>(d) * d <= n; d += 2) {
        if ((n % d) == 0) return false;
    }
    return true;
}

Element RefReduce64(uint64_t x)
{
    return static_cast<Element>(x % matmul::field::MODULUS);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_field_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(field_modulus_is_prime)
{
    BOOST_CHECK(IsPrime(matmul::field::MODULUS));
}

BOOST_AUTO_TEST_CASE(field_add_basic)
{
    const Element q = matmul::field::MODULUS;
    BOOST_CHECK_EQUAL(matmul::field::add(0, 0), 0U);
    BOOST_CHECK_EQUAL(matmul::field::add(1, q - 1), 0U);
    BOOST_CHECK_EQUAL(matmul::field::add(q - 1, q - 1), q - 2);
}

BOOST_AUTO_TEST_CASE(field_add_commutative)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 1000; ++i) {
        const Element a = matmul::field::from_uint32(rng.rand32());
        const Element b = matmul::field::from_uint32(rng.rand32());
        BOOST_CHECK_EQUAL(matmul::field::add(a, b), matmul::field::add(b, a));
    }
}

BOOST_AUTO_TEST_CASE(field_mul_basic)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 500; ++i) {
        const Element x = matmul::field::from_uint32(rng.rand32());
        BOOST_CHECK_EQUAL(matmul::field::mul(0, x), 0U);
        BOOST_CHECK_EQUAL(matmul::field::mul(1, x), x);
    }
    const Element q = matmul::field::MODULUS;
    BOOST_CHECK_EQUAL(matmul::field::mul(q - 1, q - 1), 1U);
}

BOOST_AUTO_TEST_CASE(field_mul_associative)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 1000; ++i) {
        const Element a = matmul::field::from_uint32(rng.rand32());
        const Element b = matmul::field::from_uint32(rng.rand32());
        const Element c = matmul::field::from_uint32(rng.rand32());
        BOOST_CHECK_EQUAL(
            matmul::field::mul(a, matmul::field::mul(b, c)),
            matmul::field::mul(matmul::field::mul(a, b), c));
    }
}

BOOST_AUTO_TEST_CASE(field_mul_distributive)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 1000; ++i) {
        const Element a = matmul::field::from_uint32(rng.rand32());
        const Element b = matmul::field::from_uint32(rng.rand32());
        const Element c = matmul::field::from_uint32(rng.rand32());
        BOOST_CHECK_EQUAL(
            matmul::field::mul(a, matmul::field::add(b, c)),
            matmul::field::add(matmul::field::mul(a, b), matmul::field::mul(a, c)));
    }
}

BOOST_AUTO_TEST_CASE(field_inverse)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 1000; ++i) {
        Element a{0};
        while (a == 0) {
            a = matmul::field::from_uint32(rng.rand32());
        }
        BOOST_CHECK_EQUAL(matmul::field::mul(a, matmul::field::inv(a)), 1U);
    }

    const Element q = matmul::field::MODULUS;
    BOOST_CHECK_EQUAL(matmul::field::inv(1), 1U);
    BOOST_CHECK_EQUAL(matmul::field::inv(q - 1), q - 1);
}

BOOST_AUTO_TEST_CASE(field_sub_is_add_neg)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 1000; ++i) {
        const Element a = matmul::field::from_uint32(rng.rand32());
        const Element b = matmul::field::from_uint32(rng.rand32());
        BOOST_CHECK_EQUAL(matmul::field::sub(a, b), matmul::field::add(a, matmul::field::neg(b)));
    }
}

BOOST_AUTO_TEST_CASE(field_from_oracle_deterministic)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 1000; ++i) {
        const uint256 seed = rng.rand256();
        const uint32_t index = rng.rand32();
        BOOST_CHECK_EQUAL(
            matmul::field::from_oracle(seed, index),
            matmul::field::from_oracle(seed, index));
    }
}

BOOST_AUTO_TEST_CASE(field_from_oracle_output_range)
{
    FastRandomContext rng{true};
    for (int i = 0; i < 10000; ++i) {
        const Element v = matmul::field::from_oracle(rng.rand256(), rng.rand32());
        BOOST_CHECK(v < matmul::field::MODULUS);
    }
}

BOOST_AUTO_TEST_CASE(field_from_oracle_different_seed_differs)
{
    const uint256 seed1 = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const uint256 seed2 = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    BOOST_CHECK_NE(matmul::field::from_oracle(seed1, 0), matmul::field::from_oracle(seed2, 0));
}

BOOST_AUTO_TEST_CASE(field_from_oracle_different_index_differs)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK_NE(matmul::field::from_oracle(seed, 0), matmul::field::from_oracle(seed, 1));
}

// TEST: gpu_reduce64_matches_cpu
BOOST_AUTO_TEST_CASE(field_reduce64_edge_cases)
{
    const Element q = matmul::field::MODULUS;
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(0), 0U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(1), 1U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(q), 0U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(static_cast<uint64_t>(q) + 1), 1U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(static_cast<uint64_t>(q) * q), 0U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(static_cast<uint64_t>(q - 1) * (q - 1)), 1U);
}

BOOST_AUTO_TEST_CASE(field_reduce64_single_fold_boundary)
{
    const Element q = matmul::field::MODULUS;
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest((uint64_t{1} << 62) - 1), RefReduce64((uint64_t{1} << 62) - 1));
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(uint64_t{1} << 62), RefReduce64(uint64_t{1} << 62));
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(static_cast<uint64_t>(q - 1) * q), 0U);
}

// TEST: gpu_reduce64_double_fold_required
// TEST: gpu_reduce64_max_uint64
BOOST_AUTO_TEST_CASE(field_reduce64_double_fold_required)
{
    const Element q = matmul::field::MODULUS;
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(uint64_t{1} << 63), 2U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest((uint64_t{1} << 63) - 1), 1U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(2ULL * static_cast<uint64_t>(q - 1) * (q - 1)), 2U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(std::numeric_limits<uint64_t>::max()), 3U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(3ULL * static_cast<uint64_t>(q - 1) * (q - 1)), 3U);
    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(std::numeric_limits<uint64_t>::max() - q + 1ULL), 4U);
}

BOOST_AUTO_TEST_CASE(field_reduce64_exhaustive_power_of_two)
{
    for (int k = 0; k < 64; ++k) {
        const uint64_t x = uint64_t{1} << k;
        const Element expected = static_cast<Element>(uint64_t{1} << (k % 31));
        BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(x), expected);
    }
}

BOOST_AUTO_TEST_CASE(field_dot_product_basic)
{
    const std::array<Element, 4> a{1, 2, 3, 4};
    const std::array<Element, 4> b{5, 6, 7, 8};
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), a.size()), 70U);
}

BOOST_AUTO_TEST_CASE(field_dot_kernel_probe_matches_build)
{
    const auto probe = matmul::field::ProbeDotKernel();
#if defined(__ARM_NEON)
    BOOST_CHECK(probe.neon_compiled);
    BOOST_CHECK_EQUAL(probe.reason, "neon_enabled");
#else
    BOOST_CHECK(!probe.neon_compiled);
    BOOST_CHECK_EQUAL(probe.reason, "scalar_fallback");
#endif
}

BOOST_AUTO_TEST_CASE(field_dot_product_empty)
{
    std::array<Element, 1> a{0};
    std::array<Element, 1> b{0};
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), 0), 0U);
}

// TEST: gpu_madd_matches_cpu
BOOST_AUTO_TEST_CASE(field_dot_product_matches_manual_reduce)
{
    FastRandomContext rng{true};
    std::vector<Element> a(256);
    std::vector<Element> b(256);
    for (size_t i = 0; i < a.size(); ++i) {
        a[i] = matmul::field::from_uint32(rng.rand32());
        b[i] = matmul::field::from_uint32(rng.rand32());
    }

    Element manual = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        const uint64_t sum = static_cast<uint64_t>(manual) + static_cast<uint64_t>(a[i]) * b[i];
        manual = matmul::field::Reduce64ForTest(sum);
    }

    const Element result = matmul::field::dot(a.data(), b.data(), a.size());
    BOOST_CHECK_EQUAL(result, manual);
}

BOOST_AUTO_TEST_CASE(field_dot_product_worst_case_short)
{
    std::vector<Element> a(100, matmul::field::MODULUS - 1);
    std::vector<Element> b(100, matmul::field::MODULUS - 1);
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), a.size()), 100U);
}

BOOST_AUTO_TEST_CASE(field_dot_product_worst_case_n512)
{
    std::vector<Element> a(512, matmul::field::MODULUS - 1);
    std::vector<Element> b(512, matmul::field::MODULUS - 1);
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), a.size()), 512U);
}

BOOST_AUTO_TEST_CASE(field_dot_product_worst_case_large)
{
    std::vector<Element> a(8192, matmul::field::MODULUS - 1);
    std::vector<Element> b(8192, matmul::field::MODULUS - 1);
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), a.size()), 8192U);
}

// TEST: field_dot_product_worst_case_exceeds_modulus
BOOST_AUTO_TEST_CASE(field_dot_product_worst_case_near_modulus)
{
    std::vector<Element> a(1U << 20, matmul::field::MODULUS - 1);
    std::vector<Element> b(1U << 20, matmul::field::MODULUS - 1);
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), a.size()), (1U << 20));
}

BOOST_AUTO_TEST_CASE(field_naive_accumulation_overflow_demonstration)
{
    const uint64_t product = static_cast<uint64_t>(matmul::field::MODULUS - 1) * (matmul::field::MODULUS - 1);

    uint64_t naive_acc = 0;
    for (int i = 0; i < 5; ++i) {
        naive_acc += product;
    }

    const Element naive_result = matmul::field::Reduce64ForTest(naive_acc);

    std::array<Element, 5> a;
    std::array<Element, 5> b;
    a.fill(matmul::field::MODULUS - 1);
    b.fill(matmul::field::MODULUS - 1);

    BOOST_CHECK_NE(naive_result, 5U);
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), a.size()), 5U);
}

BOOST_AUTO_TEST_CASE(field_naive_accumulation_two_products_wrong)
{
    const uint64_t sum = 2ULL * static_cast<uint64_t>(matmul::field::MODULUS - 1) * (matmul::field::MODULUS - 1);

    std::array<Element, 2> a;
    std::array<Element, 2> b;
    a.fill(matmul::field::MODULUS - 1);
    b.fill(matmul::field::MODULUS - 1);

    BOOST_CHECK_EQUAL(matmul::field::Reduce64ForTest(sum), 2U);
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), a.size()), 2U);
}

BOOST_AUTO_TEST_CASE(from_oracle_pinned_tv1)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 0), 1432335981U);
}

BOOST_AUTO_TEST_CASE(from_oracle_pinned_tv2)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 1), 1134348657U);
}

BOOST_AUTO_TEST_CASE(from_oracle_pinned_tv3)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 7), 2147021205U);
}

BOOST_AUTO_TEST_CASE(from_oracle_pinned_tv4)
{
    const uint256 seed = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 42), 1287506798U);
}

// TEST: from_oracle_rejection_boundary
BOOST_AUTO_TEST_CASE(from_oracle_retry_preimage_format)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");

    std::vector<uint8_t> preimage0(seed.begin(), seed.end());
    uint8_t zero[4];
    WriteLE32(zero, 0);
    preimage0.insert(preimage0.end(), zero, zero + 4);
    const auto hash0 = Sha256(preimage0);
    BOOST_CHECK_EQUAL(HexStr(hash0), "6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e");

    std::vector<uint8_t> preimage1(seed.begin(), seed.end());
    uint8_t index_le[4];
    uint8_t retry1_le[4];
    WriteLE32(index_le, 0);
    WriteLE32(retry1_le, 1);
    preimage1.insert(preimage1.end(), index_le, index_le + 4);
    preimage1.insert(preimage1.end(), retry1_le, retry1_le + 4);
    const auto hash1 = Sha256(preimage1);
    BOOST_CHECK_EQUAL(HexStr(hash1), "4aefeea7a0bb3e887dfac5aba09fea61faaf95a48c1229186e9a671ed4738520");
    BOOST_CHECK_EQUAL(ReadLE32(hash1.data()) & matmul::field::MODULUS, 669970250U);

    std::vector<uint8_t> preimage2(seed.begin(), seed.end());
    uint8_t retry2_le[4];
    WriteLE32(retry2_le, 2);
    preimage2.insert(preimage2.end(), index_le, index_le + 4);
    preimage2.insert(preimage2.end(), retry2_le, retry2_le + 4);
    const auto hash2 = Sha256(preimage2);
    BOOST_CHECK_EQUAL(HexStr(hash2), "7d4b807e3471ee3bffc75392607322b2b9a7226132ff0301d8dce3243cfa03c8");
    BOOST_CHECK_EQUAL(ReadLE32(hash2.data()) & matmul::field::MODULUS, 2122337149U);
}

BOOST_AUTO_TEST_CASE(from_seed_pinned_2x2)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const std::vector<Element> m = FromSeedFlat(seed, 2);
    BOOST_REQUIRE_EQUAL(m.size(), 4U);
    BOOST_CHECK_EQUAL(m[0], 1432335981U);
    BOOST_CHECK_EQUAL(m[1], 1134348657U);
    BOOST_CHECK_EQUAL(m[2], 428617384U);
    BOOST_CHECK_EQUAL(m[3], 258375063U);
}

BOOST_AUTO_TEST_CASE(from_seed_row_major_indexing)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const std::vector<Element> m = FromSeedFlat(seed, 4);
    BOOST_CHECK_EQUAL(m[4], matmul::field::from_oracle(seed, 1 * 4 + 0));
    BOOST_CHECK_EQUAL(m[11], matmul::field::from_oracle(seed, 2 * 4 + 3));
}

BOOST_AUTO_TEST_CASE(from_seed_domain_separation_a_b)
{
    const uint256 seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const uint256 seed_b = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    const std::vector<Element> a = FromSeedFlat(seed_a, 4);
    const std::vector<Element> b = FromSeedFlat(seed_b, 4);
    BOOST_CHECK(a != b);
    BOOST_CHECK_NE(a[0], b[0]);
}

// TEST: cross_platform_pinned_test_vector
BOOST_AUTO_TEST_CASE(from_seed_cross_platform_consistency)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const std::vector<Element> m = FromSeedFlat(seed, 4);
    BOOST_REQUIRE_EQUAL(m.size(), 16U);
    BOOST_CHECK_EQUAL(m[0], 1432335981U);
    BOOST_CHECK_EQUAL(m[1], 1134348657U);
    BOOST_CHECK_EQUAL(m[2], 428617384U);
    BOOST_CHECK_EQUAL(m[3], 258375063U);
}

BOOST_AUTO_TEST_CASE(from_oracle_extra_vectors_zero_seed)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 100), 1689924282U);
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 255), 140522425U);
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 1000), 370943536U);
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 65535), 484788800U);
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, std::numeric_limits<uint32_t>::max()), 752357001U);
}

BOOST_AUTO_TEST_CASE(from_oracle_extra_vectors_nonzero_seed)
{
    const uint256 seed = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    const uint256 other_seed = ParseUint256("c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735");
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 0), 360032607U);
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 1), 154360646U);
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 100), 124997740U);
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(seed, 999), 1912486207U);
    BOOST_CHECK_EQUAL(matmul::field::from_oracle(other_seed, 12345), 732050367U);
}

BOOST_AUTO_TEST_CASE(dot_all_max_len4_vector)
{
    std::array<Element, 4> a;
    std::array<Element, 4> b;
    a.fill(matmul::field::MODULUS - 1);
    b.fill(matmul::field::MODULUS - 1);
    BOOST_CHECK_EQUAL(matmul::field::dot(a.data(), b.data(), a.size()), 4U);
}

BOOST_AUTO_TEST_SUITE_END()
