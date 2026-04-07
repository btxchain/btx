// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matrix.h>

#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <array>
#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

matmul::Matrix MatrixFromRows(const std::array<std::array<uint32_t, 4>, 4>& rows)
{
    matmul::Matrix out(4, 4);
    for (uint32_t r = 0; r < 4; ++r) {
        for (uint32_t c = 0; c < 4; ++c) {
            out.at(r, c) = rows[r][c];
        }
    }
    return out;
}

matmul::Matrix RandomMatrix(FastRandomContext& rng, uint32_t n)
{
    matmul::Matrix out(n, n);
    for (uint32_t r = 0; r < n; ++r) {
        for (uint32_t c = 0; c < n; ++c) {
            out.at(r, c) = matmul::field::from_uint32(rng.rand32());
        }
    }
    return out;
}

matmul::Matrix RectMatrix(uint32_t rows, uint32_t cols, uint32_t seed)
{
    FastRandomContext rng{true};
    rng.rand32();
    for (uint32_t i = 0; i < seed; ++i) {
        rng.rand32();
    }

    matmul::Matrix out(rows, cols);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            out.at(r, c) = matmul::field::from_uint32(rng.rand32());
        }
    }
    return out;
}

class ScopedEnvVar
{
public:
    ScopedEnvVar(const char* name, const char* value) : m_name(name)
    {
        const char* existing = std::getenv(name);
        if (existing != nullptr) {
            m_original = std::string(existing);
        }
        if (value != nullptr) {
            setenv(name, value, 1);
        } else {
            unsetenv(name);
        }
    }

    ~ScopedEnvVar()
    {
        if (m_original.has_value()) {
            setenv(m_name, m_original->c_str(), 1);
        } else {
            unsetenv(m_name);
        }
    }

private:
    const char* m_name;
    std::optional<std::string> m_original;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_matrix_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(matrix_create_zero)
{
    matmul::Matrix m(3, 5);
    BOOST_CHECK_EQUAL(m.rows(), 3U);
    BOOST_CHECK_EQUAL(m.cols(), 5U);

    for (uint32_t r = 0; r < m.rows(); ++r) {
        for (uint32_t c = 0; c < m.cols(); ++c) {
            BOOST_CHECK_EQUAL(m.at(r, c), 0U);
        }
    }

    for (uint32_t r = 0; r < m.rows(); ++r) {
        for (uint32_t c = 0; c < m.cols(); ++c) {
            m.at(r, c) = r * m.cols() + c + 1;
        }
    }

    for (uint32_t idx = 0; idx < m.rows() * m.cols(); ++idx) {
        BOOST_CHECK_EQUAL(m.data()[idx], idx + 1);
    }
}

BOOST_AUTO_TEST_CASE(matrix_block_decomposition_roundtrip)
{
    constexpr uint32_t n = 8;
    constexpr uint32_t b = 4;

    matmul::Matrix src(n, n);
    for (uint32_t r = 0; r < n; ++r) {
        for (uint32_t c = 0; c < n; ++c) {
            src.at(r, c) = r * n + c;
        }
    }

    matmul::Matrix rebuilt(n, n);
    for (uint32_t bi = 0; bi < n / b; ++bi) {
        for (uint32_t bj = 0; bj < n / b; ++bj) {
            rebuilt.set_block(bi, bj, b, src.block(bi, bj, b));
        }
    }

    BOOST_CHECK(rebuilt == src);
}

BOOST_AUTO_TEST_CASE(matrix_const_block_view_reads_parent_storage)
{
    matmul::Matrix src(4, 4);
    for (uint32_t r = 0; r < src.rows(); ++r) {
        for (uint32_t c = 0; c < src.cols(); ++c) {
            src.at(r, c) = (r * src.cols()) + c + 1;
        }
    }

    const auto view = src.block_view(1, 1, 2);
    BOOST_CHECK_EQUAL(view.rows(), 2U);
    BOOST_CHECK_EQUAL(view.cols(), 2U);
    BOOST_CHECK_EQUAL(view.at(0, 0), src.at(2, 2));
    BOOST_CHECK_EQUAL(view.at(0, 1), src.at(2, 3));
    BOOST_CHECK_EQUAL(view.at(1, 0), src.at(3, 2));
    BOOST_CHECK_EQUAL(view.at(1, 1), src.at(3, 3));
}

BOOST_AUTO_TEST_CASE(matrix_mutable_block_view_writes_through_parent_storage)
{
    matmul::Matrix src(4, 4);
    for (uint32_t r = 0; r < src.rows(); ++r) {
        for (uint32_t c = 0; c < src.cols(); ++c) {
            src.at(r, c) = 0;
        }
    }

    auto view = src.mutable_block_view(0, 1, 2);
    view.at(0, 0) = 123;
    view.at(1, 1) = 456;

    BOOST_CHECK_EQUAL(src.at(0, 2), 123U);
    BOOST_CHECK_EQUAL(src.at(1, 3), 456U);

    src.at(0, 2) = 789;
    BOOST_CHECK_EQUAL(view.at(0, 0), 789U);
}

BOOST_AUTO_TEST_CASE(matrix_add_sub_inverse)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 4);
    const matmul::Matrix b = RandomMatrix(rng, 4);
    const matmul::Matrix c = (a + b) - b;

    BOOST_CHECK(c == a);
}

BOOST_AUTO_TEST_CASE(matrix_mul_identity)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 4);
    const matmul::Matrix i = matmul::Identity(4);

    BOOST_CHECK((a * i) == a);
    BOOST_CHECK((i * a) == a);
}

BOOST_AUTO_TEST_CASE(matrix_mul_known_vectors)
{
    const matmul::Matrix a = MatrixFromRows({
        std::array<uint32_t, 4>{1432335981U, 1134348657U, 428617384U, 258375063U},
        std::array<uint32_t, 4>{1089501034U, 987465407U, 604491976U, 2147021205U},
        std::array<uint32_t, 4>{974841017U, 671155217U, 1571078102U, 1743245017U},
        std::array<uint32_t, 4>{1246901555U, 770304034U, 491675067U, 1908005739U},
    });

    const matmul::Matrix expected = MatrixFromRows({
        std::array<uint32_t, 4>{2044825919U, 1782425592U, 819673979U, 1878615671U},
        std::array<uint32_t, 4>{1061851023U, 250182751U, 1997566097U, 136404410U},
        std::array<uint32_t, 4>{1879172505U, 2076395095U, 841696212U, 2067639972U},
        std::array<uint32_t, 4>{1852408301U, 1424127172U, 2033812109U, 325086830U},
    });

    BOOST_CHECK((a * a) == expected);
}

BOOST_AUTO_TEST_CASE(matrix_mul_associative)
{
    FastRandomContext rng{true};

    for (int i = 0; i < 8; ++i) {
        const matmul::Matrix a = RandomMatrix(rng, 3);
        const matmul::Matrix b = RandomMatrix(rng, 3);
        const matmul::Matrix c = RandomMatrix(rng, 3);

        BOOST_CHECK(((a * b) * c) == (a * (b * c)));
    }
}

BOOST_AUTO_TEST_CASE(matrix_mul_blocked_rectangular_matches_operator)
{
    const matmul::Matrix lhs = RectMatrix(5, 7, 17);
    const matmul::Matrix rhs = RectMatrix(7, 6, 91);

    const matmul::Matrix via_operator = lhs * rhs;
    const matmul::Matrix via_blocked = matmul::MultiplyBlocked(lhs, rhs, 3);
    BOOST_CHECK(via_blocked == via_operator);
}

BOOST_AUTO_TEST_CASE(matrix_mul_blocked_rejects_zero_tile_size)
{
    const matmul::Matrix lhs = RectMatrix(2, 2, 5);
    const matmul::Matrix rhs = RectMatrix(2, 2, 6);
    BOOST_CHECK_THROW(matmul::MultiplyBlocked(lhs, rhs, 0), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(matrix_mul_blocked_parallel_override_matches_operator)
{
    const matmul::Matrix lhs = RectMatrix(64, 64, 37);
    const matmul::Matrix rhs = RectMatrix(64, 64, 73);
    const matmul::Matrix via_operator = lhs * rhs;

    {
        ScopedEnvVar threads("BTX_MATMUL_BLOCKED_MULTIPLY_THREADS", "4");
        const matmul::Matrix via_blocked = matmul::MultiplyBlocked(lhs, rhs, 8);
        BOOST_CHECK(via_blocked == via_operator);
    }
    {
        ScopedEnvVar threads("BTX_MATMUL_BLOCKED_MULTIPLY_THREADS", "1");
        const matmul::Matrix via_blocked = matmul::MultiplyBlocked(lhs, rhs, 8);
        BOOST_CHECK(via_blocked == via_operator);
    }
    {
        ScopedEnvVar threads("BTX_MATMUL_BLOCKED_MULTIPLY_THREADS", "invalid");
        const matmul::Matrix via_blocked = matmul::MultiplyBlocked(lhs, rhs, 8);
        BOOST_CHECK(via_blocked == via_operator);
    }
}

BOOST_AUTO_TEST_CASE(matrix_content_hash_deterministic)
{
    FastRandomContext rng{true};
    matmul::Matrix a = RandomMatrix(rng, 8);

    const uint256 hash1 = a.ContentHash();
    const uint256 hash2 = a.ContentHash();
    BOOST_CHECK_EQUAL(hash1, hash2);

    a.at(0, 0) = matmul::field::add(a.at(0, 0), 1);
    const uint256 hash3 = a.ContentHash();
    BOOST_CHECK_NE(hash1, hash3);
}

BOOST_AUTO_TEST_CASE(matrix_from_seed_deterministic)
{
    const uint256 seed = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const matmul::Matrix a = matmul::FromSeed(seed, 8);
    const matmul::Matrix b = matmul::FromSeed(seed, 8);

    BOOST_CHECK(a == b);

    BOOST_CHECK_EQUAL(a.at(0, 0), 1432335981U);
    BOOST_CHECK_EQUAL(a.at(0, 1), 1134348657U);
    BOOST_CHECK_EQUAL(a.at(0, 2), 428617384U);
    BOOST_CHECK_EQUAL(a.at(0, 3), 258375063U);
    BOOST_CHECK_EQUAL(a.at(0, 4), 1089501034U);
    BOOST_CHECK_EQUAL(a.at(0, 5), 987465407U);
    BOOST_CHECK_EQUAL(a.at(0, 6), 604491976U);
    BOOST_CHECK_EQUAL(a.at(0, 7), 2147021205U);
}

BOOST_AUTO_TEST_CASE(matrix_from_seed_differs)
{
    const uint256 seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const uint256 seed_b = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");

    const matmul::Matrix a = matmul::FromSeed(seed_a, 8);
    const matmul::Matrix b = matmul::FromSeed(seed_b, 8);

    BOOST_CHECK(!(a == b));
    BOOST_CHECK_NE(a.ContentHash(), b.ContentHash());
}

BOOST_AUTO_TEST_CASE(shared_from_seed_reuses_cached_matrix)
{
    const uint256 seed = ParseUint256("4b0f5d513fb82ec3b8cc5fb704f6da4761af6a0e0e523ac0049a8a7f2ad8d7fe");

    const auto first = matmul::SharedFromSeed(seed, 16);
    const auto second = matmul::SharedFromSeed(seed, 16);
    const auto different_dim = matmul::SharedFromSeed(seed, 8);

    BOOST_REQUIRE(first);
    BOOST_REQUIRE(second);
    BOOST_REQUIRE(different_dim);
    BOOST_CHECK_EQUAL(first.get(), second.get());
    BOOST_CHECK_NE(first.get(), different_dim.get());
    BOOST_CHECK(*first == matmul::FromSeed(seed, 16));
}

BOOST_AUTO_TEST_CASE(matrix_memory_stats_track_live_bytes_and_lifetimes)
{
    matmul::ResetMatrixMemoryStats();
    const auto baseline = matmul::ProbeMatrixMemoryStats();
    const uint64_t baseline_live = baseline.live_bytes;
    const uint64_t matrix_bytes = static_cast<uint64_t>(8U * 8U * sizeof(matmul::field::Element));

    {
        matmul::Matrix a(8, 8);
        auto stats = matmul::ProbeMatrixMemoryStats();
        BOOST_CHECK_EQUAL(stats.live_bytes, baseline_live + matrix_bytes);
        BOOST_CHECK_EQUAL(stats.matrices_constructed, 1U);

        matmul::Matrix b(a);
        stats = matmul::ProbeMatrixMemoryStats();
        BOOST_CHECK_EQUAL(stats.live_bytes, baseline_live + (2U * matrix_bytes));
        BOOST_CHECK_EQUAL(stats.matrices_constructed, 2U);
        BOOST_CHECK_EQUAL(stats.matrices_destroyed, 0U);
        BOOST_CHECK_GE(stats.peak_live_bytes, baseline_live + (2U * matrix_bytes));
    }

    const auto after = matmul::ProbeMatrixMemoryStats();
    BOOST_CHECK_EQUAL(after.live_bytes, baseline_live);
    BOOST_CHECK_EQUAL(after.matrices_constructed, after.matrices_destroyed);
}

BOOST_AUTO_TEST_SUITE_END()
