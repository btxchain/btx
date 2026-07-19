// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/matmul_v4_fast_exact.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(matmul_v4_fast_exact_tests, BasicTestingSetup)

namespace {

std::vector<int32_t> Reference(const std::vector<int8_t>& a, const std::vector<int8_t>& b,
                               uint32_t rows, uint32_t inner, uint32_t cols)
{
    std::vector<int32_t> out(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t k = 0; k < inner; ++k) {
            for (uint32_t j = 0; j < cols; ++j) {
                out[static_cast<size_t>(i) * cols + j] +=
                    static_cast<int32_t>(a[static_cast<size_t>(i) * inner + k]) *
                    static_cast<int32_t>(b[static_cast<size_t>(k) * cols + j]);
            }
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(rectangular_matches_classical)
{
    constexpr uint32_t rows = 8, inner = 6, cols = 10;
    std::vector<int8_t> a(static_cast<size_t>(rows) * inner);
    std::vector<int8_t> b(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < a.size(); ++i) {
        a[i] = static_cast<int8_t>(static_cast<int>((i * 17) % 25) - 12);
    }
    for (size_t i = 0; i < b.size(); ++i) {
        b[i] = static_cast<int8_t>(static_cast<int>((i * 11) % 13) - 6);
    }
    std::vector<int32_t> got;
    BOOST_REQUIRE(matmul::v4::fast_exact::GemmS8S8Strassen1(a, b, rows, inner, cols, got));
    BOOST_CHECK(got == Reference(a, b, rows, inner, cols));
}

BOOST_AUTO_TEST_CASE(lt_range_boundary_matches_classical)
{
    constexpr uint32_t n = 8;
    std::vector<int8_t> a(n * n, 48);
    std::vector<int8_t> b(n * n, 6);
    std::vector<int32_t> got;
    BOOST_REQUIRE(matmul::v4::fast_exact::GemmS8S8Strassen1(a, b, n, n, n, got));
    BOOST_CHECK(got == Reference(a, b, n, n, n));
}

BOOST_AUTO_TEST_CASE(fails_closed_on_s8_transform_overflow_or_odd_shape)
{
    std::vector<int8_t> a(16, -128);
    std::vector<int8_t> b(16, 1);
    std::vector<int32_t> out;
    BOOST_CHECK(!matmul::v4::fast_exact::GemmS8S8Strassen1(a, b, 4, 4, 4, out));
    BOOST_CHECK(out.empty());

    a.assign(15, 1);
    b.assign(15, 1);
    BOOST_CHECK(!matmul::v4::fast_exact::GemmS8S8Strassen1(a, b, 3, 5, 3, out));
    BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_SUITE_END()
