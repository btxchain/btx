// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/wide128.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(wide128_tests, BasicTestingSetup)

#ifdef __SIZEOF_INT128__
static btx::wide_detail::Unsigned128 NativeU(btx::U128 v)
{
    btx::wide_detail::Unsigned128 u;
    u.lo = static_cast<uint64_t>(v);
    u.hi = static_cast<uint64_t>(v >> 64);
    return u;
}

static btx::wide_detail::Signed128 NativeI(btx::I128 v)
{
    return btx::wide_detail::Signed128(NativeU(static_cast<btx::U128>(v)));
}

static btx::U128 BitsU(btx::wide_detail::Unsigned128 u)
{
    return (static_cast<btx::U128>(u.hi) << 64) | u.lo;
}

static btx::I128 BitsI(btx::wide_detail::Signed128 s)
{
    return static_cast<btx::I128>((static_cast<btx::U128>(s.hi) << 64) | s.lo);
}

BOOST_AUTO_TEST_CASE(portable_unsigned_matches_native)
{
    const uint64_t samples[] = {0, 1, 2, 61, 63, 64, 65, 96, 127,
                                0xffffffffffffffffull, 0x8000000000000000ull, 123456789};
    for (uint64_t a : samples) {
        for (uint64_t b : samples) {
            const btx::U128 na = a, nb = b;
            const auto pa = btx::wide_detail::Unsigned128(a);
            const auto pb = btx::wide_detail::Unsigned128(b);
            BOOST_CHECK(BitsU(pa + pb) == na + nb);
            BOOST_CHECK(BitsU(pa - pb) == na - nb);
            BOOST_CHECK(BitsU(pa * pb) == na * nb);
            BOOST_CHECK(BitsU(pa & pb) == (na & nb));
            BOOST_CHECK(BitsU(pa | pb) == (na | nb));
            BOOST_CHECK((pa < pb) == (na < nb));
            if (b != 0) {
                BOOST_CHECK(BitsU(pa / pb) == na / nb);
                BOOST_CHECK(BitsU(pa % pb) == na % nb);
            }
            for (int s : {0, 1, 31, 32, 63, 64, 65, 127}) {
                BOOST_CHECK(BitsU(pa << s) == (na << s));
                BOOST_CHECK(BitsU(pa >> s) == (na >> s));
            }
            const btx::U128 wide = (static_cast<btx::U128>(a) << 64) | b;
            const auto folded = NativeU(wide);
            BOOST_CHECK(static_cast<uint64_t>(folded & btx::wide_detail::Unsigned128(0x1fffffffffffffffULL)) ==
                        static_cast<uint64_t>(wide & 0x1fffffffffffffffULL));
            BOOST_CHECK(static_cast<uint64_t>(folded >> 61) == static_cast<uint64_t>(wide >> 61));
        }
    }
}

BOOST_AUTO_TEST_CASE(portable_signed_matches_native)
{
    const int64_t samples[] = {0, 1, -1, 2, -2, 64, -64, 127, -128,
                               INT64_C(0x7fffffffffffffff), INT64_MIN + 1, 1000003, -1000003};
    for (int64_t a : samples) {
        for (int64_t b : samples) {
            const btx::I128 na = a, nb = b;
            const auto pa = btx::wide_detail::Signed128(a);
            const auto pb = btx::wide_detail::Signed128(b);
            BOOST_CHECK(BitsI(pa + pb) == na + nb);
            BOOST_CHECK(BitsI(pa - pb) == na - nb);
            BOOST_CHECK(BitsI(pa * pb) == na * nb);
            BOOST_CHECK(BitsI(-pa) == -na);
            BOOST_CHECK(BitsU(static_cast<btx::wide_detail::Unsigned128>(pa)) == static_cast<btx::U128>(na));
            BOOST_CHECK(BitsU(static_cast<btx::wide_detail::Unsigned128>(-pa)) == static_cast<btx::U128>(-na));
            BOOST_CHECK((pa < pb) == (na < nb));
            BOOST_CHECK((pa >= pb) == (na >= nb));
            BOOST_CHECK((pa != 0) == (na != 0));
            if (b != 0) {
                BOOST_CHECK(BitsI(pa / pb) == na / nb);
                BOOST_CHECK(BitsI(pa % pb) == na % nb);
            }
            if (a >= 0) {
                for (int s : {0, 1, 7, 32, 47}) {
                    BOOST_CHECK(BitsI(pa << s) == (na << s));
                }
            }
            for (int s : {0, 1, 31, 32, 63}) {
                BOOST_CHECK(BitsI(pa >> s) == (na >> s));
            }
        }
    }
    const btx::I128 combined = (static_cast<btx::I128>(uint64_t{0xabcdef}) << 32) | 0x12345678u;
    const auto got = (btx::wide_detail::Signed128(uint64_t{0xabcdef}) << 32) | btx::wide_detail::Signed128(0x12345678u);
    BOOST_CHECK(BitsI(got) == combined);
    BOOST_CHECK(static_cast<uint64_t>(got % btx::wide_detail::Signed128(1000003)) ==
                static_cast<uint64_t>(combined % 1000003));
}
#endif

BOOST_AUTO_TEST_CASE(overflow_helpers_match_wrapping_add)
{
    const uint64_t pairs[][2] = {{0, 0}, {1, 1}, {0xffffffffffffffffull, 1}, {5, 3}, {3, 5}};
    for (const auto& p : pairs) {
        uint64_t sum = 0, diff = 0;
        const bool carry = btx::AddOverflow(p[0], p[1], &sum);
        const bool borrow = btx::SubOverflow(p[0], p[1], &diff);
        BOOST_CHECK_EQUAL(sum, p[0] + p[1]);
        BOOST_CHECK_EQUAL(carry, p[0] + p[1] < p[0]);
        BOOST_CHECK_EQUAL(diff, p[0] - p[1]);
        BOOST_CHECK_EQUAL(borrow, p[0] < p[1]);
    }
}

BOOST_AUTO_TEST_SUITE_END()
