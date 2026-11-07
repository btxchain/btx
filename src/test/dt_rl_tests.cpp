// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_rl/dt_rl.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_rl_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(clipped_group_relative_excludes_incomplete_self_stale_and_duplicates)
{
    modelnet::DtRl rl;
    std::string err;
    BOOST_CHECK_EQUAL(std::string(rl.objective()), "BTX-GRPO-CLIPPED/1");
    BOOST_CHECK_EQUAL(rl.current_version(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(rl.stored_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!rl.Add("", "z", static_cast<int64_t>(1), static_cast<int64_t>(0), 1, true, false, err));
    BOOST_CHECK_EQUAL(err, "GROUP");
    BOOST_CHECK_EQUAL(rl.stored_count(), static_cast<int64_t>(0));

    // One completed sample must not invent a mean.
    BOOST_CHECK(rl.Add("g", "a", static_cast<int64_t>(2), static_cast<int64_t>(5), 1, true, false, err));
    BOOST_CHECK(!rl.Advantage("g", err));
    BOOST_CHECK_EQUAL(err, "GROUP");
    BOOST_CHECK(!rl.has_mean("g"));
    BOOST_CHECK_EQUAL(rl.mean_num("g"), static_cast<int64_t>(0));
    int64_t num = 9;
    int64_t den = 9;
    BOOST_CHECK(!rl.advantage("a", num, den));
    BOOST_CHECK_EQUAL(num, static_cast<int64_t>(9));
    BOOST_CHECK_EQUAL(den, static_cast<int64_t>(9));

    // Incomplete 100 is stored and must not enter the mean.
    BOOST_CHECK(rl.Add("g", "partial", static_cast<int64_t>(100), static_cast<int64_t>(0), 1, false, false, err));
    BOOST_CHECK(rl.has_sample("partial"));
    BOOST_CHECK_EQUAL(rl.reward_of("partial"), static_cast<int64_t>(100));
    BOOST_CHECK(!rl.Advantage("g", err));
    BOOST_CHECK_EQUAL(err, "GROUP");
    BOOST_CHECK_EQUAL(rl.mean_num("g"), static_cast<int64_t>(0));
    BOOST_CHECK(!rl.has_mean("g"));

    BOOST_CHECK(rl.Add("g", "b", static_cast<int64_t>(4), static_cast<int64_t>(9), 1, true, false, err));
    BOOST_CHECK(rl.Advantage("g", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(rl.has_mean("g"));
    BOOST_CHECK_EQUAL(rl.mean_num("g"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(rl.mean_den("g"), static_cast<int64_t>(1));

    BOOST_CHECK(rl.advantage("a", num, den));
    BOOST_CHECK_EQUAL(num, static_cast<int64_t>(-1));
    BOOST_CHECK_EQUAL(den, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(rl.logp_of("a"), static_cast<int64_t>(5));
    BOOST_CHECK(rl.advantage("b", num, den));
    BOOST_CHECK_EQUAL(num, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(den, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(rl.logp_of("b"), static_cast<int64_t>(9));
    int64_t partial_num = 4;
    int64_t partial_den = 4;
    BOOST_CHECK(!rl.advantage("partial", partial_num, partial_den));
    BOOST_CHECK_EQUAL(partial_num, static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(partial_den, static_cast<int64_t>(4));

    // A second pass still ignores the incomplete reward.
    BOOST_CHECK(rl.Advantage("g", err));
    BOOST_CHECK_EQUAL(rl.mean_num("g"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(rl.mean_den("g"), static_cast<int64_t>(1));
    BOOST_CHECK(rl.advantage("a", num, den));
    BOOST_CHECK_EQUAL(num, static_cast<int64_t>(-1));
    BOOST_CHECK(rl.advantage("b", num, den));
    BOOST_CHECK_EQUAL(num, static_cast<int64_t>(1));

    // Another group's equal rewards stay at advantage 0 and do not move g.
    BOOST_CHECK(rl.Add("h", "h1", static_cast<int64_t>(10), static_cast<int64_t>(0), 1, true, false, err));
    BOOST_CHECK(rl.Add("h", "h2", static_cast<int64_t>(10), static_cast<int64_t>(0), 1, true, false, err));
    BOOST_CHECK(rl.Advantage("h", err));
    BOOST_CHECK(rl.advantage("h1", num, den));
    BOOST_CHECK_EQUAL(num, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(den, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(rl.mean_num("g"), static_cast<int64_t>(3));
    BOOST_CHECK(rl.advantage("a", num, den));
    BOOST_CHECK_EQUAL(num, static_cast<int64_t>(-1));

    const int64_t stored = rl.stored_count();
    BOOST_CHECK(!rl.Add("g", "self", static_cast<int64_t>(9), static_cast<int64_t>(0), 1, true, true, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(!rl.has_sample("self"));
    BOOST_CHECK_EQUAL(rl.reward_of("self"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(rl.stored_count(), stored);

    BOOST_CHECK(rl.SetVersion(5));
    BOOST_CHECK_EQUAL(rl.current_version(), static_cast<uint64_t>(5));
    BOOST_CHECK(!rl.SetVersion(4));
    BOOST_CHECK_EQUAL(rl.current_version(), static_cast<uint64_t>(5));

    BOOST_CHECK(!rl.Add("g", "old", static_cast<int64_t>(1), static_cast<int64_t>(0), 2, true, false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK(!rl.has_sample("old"));
    BOOST_CHECK_EQUAL(rl.reward_of("old"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(rl.stored_count(), stored);

    // Lag of 2 is current_version() - 2, which is not below that line.
    BOOST_CHECK(rl.Add("g", "lag", static_cast<int64_t>(1), static_cast<int64_t>(0), 3, true, false, err));
    BOOST_CHECK(rl.has_sample("lag"));
    BOOST_CHECK_EQUAL(rl.version_of("lag"), static_cast<uint64_t>(3));
    BOOST_CHECK_EQUAL(rl.version_of("old"), static_cast<uint64_t>(0));
    BOOST_CHECK_EQUAL(rl.mean_num("g"), static_cast<int64_t>(3));

    BOOST_CHECK(!rl.Add("g", "a", static_cast<int64_t>(99), static_cast<int64_t>(0), 5, true, false, err));
    BOOST_CHECK_EQUAL(err, "DEDUP");
    BOOST_CHECK_EQUAL(rl.reward_of("a"), static_cast<int64_t>(2));
    BOOST_CHECK(!rl.Add("g", "ahead", static_cast<int64_t>(1), static_cast<int64_t>(0), 6, true, false, err));
    BOOST_CHECK_EQUAL(err, "FUTURE");
    BOOST_CHECK_EQUAL(rl.reward_of("ahead"), static_cast<int64_t>(0));

    // Ratio 2.0 is clamped to 1.2. Advantage +1 yields 1.2, within 1e-9.
    const double clipped = rl.Clip(2.0, 1.0, err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK(std::fabs(clipped - 1.2) < 1e-9);
    BOOST_CHECK(rl.advantage("b", num, den));
    const double from_sample = rl.Clip(2.0, static_cast<double>(num) / static_cast<double>(den), err);
    BOOST_CHECK(std::fabs(from_sample - 1.2) < 1e-9);
    // min(2 * -1, 1.2 * -1) is -2. The 1e-9 bound is not widened.
    const double negative = rl.Clip(2.0, -1.0, err);
    BOOST_CHECK(std::fabs(negative - (-2.0)) < 1e-9);
    const double inside = rl.Clip(0.5, 1.0, err);
    BOOST_CHECK(std::fabs(inside - 0.5) < 1e-9);

    BOOST_CHECK(!rl.launched());
    BOOST_CHECK(!rl.gpu());
    BOOST_CHECK(!rl.broadcast());
    BOOST_CHECK_EQUAL(rl.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
