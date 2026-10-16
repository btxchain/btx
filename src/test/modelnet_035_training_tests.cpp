// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/training_evidence.h>
#include <modelnet/training_profile.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_training_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fixture_covers_0_4)
{
    using namespace modelnet;
    const FixtureResult result = RunReferenceFixture(FrozenReferenceProfile());
    BOOST_CHECK(result.ok);
    BOOST_CHECK(result.code.empty());
    BOOST_CHECK_EQUAL(result.start_state, "s0");
    BOOST_CHECK_EQUAL(result.final_state, "s4");
    BOOST_REQUIRE_EQUAL(result.steps.size(), 4U);
    BOOST_REQUIRE_EQUAL(result.intervals.size(), 4U);

    const unsigned char expect_bytes[] = {86, 187, 47, 178};
    for (uint64_t step = 0; step < 4; ++step) {
        BOOST_CHECK_EQUAL(result.steps[step].index, step);
        BOOST_CHECK_EQUAL(result.steps[step].byte, expect_bytes[step]);
        BOOST_CHECK(result.steps[step].covered);
        const Interval& interval = result.intervals[step];
        BOOST_CHECK_EQUAL(interval.start_inclusive, step);
        BOOST_CHECK_EQUAL(interval.end_exclusive, step + 1);
        BOOST_CHECK_EQUAL(interval.start_state, "s" + std::to_string(step));
        BOOST_CHECK_EQUAL(interval.end_state, "s" + std::to_string(step + 1));
        BOOST_CHECK_EQUAL(interval.profile, "EXACT_CHECKS");
        BOOST_CHECK_EQUAL(interval.rng, REFERENCE_RNG);
        BOOST_CHECK_EQUAL(interval.optimizer, REFERENCE_OPTIMIZER);
        BOOST_CHECK_EQUAL(interval.data_cursor, REFERENCE_DATA_CURSOR);
        BOOST_CHECK_EQUAL(interval.ancestry, "fixture-root");
        BOOST_CHECK(!interval.publisher_only);
        BOOST_CHECK(Independent(interval));
    }
    BOOST_CHECK(FullReplayCoverage(4, result.start_state, result.final_state, result.intervals));

    const FixtureResult again = RunReferenceFixture(FrozenReferenceProfile());
    BOOST_REQUIRE_EQUAL(again.steps.size(), result.steps.size());
    for (size_t i = 0; i < result.steps.size(); ++i) {
        BOOST_CHECK_EQUAL(again.steps[i].byte, result.steps[i].byte);
    }
}

BOOST_AUTO_TEST_CASE(mutated_rng_rejected)
{
    using namespace modelnet;
    const FixtureResult mutated = MutatedRngRejected();
    BOOST_CHECK(!mutated.ok);
    BOOST_CHECK_EQUAL(mutated.code, "BTX035_RNG");
    BOOST_CHECK(mutated.steps.empty());
    BOOST_CHECK(mutated.intervals.empty());
    BOOST_CHECK(!FullReplayCoverage(4, "s0", "s4", mutated.intervals));

    ReferenceProfile optimizer = FrozenReferenceProfile();
    optimizer.optimizer = "fixture-optimizer-mutated";
    const FixtureResult opt = RunReferenceFixture(optimizer);
    BOOST_CHECK(!opt.ok);
    BOOST_CHECK_EQUAL(opt.code, "BTX035_RNG");
    BOOST_CHECK(opt.steps.empty());
    BOOST_CHECK(opt.intervals.empty());

    ReferenceProfile cursor = FrozenReferenceProfile();
    cursor.data_cursor = "fixture-data-cursor-mutated";
    const FixtureResult cur = RunReferenceFixture(cursor);
    BOOST_CHECK(!cur.ok);
    BOOST_CHECK_EQUAL(cur.code, "BTX035_RNG");
    BOOST_CHECK(cur.intervals.empty());

    ReferenceProfile renamed = FrozenReferenceProfile();
    renamed.name = "SAMPLE";
    const FixtureResult profile = RunReferenceFixture(renamed);
    BOOST_CHECK(!profile.ok);
    BOOST_CHECK_EQUAL(profile.code, "BTX035_PROFILE");
    BOOST_CHECK(profile.steps.empty());
    BOOST_CHECK(profile.intervals.empty());
}

BOOST_AUTO_TEST_SUITE_END()
