// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_progress/swarm_progress.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::SwarmProgress& progress)
{
    BOOST_CHECK(!progress.killed());
    BOOST_CHECK(!progress.launched());
    BOOST_CHECK(!progress.gpu());
    BOOST_CHECK(!progress.broadcast());
    BOOST_CHECK_EQUAL(progress.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(progress.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_progress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(changed_loss_is_kept)
{
    modelnet::SwarmProgress progress;
    std::string err = "prior";

    BOOST_CHECK(!progress.Sample("", 1000, 1, err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK(!progress.sampled());
    BOOST_CHECK_EQUAL(progress.loss_ppm(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(progress.step(), static_cast<int64_t>(0));

    BOOST_CHECK(!progress.Sample("work", -1, 1, err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK(!progress.sampled());
    BOOST_CHECK(!progress.Sample("work", 1000, -1, err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK(!progress.sampled());

    BOOST_REQUIRE(progress.Sample("work", 1000, 4, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(progress.sampled());
    BOOST_CHECK(!progress.meaningful());
    BOOST_CHECK_EQUAL(progress.loss_ppm(), static_cast<int64_t>(1000));
    BOOST_CHECK_EQUAL(progress.step(), static_cast<int64_t>(4));

    BOOST_REQUIRE(progress.Sample("work", 900, 4, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(progress.meaningful());
    BOOST_CHECK_EQUAL(progress.loss_ppm(), static_cast<int64_t>(900));
    BOOST_CHECK_EQUAL(progress.step(), static_cast<int64_t>(4));

    BOOST_REQUIRE(progress.Sample("work", 900, 5, err));
    BOOST_CHECK_EQUAL(progress.loss_ppm(), static_cast<int64_t>(900));
    BOOST_CHECK_EQUAL(progress.step(), static_cast<int64_t>(5));

    BOOST_CHECK(!progress.Sample("work", 900, 5, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!progress.correcting());
    BOOST_CHECK_EQUAL(progress.loss_ppm(), static_cast<int64_t>(900));
    BOOST_CHECK_EQUAL(progress.step(), static_cast<int64_t>(5));

    BOOST_CHECK(!progress.Sample("work", -5, 6, err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK_EQUAL(progress.loss_ppm(), static_cast<int64_t>(900));
    BOOST_CHECK_EQUAL(progress.step(), static_cast<int64_t>(5));
    ExpectQuiet(progress);
}

BOOST_AUTO_TEST_CASE(three_identical_samples_set_correcting_and_killed_stays_false)
{
    modelnet::SwarmProgress progress;
    std::string err = "prior";

    BOOST_REQUIRE(progress.Sample("work", 50, 1, err));
    BOOST_CHECK(!progress.Sample("work", 50, 1, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!progress.Sample("work", 50, 1, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!progress.correcting());
    BOOST_CHECK(!progress.killed());
    BOOST_CHECK_EQUAL(progress.loss_ppm(), static_cast<int64_t>(50));
    BOOST_CHECK_EQUAL(progress.step(), static_cast<int64_t>(1));

    BOOST_CHECK(!progress.Stall("work", 2, err));
    BOOST_CHECK_EQUAL(err, "PLATEAU");
    BOOST_CHECK(!progress.correcting());
    BOOST_CHECK(!progress.killed());

    BOOST_REQUIRE(progress.Stall("work", 3, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(progress.correcting());
    BOOST_CHECK(!progress.killed());
    ExpectQuiet(progress);

    BOOST_CHECK(!progress.Stall("work", 1, err));
    BOOST_CHECK_EQUAL(err, "PLATEAU");
    BOOST_CHECK(progress.correcting());
    BOOST_CHECK(!progress.killed());
    ExpectQuiet(progress);
}

BOOST_AUTO_TEST_CASE(different_recipe_is_secret_and_keeps_the_first)
{
    modelnet::SwarmProgress progress;
    std::string err = "prior";
    const std::string first = "alpha";
    const std::string other = "beta";

    BOOST_CHECK(!progress.Correct("work", first, err));
    BOOST_CHECK_EQUAL(err, "NOT_CORRECTING");
    BOOST_CHECK(progress.recipe().empty());

    BOOST_REQUIRE(progress.Sample("work", 50, 1, err));
    BOOST_CHECK(!progress.Sample("work", 50, 1, err));
    BOOST_CHECK(!progress.Sample("work", 50, 1, err));
    BOOST_REQUIRE(progress.Stall("work", 3, err));
    BOOST_CHECK(progress.correcting());
    BOOST_CHECK(!progress.killed());

    BOOST_REQUIRE(progress.Correct("work", first, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(progress.recipe(), first);

    BOOST_CHECK(!progress.Correct("work", other, err));
    BOOST_CHECK_EQUAL(err, "SECRET");
    BOOST_CHECK_EQUAL(progress.recipe(), first);
    BOOST_CHECK(!progress.killed());

    BOOST_REQUIRE(progress.Correct("work", first, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(progress.recipe(), first);
    ExpectQuiet(progress);
}

BOOST_AUTO_TEST_SUITE_END()
