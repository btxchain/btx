// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_gradagree/dt_gradagree.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectIdle(const modelnet::DtGradAgree& agree)
{
    BOOST_CHECK(!agree.launched());
    BOOST_CHECK(!agree.gpu());
    BOOST_CHECK(!agree.broadcast());
    BOOST_CHECK(!agree.hardware_qualified());
    BOOST_CHECK_EQUAL(agree.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(agree.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(std::string(agree.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_gradagree_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rank_two_rejected_and_one_rank_is_missing)
{
    modelnet::DtGradAgree agree;
    std::string err;
    ExpectIdle(agree);
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(0));

    BOOST_CHECK(!agree.Submit(static_cast<int64_t>(2), static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "RANK");
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(0));
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(2)), static_cast<int64_t>(0));

    BOOST_CHECK(!agree.Submit(static_cast<int64_t>(-1), static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "RANK");
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(0));

    BOOST_CHECK(agree.Submit(static_cast<int64_t>(0), static_cast<int64_t>(5), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(0)), static_cast<int64_t>(5));
    BOOST_CHECK(!agree.Agree(err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(1));

    BOOST_CHECK(!agree.Submit(static_cast<int64_t>(2), static_cast<int64_t>(8), err));
    BOOST_CHECK_EQUAL(err, "RANK");
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(0)), static_cast<int64_t>(5));
    BOOST_CHECK(!agree.agreed());
    ExpectIdle(agree);

    modelnet::DtGradAgree rank_one;
    BOOST_CHECK(rank_one.Submit(static_cast<int64_t>(1), static_cast<int64_t>(5), err));
    BOOST_CHECK(!rank_one.Agree(err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(!rank_one.agreed());
    BOOST_CHECK_EQUAL(rank_one.submitted(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(rank_one.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!rank_one.hardware_qualified());
}

BOOST_AUTO_TEST_CASE(values_three_and_four_disagree)
{
    modelnet::DtGradAgree agree;
    std::string err;
    BOOST_CHECK(agree.Submit(static_cast<int64_t>(0), static_cast<int64_t>(3), err));
    BOOST_CHECK(agree.Submit(static_cast<int64_t>(1), static_cast<int64_t>(4), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(0)), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(1)), static_cast<int64_t>(4));

    BOOST_CHECK(!agree.Agree(err));
    BOOST_CHECK_EQUAL(err, "DISAGREE");
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(2));

    BOOST_CHECK(!agree.Agree(err));
    BOOST_CHECK_EQUAL(err, "DISAGREE");
    BOOST_CHECK(!agree.agreed());

    BOOST_CHECK(!agree.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(agree.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!agree.hardware_qualified());
    BOOST_CHECK_EQUAL(std::string(agree.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    ExpectIdle(agree);
}

BOOST_AUTO_TEST_CASE(equal_fives_agree_replay_and_second_agree_unchanged)
{
    modelnet::DtGradAgree agree;
    std::string err;
    BOOST_CHECK(agree.Submit(static_cast<int64_t>(0), static_cast<int64_t>(5), err));
    BOOST_CHECK(!agree.Submit(static_cast<int64_t>(0), static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(0)), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(1));
    BOOST_CHECK(!agree.agreed());

    BOOST_CHECK(agree.Submit(static_cast<int64_t>(1), static_cast<int64_t>(5), err));
    BOOST_CHECK(!agree.Submit(static_cast<int64_t>(1), static_cast<int64_t>(6), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(1)), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(2));

    BOOST_CHECK(agree.Agree(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(agree.agreed());
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(0)), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(agree.gradient(static_cast<int64_t>(1)), static_cast<int64_t>(5));

    BOOST_CHECK(!agree.Agree(err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK(agree.agreed());
    BOOST_CHECK_EQUAL(agree.submitted(), static_cast<int64_t>(2));

    BOOST_CHECK(!agree.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(agree.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!agree.hardware_qualified());
    BOOST_CHECK_EQUAL(std::string(agree.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    ExpectIdle(agree);
}

BOOST_AUTO_TEST_SUITE_END()
