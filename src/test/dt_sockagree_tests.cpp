// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_sockagree/dt_sockagree.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectIdle(const modelnet::DtSockAgree& agree)
{
    BOOST_CHECK(!agree.launched());
    BOOST_CHECK(!agree.gpu());
    BOOST_CHECK(!agree.broadcast());
    BOOST_CHECK(!agree.hardware_qualified());
    BOOST_CHECK_EQUAL(agree.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(agree.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.ranks(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(std::string(agree.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_sockagree_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(three_versus_four_disagrees)
{
    modelnet::DtSockAgree agree;
    std::string err;
    ExpectIdle(agree);
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!agree.Compare(static_cast<int64_t>(3), static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "DISAGREE");
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(16));

    BOOST_CHECK(!agree.Compare(static_cast<int64_t>(3), static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "DISAGREE");
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(16));

    BOOST_CHECK(!agree.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(16));
    BOOST_CHECK_EQUAL(agree.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.ranks(), static_cast<int64_t>(2));
    BOOST_CHECK(!agree.hardware_qualified());
    BOOST_CHECK_EQUAL(std::string(agree.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    ExpectIdle(agree);
}

BOOST_AUTO_TEST_CASE(equal_fives_agree_then_replay)
{
    modelnet::DtSockAgree agree;
    std::string err;
    BOOST_CHECK(agree.Compare(static_cast<int64_t>(5), static_cast<int64_t>(5), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(16));

    BOOST_CHECK(!agree.Compare(static_cast<int64_t>(5), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(16));

    BOOST_CHECK(!agree.Compare(static_cast<int64_t>(9), static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(16));

    BOOST_CHECK(!agree.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(agree.agreed());
    BOOST_CHECK_EQUAL(agree.bytes_moved(), static_cast<int64_t>(16));
    BOOST_CHECK_EQUAL(agree.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(agree.ranks(), static_cast<int64_t>(2));
    BOOST_CHECK(!agree.hardware_qualified());
    BOOST_CHECK_EQUAL(std::string(agree.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    ExpectIdle(agree);
}

BOOST_AUTO_TEST_SUITE_END()
