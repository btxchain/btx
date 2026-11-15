// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closeout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_closeout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(margin_is_160)
{
    modelnet::SwarmCloseOut closeout;
    BOOST_CHECK_EQUAL(closeout.margin(), 160);
}

BOOST_AUTO_TEST_CASE(shrink_to_10_is_refused)
{
    modelnet::SwarmCloseOut closeout;
    std::string err = "prior";
    BOOST_CHECK(!closeout.Shrink(10, err));
    BOOST_CHECK_EQUAL(err, "MARGIN");
    BOOST_CHECK_EQUAL(closeout.margin(), 160);
}

BOOST_AUTO_TEST_CASE(shrink_to_160_clears_err_and_keeps_margin)
{
    modelnet::SwarmCloseOut closeout;
    std::string err = "prior";
    BOOST_CHECK(closeout.Shrink(160, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(closeout.margin(), 160);
}

BOOST_AUTO_TEST_CASE(shrink_below_one_is_refused)
{
    modelnet::SwarmCloseOut closeout;
    std::string err = "prior";
    BOOST_CHECK(!closeout.Shrink(0, err));
    BOOST_CHECK_EQUAL(err, "MARGIN");
    BOOST_CHECK_EQUAL(closeout.margin(), 160);

    err = "prior";
    BOOST_CHECK(!closeout.Shrink(-1, err));
    BOOST_CHECK_EQUAL(err, "MARGIN");
    BOOST_CHECK_EQUAL(closeout.margin(), 160);
}

BOOST_AUTO_TEST_SUITE_END()
