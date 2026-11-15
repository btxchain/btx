// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchseq.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_watchseq_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(observe_one_then_two_and_stale_one_is_refused)
{
    modelnet::SwarmWatchSeq watch;
    BOOST_CHECK_EQUAL(watch.latest(), 0);
    BOOST_CHECK(!watch.secret_released());

    std::string err = "prior";
    BOOST_CHECK(watch.Observe(1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(watch.latest(), 1);
    BOOST_CHECK(!watch.secret_released());

    err = "prior";
    BOOST_CHECK(watch.Observe(2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(watch.latest(), 2);
    BOOST_CHECK(!watch.secret_released());

    err = "prior";
    BOOST_CHECK(!watch.Observe(1, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(watch.latest(), 2);
    BOOST_CHECK(!watch.secret_released());
}

BOOST_AUTO_TEST_CASE(sequence_below_one_is_sequence)
{
    modelnet::SwarmWatchSeq watch;
    std::string err = "prior";
    BOOST_CHECK(watch.Observe(1, err));
    BOOST_CHECK_EQUAL(watch.latest(), 1);

    err = "prior";
    BOOST_CHECK(!watch.Observe(0, err));
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
    BOOST_CHECK_EQUAL(watch.latest(), 1);

    err = "prior";
    BOOST_CHECK(!watch.Observe(-1, err));
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
    BOOST_CHECK_EQUAL(watch.latest(), 1);
    BOOST_CHECK(!watch.secret_released());
}

BOOST_AUTO_TEST_CASE(equal_sequence_is_replay)
{
    modelnet::SwarmWatchSeq watch;
    std::string err = "prior";
    BOOST_CHECK(watch.Observe(1, err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!watch.Observe(1, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(watch.latest(), 1);
    BOOST_CHECK(!watch.secret_released());
}

BOOST_AUTO_TEST_SUITE_END()
