// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_datasetgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_datasetgate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(withdrawn_grant_does_not_start)
{
    modelnet::SwarmDatasetGate gate;
    std::string err = "prior";

    BOOST_CHECK(!gate.Grant("ds-a", true, true, err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!gate.started("ds-a"));

    err = "prior";
    BOOST_CHECK(!gate.Grant("", true, false, err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!gate.started(""));

    err = "prior";
    BOOST_CHECK(!gate.Grant("ds-a", false, false, err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!gate.started("ds-a"));
}

BOOST_AUTO_TEST_CASE(authorized_grant_starts)
{
    modelnet::SwarmDatasetGate gate;
    std::string err = "prior";

    BOOST_REQUIRE(gate.Grant("ds-a", true, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gate.started("ds-a"));
    BOOST_CHECK(!gate.started("ds-b"));
}

BOOST_AUTO_TEST_CASE(replay_leaves_the_first_row)
{
    modelnet::SwarmDatasetGate gate;
    std::string err = "prior";

    BOOST_REQUIRE(gate.Grant("ds-a", true, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gate.started("ds-a"));

    err = "prior";
    BOOST_CHECK(!gate.Grant("ds-a", true, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(gate.started("ds-a"));

    err = "prior";
    BOOST_CHECK(!gate.Grant("ds-a", true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(gate.started("ds-a"));

    BOOST_REQUIRE(gate.Grant("ds-b", true, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gate.started("ds-a"));
    BOOST_CHECK(gate.started("ds-b"));
}

BOOST_AUTO_TEST_SUITE_END()
