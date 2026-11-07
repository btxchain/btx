// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/swarm_disputestay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_disputestay_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_open_of_the_same_id_is_replay)
{
    modelnet::SwarmDisputeStay plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("dispute-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened("dispute-1"));
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("dispute-1", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.opened("dispute-1"));
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!plane.Open("dispute-1", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_id_is_dispute_before_replay)
{
    modelnet::SwarmDisputeStay plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("dispute-1", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Open("", err));
    BOOST_REQUIRE_EQUAL(err, "DISPUTE");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(!plane.settled());
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_id_is_stored)
{
    modelnet::SwarmDisputeStay plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("dispute-1", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(plane.Open("dispute-2", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Open("dispute-1", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.stored_id("dispute-2") == "dispute-2");
    BOOST_REQUIRE(plane.open_count() == 2);
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("dispute-1", 3, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.stored_id("dispute-2") == "dispute-2");
    BOOST_REQUIRE(plane.open_count() == 2);
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
