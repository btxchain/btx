// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/limits.h>
#include <modelnet/swarm_disputestay/swarm_disputestay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_disputestay_atoms_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(atoms_zero_on_a_known_id_is_held_and_adds_nothing)
{
    modelnet::SwarmDisputeStay plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("dispute-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened("dispute-1"));
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("dispute-1", 0, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.opened("dispute-1"));
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE(plane.settled() == modelnet::kSwarmDisputeStaySettled);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(plane.atoms_moved() == modelnet::kSwarmDisputeStayAtomsMoved);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("dispute-1", 0, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(atoms_below_one_and_above_one_leave_the_total_at_zero)
{
    modelnet::SwarmDisputeStay plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("dispute-1", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("dispute-1", -1, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("dispute-1", modelnet::kSwarmDisputeStayMinAtoms, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("dispute-1", 100, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(atoms_zero_on_an_unknown_id_is_held_and_stores_nothing)
{
    modelnet::SwarmDisputeStay plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("dispute-1", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Settle("missing", 0, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.opened("missing"));
    BOOST_REQUIRE(plane.stored_id("missing").empty());
    BOOST_REQUIRE(plane.opened("dispute-1"));
    BOOST_REQUIRE(plane.stored_id("dispute-1") == "dispute-1");
    BOOST_REQUIRE(plane.open_count() == 1);
    BOOST_REQUIRE(!plane.settled());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
