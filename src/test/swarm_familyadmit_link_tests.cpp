// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/swarm_familyadmit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_familyadmit_link_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(connected_is_false_before_and_after_admit)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-b"));
    BOOST_REQUIRE(!plane.connected(""));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.dns_seeds().empty());

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-b"));
    BOOST_REQUIRE(!plane.connected(""));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(false_compatibility_does_not_connect)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "fam-2", true, err));
    BOOST_REQUIRE_EQUAL(err, "FALSE_COMPAT");
    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("fam-2"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.dns_seeds().empty());
}

BOOST_AUTO_TEST_CASE(replay_and_seed_hold_do_not_connect)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(!plane.connected("peer-a"));

    err = "prior";
    BOOST_REQUIRE(!plane.AddSeed("slot-1", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("slot-1"));
    BOOST_REQUIRE(!plane.admitted("slot-1"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
