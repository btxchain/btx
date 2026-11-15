// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/swarm_familyadmit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_familyadmit_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(duplicate_peer_is_replay_and_keeps_the_first_family)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-2", "fam-2", true, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(a_different_peer_is_not_a_replay)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(plane.Admit("peer-b", "fam-2", "fam-2", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.admitted("peer-b"));
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-b"), "fam-2");
    BOOST_REQUIRE(plane.admitted_count() == 2);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-b"));
}

BOOST_AUTO_TEST_CASE(a_bad_second_attempt_does_not_replace_the_family)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "fam-9", true, err));
    BOOST_REQUIRE_EQUAL(err, "FALSE_COMPAT");
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE(plane.admitted_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "fam-1", false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_ADMITTED");
    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE(plane.admitted_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "", "fam-1", true, err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
