// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/swarm_familyadmit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_familyadmit_admit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(matching_family_stores_the_peer)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.family_of("peer-a").empty());
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(!plane.admitted("peer-b"));
    BOOST_REQUIRE(plane.family_of("peer-b").empty());
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-b"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(two_peers_may_share_one_family)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Admit("peer-b", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.admitted("peer-b"));
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-b"), "fam-1");
    BOOST_REQUIRE(plane.admitted_count() == 2);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-b"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(distinct_families_stay_with_their_peers)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(plane.Admit("peer-b", "fam-2", "fam-2", true, err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-b"), "fam-2");
    BOOST_REQUIRE(plane.admitted_count() == 2);
    BOOST_REQUIRE(!plane.admitted("peer"));
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-b"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.dns_seeds().empty());
}

BOOST_AUTO_TEST_SUITE_END()
