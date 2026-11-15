// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/swarm_familyadmit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_familyadmit_compat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_or_family_is_family_and_stores_nothing)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.family_of("peer-a").empty());
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(!plane.Admit("", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(!plane.admitted(""));
    BOOST_REQUIRE(plane.family_of("").empty());
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.connected(""));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "", "fam-1", true, err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.family_of("peer-a").empty());
    BOOST_REQUIRE(plane.admitted_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("", "", "", true, err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(plane.admitted_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("", "fam-1", "other-fam", true, err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(plane.admitted_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "", "", false, err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(false_compatibility_stores_nothing)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "fam-2", true, err));
    BOOST_REQUIRE_EQUAL(err, "FALSE_COMPAT");
    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.family_of("peer-a").empty());
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "", true, err));
    BOOST_REQUIRE_EQUAL(err, "FALSE_COMPAT");
    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.admitted_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "Fam-1", true, err));
    BOOST_REQUIRE_EQUAL(err, "FALSE_COMPAT");
    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.family_of("peer-a").empty());
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(missing_compatibility_claim_is_not_admitted)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Admit("peer-a", "fam-1", "fam-1", false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_ADMITTED");
    BOOST_REQUIRE(!plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.family_of("peer-a").empty());
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-b", "fam-1", "fam-2", false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_ADMITTED");
    BOOST_REQUIRE(!plane.admitted("peer-b"));
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.connected("peer-b"));
}

BOOST_AUTO_TEST_CASE(refused_attempt_leaves_a_stored_peer_in_place)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("peer-a"));

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("peer-b", "fam-1", "fam-9", true, err));
    BOOST_REQUIRE_EQUAL(err, "FALSE_COMPAT");
    BOOST_REQUIRE(!plane.admitted("peer-b"));
    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("peer-b"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
