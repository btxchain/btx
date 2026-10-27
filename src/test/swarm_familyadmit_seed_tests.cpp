// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/swarm_familyadmit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_familyadmit_seed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dns_seeds_start_empty_and_addseed_is_held)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    const std::vector<std::string>& seeds = plane.dns_seeds();
    BOOST_REQUIRE(seeds.empty());
    BOOST_REQUIRE(seeds.size() == 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.connected("slot-1"));

    BOOST_REQUIRE(!plane.AddSeed("slot-1", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.dns_seeds().size() == 0);
    BOOST_REQUIRE(!plane.admitted("slot-1"));
    BOOST_REQUIRE(!plane.connected("slot-1"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.AddSeed("", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.dns_seeds().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.AddSeed("slot-2", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.connected("slot-2"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(admit_does_not_fill_dns_seeds)
{
    modelnet::SwarmFamilyAdmit plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("peer-a", "fam-1", "fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE(plane.dns_seeds().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.AddSeed("slot-1", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.admitted("peer-a"));
    BOOST_REQUIRE_EQUAL(plane.family_of("peer-a"), "fam-1");
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(!plane.connected("peer-a"));
    BOOST_REQUIRE(!plane.connected("slot-1"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
