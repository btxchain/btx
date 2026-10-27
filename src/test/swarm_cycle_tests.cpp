// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_cycle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(an_expired_cohort_and_an_unverified_root_do_not_proceed)
{
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAdmitCohortMember(1000, 1000, true, true, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK(!modelnet::SwarmAdmitCohortMember(100, 1000, false, true, err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK(modelnet::SwarmAdmitCohortMember(100, 1000, true, true, err));

    modelnet::SwarmManifestRoot root;
    root.children.push_back({"aa", false});
    root.children.push_back({"bb", false});
    BOOST_CHECK(!modelnet::SwarmBindManifestRoot(root, {"aa"}, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!root.usable);
    BOOST_CHECK(!root.bytes_streamed);
    BOOST_REQUIRE(modelnet::SwarmBindManifestRoot(root, {"aa", "bb"}, err));
    BOOST_CHECK(root.usable);
    BOOST_CHECK(!root.bytes_streamed);

    BOOST_CHECK(!modelnet::SwarmStartTraining(true, true, err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(modelnet::SwarmStartTraining(true, false, err));

    modelnet::SwarmCycle cycle;
    cycle.parent_id = "gen-1";
    BOOST_CHECK(!modelnet::SwarmAdvanceCycle(cycle, "gen-2", false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(cycle.parent_id, "gen-1");
    BOOST_REQUIRE(modelnet::SwarmAdvanceCycle(cycle, "gen-2", true, err));
    BOOST_CHECK_EQUAL(cycle.parent_id, "gen-2");
    BOOST_CHECK_EQUAL(cycle.cycle, 1);
    BOOST_REQUIRE(modelnet::SwarmAdvanceCycle(cycle, "gen-3", true, err));
    BOOST_CHECK_EQUAL(cycle.parent_id, "gen-3");
    BOOST_CHECK_EQUAL(cycle.cycle, 2);
}

BOOST_AUTO_TEST_SUITE_END()
