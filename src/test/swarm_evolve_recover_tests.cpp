// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_evolve_recover_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(recover_drops_the_coordinator_and_keeps_earned_atoms)
{
    modelnet::SwarmGeneration gen("subject-a", "baseline-parent", "coordinator-1");
    std::string err = "prior";
    BOOST_CHECK_EQUAL(gen.CoordinatorId(), "coordinator-1");
    BOOST_CHECK_EQUAL(gen.BytesMoved(), 0);
    BOOST_CHECK(!gen.Mined());
    BOOST_REQUIRE(gen.Pay(7, err));
    BOOST_REQUIRE(gen.Pay(8, err));
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 15);
    BOOST_CHECK_EQUAL(gen.AutomaticSpend(), "0");
    BOOST_CHECK(!gen.Broadcast());

    BOOST_REQUIRE(gen.Recover(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gen.CoordinatorId().empty());
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 15);
    BOOST_CHECK_EQUAL(gen.BytesMoved(), 0);
    BOOST_CHECK(!gen.Mined());
    BOOST_CHECK_EQUAL(gen.AutomaticSpend(), "0");
    BOOST_CHECK(!gen.Broadcast());

    BOOST_REQUIRE(gen.Recover(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gen.CoordinatorId().empty());
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 15);
    BOOST_CHECK_EQUAL(gen.BytesMoved(), 0);
    BOOST_CHECK(!gen.Mined());
}

BOOST_AUTO_TEST_SUITE_END()
