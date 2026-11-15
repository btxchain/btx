// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_generation_allocate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bad_slots_and_explore_store_nothing)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK_EQUAL(gen.exploration_slots(), 0);

    BOOST_CHECK(!gen.Allocate(0, 50, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 0);

    BOOST_CHECK(!gen.Allocate(-3, 50, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 0);

    BOOST_CHECK(!gen.Allocate(0, 101, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");

    BOOST_CHECK(!gen.Allocate(4, -1, err));
    BOOST_CHECK_EQUAL(err, "EXPLORE");
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 0);

    BOOST_CHECK(!gen.Allocate(4, 101, err));
    BOOST_CHECK_EQUAL(err, "EXPLORE");
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 0);
}

BOOST_AUTO_TEST_CASE(exploration_share_is_integer_division)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(gen.Allocate(10, 0, err));
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 0);

    BOOST_CHECK(gen.Allocate(10, 100, err));
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 10);

    BOOST_CHECK(gen.Allocate(10, 25, err));
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 2);

    BOOST_CHECK(gen.Allocate(7, 50, err));
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 3);

    BOOST_CHECK(gen.Allocate(1, 99, err));
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 0);

    BOOST_CHECK(gen.Allocate(7, 50, err));
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 3);
    BOOST_CHECK(!gen.Allocate(0, 50, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 3);
    BOOST_CHECK(!gen.Allocate(7, 101, err));
    BOOST_CHECK_EQUAL(err, "EXPLORE");
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 3);
}

BOOST_AUTO_TEST_SUITE_END()
