// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_generation_fork_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(incompatible_compare_forks_and_does_not_average)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights-left", "nonce-l", err));
    const std::string left = gen.candidate_id();
    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights-right", "nonce-r", err));
    const std::string right = gen.candidate_id();

    BOOST_CHECK(!gen.forked());
    BOOST_CHECK(!gen.Compare(left, right, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK(gen.forked());
    BOOST_CHECK_EQUAL(gen.candidate_id(), right);
    BOOST_CHECK(!gen.verified(left));
    BOOST_CHECK(!gen.verified(right));

    BOOST_CHECK(gen.Compare(left, right, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gen.forked());
    BOOST_CHECK_EQUAL(gen.candidate_id(), right);
}

BOOST_AUTO_TEST_CASE(compatible_compare_stores_without_a_fork)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", "nonce", err));
    const std::string id = gen.candidate_id();

    BOOST_CHECK(gen.Compare(id, "parent", true, err));
    BOOST_CHECK(!gen.forked());
    BOOST_CHECK_EQUAL(gen.candidate_id(), id);
    BOOST_CHECK(gen.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
