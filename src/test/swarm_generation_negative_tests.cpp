// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

std::string Qualify(modelnet::SwarmGenerationEngine& gen, const std::string& nonce)
{
    std::string err;
    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", nonce, err));
    const std::string id = gen.candidate_id();
    BOOST_REQUIRE(gen.Evaluate(id, "ada", "bea", "train", "vision", false, false, false, err));
    BOOST_REQUIRE(gen.Evaluate(id, "ada", "cy", "train", "audio", false, false, false, err));
    BOOST_REQUIRE(gen.qualified(id));
    return id;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_generation_negative_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_negative_stores_nothing)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(!gen.KeepNegative("", err));
    BOOST_CHECK_EQUAL(err, "NEGATIVE");
    BOOST_CHECK_EQUAL(gen.negative_count(), 0U);
    BOOST_CHECK(!gen.negative_kept(""));
}

BOOST_AUTO_TEST_CASE(negative_result_survives_promotion)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(gen.KeepNegative("diverged", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gen.negative_count(), 1U);
    BOOST_CHECK(gen.negative_kept("diverged"));

    const std::string id = Qualify(gen, "nonce-n");
    BOOST_CHECK(gen.Promote(id, err));
    BOOST_CHECK(gen.promoted(id));
    BOOST_CHECK_EQUAL(gen.negative_count(), 1U);
    BOOST_CHECK(gen.negative_kept("diverged"));
    BOOST_CHECK(!gen.realm_promoted());
}

BOOST_AUTO_TEST_SUITE_END()
