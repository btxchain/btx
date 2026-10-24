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

BOOST_FIXTURE_TEST_SUITE(swarm_generation_stage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(policy_and_qualification_gate_the_staged_head)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    const std::string id = Qualify(gen, "nonce-st");

    BOOST_CHECK(!gen.Stage("code/stable", id, "hold", err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK(gen.staged("code/stable").empty());
    BOOST_CHECK(gen.active("code/stable").empty());

    BOOST_CHECK(!gen.Stage("code/stable", "missing", "follow", err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK(gen.staged("code/stable").empty());

    BOOST_CHECK(!gen.Stage("code/stable", "missing", "pin", err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");

    BOOST_CHECK(gen.Stage("code/stable", id, "pin", err));
    BOOST_CHECK(gen.staged("code/stable").empty());
    BOOST_CHECK(gen.active("code/stable").empty());

    BOOST_CHECK(gen.Stage("code/stable", id, "follow", err));
    BOOST_CHECK_EQUAL(gen.staged("code/stable"), id);
    BOOST_CHECK(gen.active("code/stable").empty());
    BOOST_CHECK(gen.staged("general/stable").empty());
    BOOST_CHECK(gen.active("general/stable").empty());

    BOOST_CHECK(gen.Stage("code/stable", id, "refuse", err));
    BOOST_CHECK_EQUAL(gen.staged("code/stable"), id);
    BOOST_CHECK(gen.active("code/stable").empty());
}

BOOST_AUTO_TEST_CASE(adopt_moves_the_staged_head_and_records_rollback)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    const std::string id = Qualify(gen, "nonce-ad");

    BOOST_CHECK(!gen.Adopt("code/stable", err));
    BOOST_CHECK_EQUAL(err, "NOT_STAGED");
    BOOST_CHECK_EQUAL(gen.rollback_count(), 0U);
    BOOST_CHECK(gen.active("code/stable").empty());

    BOOST_REQUIRE(gen.Stage("code/stable", id, "follow", err));
    BOOST_CHECK(gen.Adopt("code/stable", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gen.active("code/stable"), id);
    BOOST_CHECK(gen.staged("code/stable").empty());
    BOOST_CHECK_EQUAL(gen.rollback_count(), 1U);
    BOOST_CHECK(gen.active("general/stable").empty());
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");

    BOOST_CHECK(!gen.Adopt("code/stable", err));
    BOOST_CHECK_EQUAL(err, "NOT_STAGED");
    BOOST_CHECK_EQUAL(gen.active("code/stable"), id);
    BOOST_CHECK_EQUAL(gen.rollback_count(), 1U);
    BOOST_CHECK(!gen.realm_promoted());
    BOOST_CHECK(!gen.exact_replay_admitted());
}

BOOST_AUTO_TEST_SUITE_END()
