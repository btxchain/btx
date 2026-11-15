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

BOOST_FIXTURE_TEST_SUITE(swarm_generation_promote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unqualified_candidate_is_not_graduated)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", "nonce", err));
    const std::string id = gen.candidate_id();

    BOOST_CHECK(!gen.Promote(id, err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK(!gen.promoted(id));
    BOOST_CHECK(!gen.realm_promoted());
    BOOST_CHECK(!gen.exact_replay_admitted());
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");
    BOOST_CHECK(!gen.broadcast());
    BOOST_CHECK_EQUAL(gen.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(qualified_candidate_receives_a_certificate)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    const std::string id = Qualify(gen, "nonce-p");

    BOOST_CHECK(gen.Promote(id, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gen.promoted(id));
    BOOST_CHECK(gen.Promote(id, err));
    BOOST_CHECK(!gen.realm_promoted());
    BOOST_CHECK(!gen.exact_replay_admitted());
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");
    BOOST_CHECK(gen.bytes_moved() == 0);
    BOOST_CHECK(gen.atoms_moved() == 0);
}

BOOST_AUTO_TEST_CASE(specialist_does_not_replace_general_stable)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    const std::string id = Qualify(gen, "nonce-s");

    BOOST_CHECK(!gen.KeepSpecialist("", id, err));
    BOOST_CHECK_EQUAL(err, "SPECIALIST");
    BOOST_CHECK_EQUAL(gen.specialist_count(), 0U);
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");

    BOOST_CHECK(gen.KeepSpecialist("ocr", id, err));
    BOOST_CHECK_EQUAL(gen.specialist_count(), 1U);
    BOOST_CHECK(gen.KeepSpecialist("general/stable", id, err));
    BOOST_CHECK_EQUAL(gen.specialist_count(), 2U);
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");
    BOOST_CHECK(gen.active("general/stable").empty());
    BOOST_CHECK(!gen.realm_promoted());
}

BOOST_AUTO_TEST_SUITE_END()
