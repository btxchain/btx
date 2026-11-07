// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_generation_continue_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(continue_without_an_adopted_head_leaves_the_parent)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(!gen.Continue(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(gen.parent().empty());
    BOOST_CHECK_EQUAL(gen.cycle(), 0);

    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", "nonce", err));
    const std::string id = gen.candidate_id();
    BOOST_REQUIRE(gen.Evaluate(id, "ada", "bea", "train", "vision", false, false, false, err));
    BOOST_REQUIRE(gen.Evaluate(id, "ada", "cy", "train", "audio", false, false, false, err));
    BOOST_REQUIRE(gen.Stage("code/stable", id, "follow", err));
    BOOST_CHECK(!gen.Continue(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(gen.parent().empty());
    BOOST_CHECK_EQUAL(gen.cycle(), 0);
    BOOST_CHECK_EQUAL(gen.staged("code/stable"), id);
    BOOST_CHECK(gen.active("code/stable").empty());
}

BOOST_AUTO_TEST_CASE(full_generation_adopts_code_stable_and_continue_advances_the_parent)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");
    BOOST_CHECK(!gen.eligible());
    BOOST_CHECK(!gen.running());
    BOOST_CHECK(!gen.launched());
    BOOST_CHECK(!gen.gpu());
    BOOST_CHECK(!gen.broadcast());
    BOOST_CHECK(!gen.realm_promoted());
    BOOST_CHECK(!gen.exact_replay_admitted());
    BOOST_CHECK(gen.bytes_moved() == 0);
    BOOST_CHECK(gen.atoms_moved() == 0);
    BOOST_CHECK_EQUAL(gen.automatic_spend(), "0");

    BOOST_REQUIRE(gen.Identify("slow-decode", err));
    BOOST_REQUIRE(gen.Propose("try-recipe", err));
    BOOST_REQUIRE(gen.Eligible(true, true, err));
    BOOST_REQUIRE(gen.Allocate(8, 25, err));
    BOOST_CHECK_EQUAL(gen.exploration_slots(), 2);
    BOOST_REQUIRE(gen.SelectTask("try-recipe", true, err));
    BOOST_CHECK(!gen.Execute(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!gen.running());
    BOOST_CHECK_EQUAL(gen.training_count(), 1U);

    BOOST_REQUIRE(gen.Produce("base-parent", "recipe", "weights", "nonce-1", err));
    const std::string id = gen.candidate_id();
    BOOST_REQUIRE(gen.VerifyProvenance(id, "base-parent", err));
    BOOST_REQUIRE(gen.verified(id));
    BOOST_REQUIRE(gen.Evaluate(id, "ada", "bea", "train", "vision", false, false, false, err));
    BOOST_CHECK(!gen.qualified(id));
    BOOST_REQUIRE(gen.Evaluate(id, "ada", "cy", "train", "audio", false, false, false, err));
    BOOST_REQUIRE(gen.qualified(id));
    BOOST_REQUIRE(gen.KeepNegative("diverged", err));
    BOOST_REQUIRE(gen.Compare(id, "base-parent", true, err));
    BOOST_CHECK(!gen.forked());
    BOOST_REQUIRE(gen.Promote(id, err));
    BOOST_REQUIRE(gen.promoted(id));
    BOOST_REQUIRE(gen.KeepSpecialist("ocr", id, err));
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");
    BOOST_CHECK(!gen.Distribute(id, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(gen.bytes_moved() == 0);
    BOOST_CHECK(gen.verified(id));

    BOOST_REQUIRE(gen.Stage("code/stable", id, "follow", err));
    BOOST_CHECK_EQUAL(gen.staged("code/stable"), id);
    BOOST_CHECK(gen.active("code/stable").empty());
    BOOST_CHECK(gen.active("general/stable").empty());
    BOOST_REQUIRE(gen.Adopt("code/stable", err));
    BOOST_CHECK_EQUAL(gen.active("code/stable"), id);
    BOOST_CHECK(gen.staged("code/stable").empty());
    BOOST_CHECK_EQUAL(gen.rollback_count(), 1U);

    BOOST_CHECK(gen.Continue(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gen.parent(), id);
    BOOST_CHECK_EQUAL(gen.active("code/stable"), id);
    BOOST_CHECK_EQUAL(gen.cycle(), 1);
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");
    BOOST_CHECK_EQUAL(gen.negative_count(), 1U);
    BOOST_CHECK(gen.negative_kept("diverged"));
    BOOST_CHECK_EQUAL(gen.specialist_count(), 1U);
    BOOST_CHECK(!gen.realm_promoted());
    BOOST_CHECK(!gen.exact_replay_admitted());
    BOOST_CHECK(!gen.launched());
    BOOST_CHECK(!gen.gpu());
    BOOST_CHECK(!gen.broadcast());
    BOOST_CHECK(!gen.running());
    BOOST_CHECK(gen.bytes_moved() == 0);
    BOOST_CHECK(gen.atoms_moved() == 0);
    BOOST_CHECK_EQUAL(gen.automatic_spend(), "0");

    BOOST_CHECK(!gen.Identify("slow-decode", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gen.weakness_count(), 1U);
    BOOST_CHECK(gen.Identify("next-gap", err));
    BOOST_CHECK_EQUAL(gen.weakness_count(), 2U);
    BOOST_CHECK_EQUAL(gen.parent(), id);
    BOOST_CHECK_EQUAL(gen.cycle(), 1);
}

BOOST_AUTO_TEST_CASE(code_stable_is_distinct_from_general_stable)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", "nonce-c", err));
    const std::string code_id = gen.candidate_id();
    BOOST_REQUIRE(gen.Evaluate(code_id, "ada", "bea", "train", "vision", false, false, false, err));
    BOOST_REQUIRE(gen.Evaluate(code_id, "ada", "cy", "train", "audio", false, false, false, err));

    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", "nonce-g", err));
    const std::string general_id = gen.candidate_id();
    BOOST_REQUIRE(gen.Evaluate(general_id, "ada", "bea", "train", "vision", false, false, false, err));
    BOOST_REQUIRE(gen.Evaluate(general_id, "ada", "cy", "train", "audio", false, false, false, err));

    BOOST_REQUIRE(gen.Stage("general/stable", general_id, "follow", err));
    BOOST_REQUIRE(gen.Adopt("general/stable", err));
    BOOST_REQUIRE(gen.Stage("code/stable", code_id, "follow", err));
    BOOST_REQUIRE(gen.Adopt("code/stable", err));

    BOOST_CHECK_EQUAL(gen.active("code/stable"), code_id);
    BOOST_CHECK_EQUAL(gen.active("general/stable"), general_id);
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");
    BOOST_CHECK(gen.Continue(err));
    BOOST_CHECK_EQUAL(gen.parent(), code_id);
    BOOST_CHECK_EQUAL(gen.cycle(), 1);
    BOOST_CHECK_EQUAL(gen.general_stable(), "general/stable");
}

BOOST_AUTO_TEST_SUITE_END()
