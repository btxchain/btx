// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_generation_evaluate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(refused_reports_store_nothing_and_do_not_qualify)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", "nonce", err));
    const std::string id = gen.candidate_id();

    BOOST_CHECK(!gen.Evaluate(id, "ada", "ada", "train", "train", true, true, true, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(gen.report_count(id), 0U);
    BOOST_CHECK(!gen.qualified(id));

    BOOST_CHECK(!gen.Evaluate(id, "ada", "bea", "train", "train", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_QUORUM");
    BOOST_CHECK_EQUAL(gen.report_count(id), 0U);

    BOOST_CHECK(!gen.Evaluate(id, "ada", "bea", "train", "vision", true, false, false, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(gen.report_count(id), 0U);

    BOOST_CHECK(!gen.Evaluate(id, "ada", "bea", "train", "vision", false, true, false, err));
    BOOST_CHECK_EQUAL(err, "SAFETY");
    BOOST_CHECK_EQUAL(gen.report_count(id), 0U);

    BOOST_CHECK(!gen.Evaluate(id, "ada", "bea", "train", "vision", false, false, true, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK_EQUAL(gen.report_count(id), 0U);
    BOOST_CHECK(!gen.qualified(id));

    BOOST_CHECK(gen.Evaluate(id, "ada", "bea", "train", "vision", false, false, false, err));
    BOOST_CHECK_EQUAL(gen.report_count(id), 1U);
    BOOST_CHECK(!gen.qualified(id));

    BOOST_CHECK(gen.Evaluate(id, "ada", "cy", "train", "audio", false, false, false, err));
    BOOST_CHECK_EQUAL(gen.report_count(id), 2U);
    BOOST_CHECK(gen.qualified(id));
}

BOOST_AUTO_TEST_CASE(two_independent_reports_qualify_and_one_does_not)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", "nonce", err));
    const std::string id = gen.candidate_id();

    BOOST_CHECK(gen.Evaluate(id, "ada", "bea", "train", "vision", false, false, false, err));
    BOOST_CHECK(gen.Evaluate(id, "ada", "bea", "train", "audio", false, false, false, err));
    BOOST_CHECK_EQUAL(gen.report_count(id), 2U);
    BOOST_CHECK(!gen.qualified(id));

    BOOST_REQUIRE(gen.Produce("parent", "recipe", "weights", "nonce-b", err));
    const std::string same_domain = gen.candidate_id();
    BOOST_CHECK(gen.Evaluate(same_domain, "ada", "bea", "train", "vision", false, false, false, err));
    BOOST_CHECK(gen.Evaluate(same_domain, "ada", "cy", "train", "vision", false, false, false, err));
    BOOST_CHECK_EQUAL(gen.report_count(same_domain), 2U);
    BOOST_CHECK(!gen.qualified(same_domain));

    BOOST_CHECK(gen.Evaluate(same_domain, "ada", "dee", "train", "audio", false, false, false, err));
    BOOST_CHECK(gen.qualified(same_domain));
    BOOST_CHECK(!gen.qualified(id));
    BOOST_CHECK(!gen.realm_promoted());
    BOOST_CHECK(!gen.exact_replay_admitted());
}

BOOST_AUTO_TEST_SUITE_END()
