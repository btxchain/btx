// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_pareto.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_pareto_tests, BasicTestingSetup)

static modelnet::SwarmPareto SameNiche()
{
    modelnet::SwarmPareto pareto;
    pareto.candidate_id = "cand-1";
    pareto.niche = "vision";
    pareto.other_niche = "vision";
    pareto.want_rank = false;
    return pareto;
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_pareto)
{
    modelnet::SwarmPareto pareto = SameNiche();
    pareto.candidate_id.clear();
    std::string err = "prior";
    const modelnet::SwarmParetoResult result = modelnet::SwarmNotePareto(pareto, err);
    BOOST_CHECK(!result.ranked);
    BOOST_CHECK_EQUAL(result.code, "PARETO");
    BOOST_CHECK_EQUAL(err, "PARETO");
}

BOOST_AUTO_TEST_CASE(empty_niche_is_pareto)
{
    modelnet::SwarmPareto pareto = SameNiche();
    pareto.niche.clear();
    std::string err = "prior";
    const modelnet::SwarmParetoResult result = modelnet::SwarmNotePareto(pareto, err);
    BOOST_CHECK(!result.ranked);
    BOOST_CHECK_EQUAL(result.code, "PARETO");
    BOOST_CHECK_EQUAL(err, "PARETO");
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_wins_over_want_rank)
{
    modelnet::SwarmPareto pareto = SameNiche();
    pareto.candidate_id.clear();
    pareto.other_niche = "speech";
    pareto.want_rank = true;
    std::string err = "prior";
    const modelnet::SwarmParetoResult result = modelnet::SwarmNotePareto(pareto, err);
    BOOST_CHECK(!result.ranked);
    BOOST_CHECK_EQUAL(result.code, "PARETO");
    BOOST_CHECK_EQUAL(err, "PARETO");
}

BOOST_AUTO_TEST_CASE(different_niches_are_separate_even_when_want_rank)
{
    modelnet::SwarmPareto pareto = SameNiche();
    pareto.niche = "vision";
    pareto.other_niche = "speech";
    pareto.want_rank = true;
    std::string err = "prior";
    const modelnet::SwarmParetoResult result = modelnet::SwarmNotePareto(pareto, err);
    BOOST_CHECK(!result.ranked);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(want_rank_on_the_same_niche_is_held)
{
    modelnet::SwarmPareto pareto = SameNiche();
    pareto.want_rank = true;
    std::string err = "prior";
    const modelnet::SwarmParetoResult result = modelnet::SwarmNotePareto(pareto, err);
    BOOST_CHECK(!result.ranked);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(same_niche_without_rank_is_noted)
{
    modelnet::SwarmPareto pareto = SameNiche();
    std::string err = "prior";
    const modelnet::SwarmParetoResult result = modelnet::SwarmNotePareto(pareto, err);
    BOOST_CHECK(!result.ranked);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
