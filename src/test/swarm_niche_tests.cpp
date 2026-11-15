// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_niche.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_niche_tests, BasicTestingSetup)

static modelnet::SwarmNicheCompare SameNiche()
{
    modelnet::SwarmNicheCompare compare;
    compare.left_niche = "vision";
    compare.right_niche = "vision";
    compare.want_compare = false;
    return compare;
}

BOOST_AUTO_TEST_CASE(empty_left_niche_is_niche)
{
    modelnet::SwarmNicheCompare compare = SameNiche();
    compare.left_niche.clear();
    std::string err = "prior";
    const modelnet::SwarmNicheResult result = modelnet::SwarmNoteNiche(compare, err);
    BOOST_CHECK(!result.compared);
    BOOST_CHECK_EQUAL(result.code, "NICHE");
    BOOST_CHECK_EQUAL(err, "NICHE");
}

BOOST_AUTO_TEST_CASE(empty_right_niche_is_niche)
{
    modelnet::SwarmNicheCompare compare = SameNiche();
    compare.right_niche.clear();
    std::string err = "prior";
    const modelnet::SwarmNicheResult result = modelnet::SwarmNoteNiche(compare, err);
    BOOST_CHECK(!result.compared);
    BOOST_CHECK_EQUAL(result.code, "NICHE");
    BOOST_CHECK_EQUAL(err, "NICHE");
}

BOOST_AUTO_TEST_CASE(empty_niches_win_over_want_compare)
{
    modelnet::SwarmNicheCompare compare = SameNiche();
    compare.left_niche.clear();
    compare.right_niche = "language";
    compare.want_compare = true;
    std::string err = "prior";
    const modelnet::SwarmNicheResult result = modelnet::SwarmNoteNiche(compare, err);
    BOOST_CHECK(!result.compared);
    BOOST_CHECK_EQUAL(result.code, "NICHE");
    BOOST_CHECK_EQUAL(err, "NICHE");
}

BOOST_AUTO_TEST_CASE(different_niches_are_separate_even_when_want_compare)
{
    modelnet::SwarmNicheCompare compare = SameNiche();
    compare.right_niche = "language";
    compare.want_compare = true;
    std::string err = "prior";
    const modelnet::SwarmNicheResult result = modelnet::SwarmNoteNiche(compare, err);
    BOOST_CHECK(!result.compared);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(want_compare_on_the_same_niche_is_held)
{
    modelnet::SwarmNicheCompare compare = SameNiche();
    compare.want_compare = true;
    std::string err = "prior";
    const modelnet::SwarmNicheResult result = modelnet::SwarmNoteNiche(compare, err);
    BOOST_CHECK(!result.compared);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(same_niche_without_compare_is_noted)
{
    modelnet::SwarmNicheCompare compare = SameNiche();
    std::string err = "prior";
    const modelnet::SwarmNicheResult result = modelnet::SwarmNoteNiche(compare, err);
    BOOST_CHECK(!result.compared);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
