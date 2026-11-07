// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_explore.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_explore_tests, BasicTestingSetup)

static modelnet::SwarmExplore NotedExplore()
{
    modelnet::SwarmExplore explore;
    explore.pool_id = "pool-local";
    explore.slots = 5;
    explore.exploration_ppm = 200000;
    explore.candidate_count = 3;
    explore.want_assign = false;
    return explore;
}

static void ExpectAssignedStaysFalse(const modelnet::SwarmExploreResult& result)
{
    BOOST_CHECK(!result.assigned);
}

static void ExpectCountsZero(const modelnet::SwarmExploreResult& result)
{
    BOOST_CHECK_EQUAL(result.first, 0);
    BOOST_CHECK_EQUAL(result.second, 0);
    BOOST_CHECK_EQUAL(result.third, 0);
}

static void ExpectIllustrationCounts(const modelnet::SwarmExploreResult& result)
{
    BOOST_CHECK_EQUAL(result.first, 1);
    BOOST_CHECK_EQUAL(result.second, 2);
    BOOST_CHECK_EQUAL(result.third, 2);
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_explore)
{
    modelnet::SwarmExplore explore = NotedExplore();
    explore.pool_id.clear();
    explore.want_assign = true;
    std::string err = "prior";
    const modelnet::SwarmExploreResult result = modelnet::SwarmNoteExplore(explore, err);
    ExpectAssignedStaysFalse(result);
    ExpectCountsZero(result);
    BOOST_CHECK_EQUAL(result.code, "EXPLORE");
    BOOST_CHECK_EQUAL(err, "EXPLORE");
}

BOOST_AUTO_TEST_CASE(slots_below_one_is_explore)
{
    std::string err = "prior";
    modelnet::SwarmExplore zero_slots = NotedExplore();
    zero_slots.slots = 0;
    zero_slots.want_assign = true;
    const modelnet::SwarmExploreResult zero = modelnet::SwarmNoteExplore(zero_slots, err);
    ExpectAssignedStaysFalse(zero);
    ExpectCountsZero(zero);
    BOOST_CHECK_EQUAL(zero.code, "EXPLORE");
    BOOST_CHECK_EQUAL(err, "EXPLORE");

    modelnet::SwarmExplore negative_slots = NotedExplore();
    negative_slots.slots = -1;
    negative_slots.want_assign = true;
    const modelnet::SwarmExploreResult negative = modelnet::SwarmNoteExplore(negative_slots, err);
    ExpectAssignedStaysFalse(negative);
    ExpectCountsZero(negative);
    BOOST_CHECK_EQUAL(negative.code, "EXPLORE");
    BOOST_CHECK_EQUAL(err, "EXPLORE");
}

BOOST_AUTO_TEST_CASE(exploration_ppm_out_of_range_is_explore)
{
    std::string err = "prior";
    modelnet::SwarmExplore negative_ppm = NotedExplore();
    negative_ppm.exploration_ppm = -1;
    negative_ppm.want_assign = true;
    const modelnet::SwarmExploreResult negative = modelnet::SwarmNoteExplore(negative_ppm, err);
    ExpectAssignedStaysFalse(negative);
    ExpectCountsZero(negative);
    BOOST_CHECK_EQUAL(negative.code, "EXPLORE");
    BOOST_CHECK_EQUAL(err, "EXPLORE");

    modelnet::SwarmExplore above_ppm = NotedExplore();
    above_ppm.exploration_ppm = 1000001;
    above_ppm.want_assign = true;
    const modelnet::SwarmExploreResult above = modelnet::SwarmNoteExplore(above_ppm, err);
    ExpectAssignedStaysFalse(above);
    ExpectCountsZero(above);
    BOOST_CHECK_EQUAL(above.code, "EXPLORE");
    BOOST_CHECK_EQUAL(err, "EXPLORE");
}

BOOST_AUTO_TEST_CASE(candidate_count_below_one_is_explore)
{
    std::string err = "prior";
    modelnet::SwarmExplore zero_count = NotedExplore();
    zero_count.candidate_count = 0;
    zero_count.want_assign = true;
    const modelnet::SwarmExploreResult zero = modelnet::SwarmNoteExplore(zero_count, err);
    ExpectAssignedStaysFalse(zero);
    ExpectCountsZero(zero);
    BOOST_CHECK_EQUAL(zero.code, "EXPLORE");
    BOOST_CHECK_EQUAL(err, "EXPLORE");

    modelnet::SwarmExplore negative_count = NotedExplore();
    negative_count.candidate_count = -2;
    const modelnet::SwarmExploreResult negative = modelnet::SwarmNoteExplore(negative_count, err);
    ExpectAssignedStaysFalse(negative);
    ExpectCountsZero(negative);
    BOOST_CHECK_EQUAL(negative.code, "EXPLORE");
    BOOST_CHECK_EQUAL(err, "EXPLORE");
}

BOOST_AUTO_TEST_CASE(explore_wins_over_illustration_and_want_assign)
{
    modelnet::SwarmExplore explore = NotedExplore();
    explore.pool_id.clear();
    explore.slots = 4;
    explore.want_assign = true;
    std::string err = "prior";
    const modelnet::SwarmExploreResult result = modelnet::SwarmNoteExplore(explore, err);
    ExpectAssignedStaysFalse(result);
    ExpectCountsZero(result);
    BOOST_CHECK_EQUAL(result.code, "EXPLORE");
    BOOST_CHECK_EQUAL(err, "EXPLORE");
}

BOOST_AUTO_TEST_CASE(other_splits_are_illustration)
{
    std::string err = "prior";
    modelnet::SwarmExplore other_slots = NotedExplore();
    other_slots.slots = 4;
    const modelnet::SwarmExploreResult slots = modelnet::SwarmNoteExplore(other_slots, err);
    ExpectAssignedStaysFalse(slots);
    ExpectCountsZero(slots);
    BOOST_CHECK_EQUAL(slots.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");

    modelnet::SwarmExplore other_ppm = NotedExplore();
    other_ppm.exploration_ppm = 200001;
    const modelnet::SwarmExploreResult ppm = modelnet::SwarmNoteExplore(other_ppm, err);
    ExpectAssignedStaysFalse(ppm);
    ExpectCountsZero(ppm);
    BOOST_CHECK_EQUAL(ppm.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");

    modelnet::SwarmExplore other_count = NotedExplore();
    other_count.candidate_count = 4;
    const modelnet::SwarmExploreResult count = modelnet::SwarmNoteExplore(other_count, err);
    ExpectAssignedStaysFalse(count);
    ExpectCountsZero(count);
    BOOST_CHECK_EQUAL(count.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");
}

BOOST_AUTO_TEST_CASE(ppm_bounds_that_are_not_the_illustration_stay_illustration)
{
    std::string err = "prior";
    modelnet::SwarmExplore zero_ppm = NotedExplore();
    zero_ppm.exploration_ppm = 0;
    zero_ppm.want_assign = true;
    const modelnet::SwarmExploreResult zero = modelnet::SwarmNoteExplore(zero_ppm, err);
    ExpectAssignedStaysFalse(zero);
    ExpectCountsZero(zero);
    BOOST_CHECK_EQUAL(zero.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");

    modelnet::SwarmExplore full_ppm = NotedExplore();
    full_ppm.exploration_ppm = 1000000;
    full_ppm.want_assign = true;
    const modelnet::SwarmExploreResult full = modelnet::SwarmNoteExplore(full_ppm, err);
    ExpectAssignedStaysFalse(full);
    ExpectCountsZero(full);
    BOOST_CHECK_EQUAL(full.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");
}

BOOST_AUTO_TEST_CASE(illustration_wins_when_want_assign_is_true)
{
    modelnet::SwarmExplore explore = NotedExplore();
    explore.slots = 6;
    explore.want_assign = true;
    std::string err = "prior";
    const modelnet::SwarmExploreResult result = modelnet::SwarmNoteExplore(explore, err);
    ExpectAssignedStaysFalse(result);
    ExpectCountsZero(result);
    BOOST_CHECK_EQUAL(result.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");
}

BOOST_AUTO_TEST_CASE(want_assign_on_the_known_illustration_is_held)
{
    modelnet::SwarmExplore explore = NotedExplore();
    explore.want_assign = true;
    std::string err = "prior";
    const modelnet::SwarmExploreResult result = modelnet::SwarmNoteExplore(explore, err);
    ExpectAssignedStaysFalse(result);
    ExpectIllustrationCounts(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(known_illustration_is_noted)
{
    modelnet::SwarmExplore explore = NotedExplore();
    std::string err = "prior";
    const modelnet::SwarmExploreResult result = modelnet::SwarmNoteExplore(explore, err);
    ExpectAssignedStaysFalse(result);
    ExpectIllustrationCounts(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
