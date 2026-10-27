// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_exploreill.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_exploreill_tests, BasicTestingSetup)

static modelnet::SwarmExploreIll NotedRun()
{
    modelnet::SwarmExploreIll run;
    run.run_id = "run-1";
    run.want_assign = false;
    return run;
}

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmExploreIll run = NotedRun();
    run.run_id.clear();
    std::string err = "prior";
    const modelnet::SwarmExploreIllResult result = modelnet::SwarmNoteExploration(run, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.illustrated_a, 1);
    BOOST_CHECK_EQUAL(result.illustrated_b, 2);
    BOOST_CHECK_EQUAL(result.illustrated_c, 2);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_assign_is_held)
{
    modelnet::SwarmExploreIll run = NotedRun();
    run.want_assign = true;
    std::string err = "prior";
    const modelnet::SwarmExploreIllResult result = modelnet::SwarmNoteExploration(run, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.illustrated_a, 1);
    BOOST_CHECK_EQUAL(result.illustrated_b, 2);
    BOOST_CHECK_EQUAL(result.illustrated_c, 2);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmExploreIll run = NotedRun();
    run.want_assign = false;
    std::string err = "prior";
    const modelnet::SwarmExploreIllResult result = modelnet::SwarmNoteExploration(run, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.illustrated_a, 1);
    BOOST_CHECK_EQUAL(result.illustrated_b, 2);
    BOOST_CHECK_EQUAL(result.illustrated_c, 2);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
