// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexploreill2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoexploreill2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoExploreIll2 NotedNote()
{
    modelnet::SwarmNotNoExploreIll2 note;
    note.run_id = "run-1";
    note.want_assign = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoExploreIll2 note = NotedNote();
    note.run_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoExploreIll2Result result = modelnet::SwarmNoteNotNoExploreIll2(note, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_assign_is_held)
{
    modelnet::SwarmNotNoExploreIll2 note = NotedNote();
    note.want_assign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoExploreIll2Result result = modelnet::SwarmNoteNotNoExploreIll2(note, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoExploreIll2 note = NotedNote();
    note.want_assign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoExploreIll2Result result = modelnet::SwarmNoteNotNoExploreIll2(note, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
