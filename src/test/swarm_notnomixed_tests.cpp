// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomixed.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomixed_tests, BasicTestingSetup)

static modelnet::SwarmNotNoMixed NotedNote()
{
    modelnet::SwarmNotNoMixed note;
    note.step_id = "step-1";
    note.want_mixed = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_step_id_is_step)
{
    modelnet::SwarmNotNoMixed note = NotedNote();
    note.step_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoMixedResult result = modelnet::SwarmNoteNotNoMixed(note, err);
    BOOST_CHECK(!result.mixed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(want_mixed_is_not_run)
{
    modelnet::SwarmNotNoMixed note = NotedNote();
    note.want_mixed = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoMixedResult result = modelnet::SwarmNoteNotNoMixed(note, err);
    BOOST_CHECK(!result.mixed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoMixed note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoMixedResult result = modelnet::SwarmNoteNotNoMixed(note, err);
    BOOST_CHECK(!result.mixed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
