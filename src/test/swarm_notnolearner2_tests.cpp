// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolearner2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnolearner2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoLearner2 NotedNote()
{
    modelnet::SwarmNotNoLearner2 note;
    note.learner_id = "learner-1";
    note.want_run = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_learner_id_is_learner)
{
    modelnet::SwarmNotNoLearner2 note = NotedNote();
    note.learner_id.clear();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLearner2Result result = modelnet::SwarmNoteNotNoLearner2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.code, "LEARNER");
    BOOST_CHECK_EQUAL(err, "LEARNER");
}

BOOST_AUTO_TEST_CASE(want_run_is_held)
{
    modelnet::SwarmNotNoLearner2 note = NotedNote();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLearner2Result result = modelnet::SwarmNoteNotNoLearner2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoLearner2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoLearner2Result result = modelnet::SwarmNoteNotNoLearner2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
