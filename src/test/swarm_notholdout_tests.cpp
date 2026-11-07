// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notholdout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notholdout_tests, BasicTestingSetup)

static modelnet::SwarmNotHoldout NotedNote()
{
    modelnet::SwarmNotHoldout note;
    note.model_id = "model-1";
    note.want_score = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_model_id_is_model)
{
    modelnet::SwarmNotHoldout note = NotedNote();
    note.model_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotHoldoutResult result = modelnet::SwarmNoteNotHoldout(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "MODEL");
    BOOST_CHECK_EQUAL(err, "MODEL");
}

BOOST_AUTO_TEST_CASE(want_score_is_not_scored)
{
    modelnet::SwarmNotHoldout note = NotedNote();
    note.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmNotHoldoutResult result = modelnet::SwarmNoteNotHoldout(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "NOT_SCORED");
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotHoldout note = NotedNote();
    note.want_score = false;
    std::string err = "prior";
    const modelnet::SwarmNotHoldoutResult result = modelnet::SwarmNoteNotHoldout(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
