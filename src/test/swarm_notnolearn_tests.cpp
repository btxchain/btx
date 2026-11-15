// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolearn.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnolearn_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_learner_id_is_learner)
{
    std::string err = "prior";
    modelnet::SwarmNotNoLearn note;
    note.want_spend = true;
    const modelnet::SwarmNotNoLearnResult result = modelnet::SwarmNoteNotNoLearn(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "LEARNER");
    BOOST_CHECK_EQUAL(err, "LEARNER");
}

BOOST_AUTO_TEST_CASE(want_spend_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoLearn note;
    note.learner_id = "learner-1";
    note.want_spend = true;
    const modelnet::SwarmNotNoLearnResult result = modelnet::SwarmNoteNotNoLearn(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoLearn note;
    note.learner_id = "learner-1";
    note.want_spend = false;
    const modelnet::SwarmNotNoLearnResult result = modelnet::SwarmNoteNotNoLearn(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
