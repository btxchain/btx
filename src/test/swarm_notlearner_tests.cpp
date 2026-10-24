// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlearner.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notlearner_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_trajectory_id_is_trajectory)
{
    std::string err = "prior";
    modelnet::SwarmNotLearner note;
    note.want_queue = true;
    const modelnet::SwarmNotLearnerResult result = modelnet::SwarmNoteNotLearner(note, err);
    BOOST_CHECK(!result.queued);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "TRAJECTORY");
    BOOST_CHECK_EQUAL(err, "TRAJECTORY");
}

BOOST_AUTO_TEST_CASE(want_queue_is_not_queued)
{
    std::string err = "prior";
    modelnet::SwarmNotLearner note;
    note.trajectory_id = "trajectory-learner";
    note.want_queue = true;
    const modelnet::SwarmNotLearnerResult result = modelnet::SwarmNoteNotLearner(note, err);
    BOOST_CHECK(!result.queued);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_QUEUED");
    BOOST_CHECK_EQUAL(err, "NOT_QUEUED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotLearner note;
    note.trajectory_id = "trajectory-learner";
    note.want_queue = false;
    const modelnet::SwarmNotLearnerResult result = modelnet::SwarmNoteNotLearner(note, err);
    BOOST_CHECK(!result.queued);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
