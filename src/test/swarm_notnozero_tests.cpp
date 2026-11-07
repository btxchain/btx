// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnozero.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnozero_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id)
{
    modelnet::SwarmNotNoZero note;
    note.max_steps = 1;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoZeroResult result = modelnet::SwarmNoteNotNoZero(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(max_steps_0)
{
    modelnet::SwarmNotNoZero note;
    note.run_id = "run-1";
    note.max_steps = 0;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoZeroResult result = modelnet::SwarmNoteNotNoZero(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(max_steps_1_want_train)
{
    modelnet::SwarmNotNoZero note;
    note.run_id = "run-1";
    note.max_steps = 1;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoZeroResult result = modelnet::SwarmNoteNotNoZero(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(max_steps_1_plain)
{
    modelnet::SwarmNotNoZero note;
    note.run_id = "run-1";
    note.max_steps = 1;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoZeroResult result = modelnet::SwarmNoteNotNoZero(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
