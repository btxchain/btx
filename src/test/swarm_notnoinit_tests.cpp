// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoinit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_step_id)
{
    modelnet::SwarmNotNoInit note;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoInitResult result = modelnet::SwarmNoteNotNoInit(note, err);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.checkpoint_saved);
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(want_train)
{
    modelnet::SwarmNotNoInit note;
    note.step_id = "step-1";
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoInitResult result = modelnet::SwarmNoteNotNoInit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.checkpoint_saved);
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoInit note;
    note.step_id = "step-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoInitResult result = modelnet::SwarmNoteNotNoInit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.checkpoint_saved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
