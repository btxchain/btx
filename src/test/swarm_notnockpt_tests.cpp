// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnockpt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnockpt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_step_id)
{
    modelnet::SwarmNotNoCkpt note;
    note.want_save = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoCkptResult result = modelnet::SwarmNoteNotNoCkpt(note, err);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.distributed);
}

BOOST_AUTO_TEST_CASE(want_save)
{
    modelnet::SwarmNotNoCkpt note;
    note.step_id = "step-a";
    note.want_save = true;
    std::string err;
    const modelnet::SwarmNotNoCkptResult result = modelnet::SwarmNoteNotNoCkpt(note, err);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.distributed);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoCkpt note;
    note.step_id = "step-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoCkptResult result = modelnet::SwarmNoteNotNoCkpt(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.distributed);
}

BOOST_AUTO_TEST_SUITE_END()
