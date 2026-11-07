// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreplay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoreplay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_eval_id_is_eval)
{
    std::string err = "prior";
    modelnet::SwarmNotNoReplay note;
    note.quality_pass = true;
    note.want_admit = true;
    const modelnet::SwarmNotNoReplayResult result = modelnet::SwarmNoteNotNoReplay(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(quality_pass_without_want_admit_is_not_replay)
{
    std::string err = "prior";
    modelnet::SwarmNotNoReplay note;
    note.eval_id = "eval-a";
    note.quality_pass = true;
    note.want_admit = false;
    const modelnet::SwarmNotNoReplayResult result = modelnet::SwarmNoteNotNoReplay(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.code, "NOT_REPLAY");
    BOOST_CHECK_EQUAL(err, "NOT_REPLAY");
}

BOOST_AUTO_TEST_CASE(want_admit_is_not_replay)
{
    std::string err = "prior";
    modelnet::SwarmNotNoReplay note;
    note.eval_id = "eval-a";
    note.quality_pass = false;
    note.want_admit = true;
    const modelnet::SwarmNotNoReplayResult result = modelnet::SwarmNoteNotNoReplay(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.code, "NOT_REPLAY");
    BOOST_CHECK_EQUAL(err, "NOT_REPLAY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoReplay note;
    note.eval_id = "eval-a";
    note.quality_pass = false;
    note.want_admit = false;
    const modelnet::SwarmNotNoReplayResult result = modelnet::SwarmNoteNotNoReplay(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
