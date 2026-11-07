// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notreplay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notreplay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_replay)
{
    std::string err = "prior";
    modelnet::SwarmNotReplay note;
    note.quality_passed = true;
    note.want_exact_replay = true;
    const modelnet::SwarmNotReplayResult result = modelnet::SwarmNoteNotReplay(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "REPLAY");
    BOOST_CHECK_EQUAL(err, "REPLAY");
}

BOOST_AUTO_TEST_CASE(want_exact_replay_with_quality_passed_is_not_replay)
{
    std::string err = "prior";
    modelnet::SwarmNotReplay note;
    note.candidate_id = "cand-a";
    note.quality_passed = true;
    note.want_exact_replay = true;
    const modelnet::SwarmNotReplayResult result = modelnet::SwarmNoteNotReplay(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_REPLAY");
    BOOST_CHECK_EQUAL(err, "NOT_REPLAY");
}

BOOST_AUTO_TEST_CASE(quality_passed_without_exact_replay_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotReplay note;
    note.candidate_id = "cand-a";
    note.quality_passed = true;
    note.want_exact_replay = false;
    const modelnet::SwarmNotReplayResult result = modelnet::SwarmNoteNotReplay(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotReplay note;
    note.candidate_id = "cand-a";
    note.quality_passed = false;
    note.want_exact_replay = false;
    const modelnet::SwarmNotReplayResult result = modelnet::SwarmNoteNotReplay(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
