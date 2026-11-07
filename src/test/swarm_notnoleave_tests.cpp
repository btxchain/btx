// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleave.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoleave_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_candidate)
{
    modelnet::SwarmNotNoLeave note;
    note.candidate_id.clear();
    note.unqualified = true;
    note.want_keep = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaveResult result = modelnet::SwarmNoteNotNoLeave(note, err);
    BOOST_CHECK(!result.kept);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(unqualified_is_left)
{
    modelnet::SwarmNotNoLeave note;
    note.candidate_id = "candidate-1";
    note.unqualified = true;
    note.want_keep = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaveResult result = modelnet::SwarmNoteNotNoLeave(note, err);
    BOOST_CHECK(!result.kept);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "LEFT");
    BOOST_CHECK_EQUAL(err, "LEFT");
}

BOOST_AUTO_TEST_CASE(want_keep_is_held)
{
    modelnet::SwarmNotNoLeave note;
    note.candidate_id = "candidate-1";
    note.unqualified = false;
    note.want_keep = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaveResult result = modelnet::SwarmNoteNotNoLeave(note, err);
    BOOST_CHECK(!result.kept);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoLeave note;
    BOOST_CHECK(!note.unqualified);
    BOOST_CHECK(!note.want_keep);
    note.candidate_id = "candidate-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaveResult result = modelnet::SwarmNoteNotNoLeave(note, err);
    BOOST_CHECK(!result.kept);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
