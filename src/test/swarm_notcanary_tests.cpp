// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcanary.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcanary_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_candidate)
{
    modelnet::SwarmNotCanary note;
    std::string err = "prior";
    const modelnet::SwarmNotCanaryResult result = modelnet::SwarmNoteNotCanary(note, err);
    BOOST_CHECK_EQUAL(result.rolled, false);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(want_roll_is_not_canary)
{
    modelnet::SwarmNotCanary note;
    note.candidate_id = "candidate-1";
    note.want_roll = true;
    std::string err = "prior";
    const modelnet::SwarmNotCanaryResult result = modelnet::SwarmNoteNotCanary(note, err);
    BOOST_CHECK_EQUAL(result.rolled, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_CANARY");
    BOOST_CHECK_EQUAL(err, "NOT_CANARY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotCanary note;
    note.candidate_id = "candidate-1";
    note.want_roll = false;
    std::string err = "prior";
    const modelnet::SwarmNotCanaryResult result = modelnet::SwarmNoteNotCanary(note, err);
    BOOST_CHECK_EQUAL(result.rolled, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
