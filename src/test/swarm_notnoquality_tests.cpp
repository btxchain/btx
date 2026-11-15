// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquality.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoquality_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_candidate)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQuality note;
    note.want_promote = true;
    const modelnet::SwarmNotNoQualityResult result = modelnet::SwarmNoteNotNoQuality(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(want_promote_is_not_realm)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQuality note;
    note.candidate_id = "candidate-1";
    note.want_promote = true;
    const modelnet::SwarmNotNoQualityResult result = modelnet::SwarmNoteNotNoQuality(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_REALM");
    BOOST_CHECK_EQUAL(err, "NOT_REALM");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQuality note;
    note.candidate_id = "candidate-1";
    note.want_promote = false;
    const modelnet::SwarmNotNoQualityResult result = modelnet::SwarmNoteNotNoQuality(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
