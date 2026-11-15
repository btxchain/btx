// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoablation2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoablation2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_study_id_is_study)
{
    modelnet::SwarmNotNoAblation2 note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAblation2Result result = modelnet::SwarmNoteNotNoAblation2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "STUDY");
    BOOST_CHECK_EQUAL(err, "STUDY");
}

BOOST_AUTO_TEST_CASE(want_publish_is_held)
{
    modelnet::SwarmNotNoAblation2 note;
    note.study_id = "study-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAblation2Result result = modelnet::SwarmNoteNotNoAblation2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAblation2 note;
    note.study_id = "study-1";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAblation2Result result = modelnet::SwarmNoteNotNoAblation2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
