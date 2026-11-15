// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotokps2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotokps2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoTokps2 NotedNote()
{
    modelnet::SwarmNotNoTokps2 note;
    note.sample_id = "sample-1";
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_sample_id_is_sample)
{
    modelnet::SwarmNotNoTokps2 note = NotedNote();
    note.sample_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoTokps2Result result = modelnet::SwarmNoteNotNoTokps2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(result.code, "SAMPLE");
    BOOST_CHECK_EQUAL(err, "SAMPLE");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotNoTokps2 note = NotedNote();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTokps2Result result = modelnet::SwarmNoteNotNoTokps2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoTokps2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoTokps2Result result = modelnet::SwarmNoteNotNoTokps2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
