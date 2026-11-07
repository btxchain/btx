// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotps.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotps_tests, BasicTestingSetup)

static modelnet::SwarmNotNoTps NotedNote()
{
    modelnet::SwarmNotNoTps note;
    note.run_id = "run-1";
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoTps note = NotedNote();
    note.run_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoTpsResult result = modelnet::SwarmNoteNotNoTps(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotNoTps note = NotedNote();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTpsResult result = modelnet::SwarmNoteNotNoTps(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoTps note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoTpsResult result = modelnet::SwarmNoteNotNoTps(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
