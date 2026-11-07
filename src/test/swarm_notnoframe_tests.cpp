// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoframe.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoframe_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFrame NotedNote()
{
    modelnet::SwarmNotNoFrame note;
    note.framework_id = "framework-1";
    note.want_run = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_framework_id_is_framework)
{
    modelnet::SwarmNotNoFrame note = NotedNote();
    note.framework_id.clear();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFrameResult result = modelnet::SwarmNoteNotNoFrame(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "FRAMEWORK");
    BOOST_CHECK_EQUAL(err, "FRAMEWORK");
}

BOOST_AUTO_TEST_CASE(want_run_is_not_run)
{
    modelnet::SwarmNotNoFrame note = NotedNote();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFrameResult result = modelnet::SwarmNoteNotNoFrame(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFrame note = NotedNote();
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFrameResult result = modelnet::SwarmNoteNotNoFrame(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
