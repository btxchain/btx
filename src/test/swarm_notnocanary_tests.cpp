// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocanary.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocanary_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCanary NotedNote()
{
    modelnet::SwarmNotNoCanary note;
    note.canary_id = "canary-1";
    note.want_run = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_canary_id_is_canary)
{
    modelnet::SwarmNotNoCanary note = NotedNote();
    note.canary_id.clear();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCanaryResult result = modelnet::SwarmNoteNotNoCanary(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.regressed);
    BOOST_CHECK_EQUAL(result.code, "CANARY");
    BOOST_CHECK_EQUAL(err, "CANARY");
}

BOOST_AUTO_TEST_CASE(want_run_is_not_run)
{
    modelnet::SwarmNotNoCanary note = NotedNote();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCanaryResult result = modelnet::SwarmNoteNotNoCanary(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.regressed);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCanary note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoCanaryResult result = modelnet::SwarmNoteNotNoCanary(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.regressed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
