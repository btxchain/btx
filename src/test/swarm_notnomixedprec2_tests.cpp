// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomixedprec2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomixedprec2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoMixedPrec2 NotedNote()
{
    modelnet::SwarmNotNoMixedPrec2 note;
    note.run_id = "run-1";
    note.want_run = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoMixedPrec2 note = NotedNote();
    note.run_id.clear();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoMixedPrec2Result result = modelnet::SwarmNoteNotNoMixedPrec2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_run_is_held)
{
    modelnet::SwarmNotNoMixedPrec2 note = NotedNote();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoMixedPrec2Result result = modelnet::SwarmNoteNotNoMixedPrec2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoMixedPrec2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoMixedPrec2Result result = modelnet::SwarmNoteNotNoMixedPrec2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
