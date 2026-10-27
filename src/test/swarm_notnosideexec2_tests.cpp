// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosideexec2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosideexec2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_name_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSideExec2 note;
    note.want_exec = true;
    const modelnet::SwarmNotNoSideExec2Result result = modelnet::SwarmNoteNotNoSideExec2(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK_EQUAL(result.code, "NAME");
    BOOST_CHECK_EQUAL(err, "NAME");
}

BOOST_AUTO_TEST_CASE(want_exec)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSideExec2 note;
    note.name_id = "name-1";
    note.want_exec = true;
    const modelnet::SwarmNotNoSideExec2Result result = modelnet::SwarmNoteNotNoSideExec2(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSideExec2 note;
    note.name_id = "name-1";
    note.want_exec = false;
    const modelnet::SwarmNotNoSideExec2Result result = modelnet::SwarmNoteNotNoSideExec2(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
