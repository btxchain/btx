// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopassnote2.h>
#include <test/util/setup_common.h>

#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopassnote2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_stage_id_yields_stage)
{
    modelnet::SwarmNotNoPassNote2 note;
    note.stage_id.clear();
    note.want_pass = false;
    std::string err = "dirty";
    const modelnet::SwarmNotNoPassNote2Result result = modelnet::SwarmNoteNotNoPassNote2(note, err);
    BOOST_CHECK_EQUAL(result.code, "STAGE");
    BOOST_CHECK_EQUAL(err, "STAGE");
    BOOST_CHECK(!result.passed);
}

BOOST_AUTO_TEST_CASE(want_pass_yields_held)
{
    modelnet::SwarmNotNoPassNote2 note;
    note.stage_id = "hw";
    note.want_pass = true;
    std::string err;
    const modelnet::SwarmNotNoPassNote2Result result = modelnet::SwarmNoteNotNoPassNote2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.passed);
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    modelnet::SwarmNotNoPassNote2 note;
    note.stage_id = "hw";
    note.want_pass = false;
    std::string err = "dirty";
    const modelnet::SwarmNotNoPassNote2Result result = modelnet::SwarmNoteNotNoPassNote2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.passed);
}

BOOST_AUTO_TEST_SUITE_END()
