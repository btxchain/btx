// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowindows2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnowindows2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_check_id_is_check)
{
    modelnet::SwarmNotNoWindows2 note;
    note.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoWindows2Result result = modelnet::SwarmNoteNotNoWindows2(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "CHECK");
    BOOST_CHECK_EQUAL(err, "CHECK");
}

BOOST_AUTO_TEST_CASE(want_pass_is_held)
{
    modelnet::SwarmNotNoWindows2 note;
    note.check_id = "check-1";
    note.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoWindows2Result result = modelnet::SwarmNoteNotNoWindows2(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoWindows2 note;
    note.check_id = "check-1";
    note.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoWindows2Result result = modelnet::SwarmNoteNotNoWindows2(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
