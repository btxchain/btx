// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoguestagent2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoguestagent2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_check_id_is_check)
{
    modelnet::SwarmNotNoGuestAgent2 note;
    std::string err = "prior";
    const modelnet::SwarmNotNoGuestAgent2Result result = modelnet::SwarmNoteNotNoGuestAgent2(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "CHECK");
    BOOST_CHECK_EQUAL(err, "CHECK");
}

BOOST_AUTO_TEST_CASE(no_agent_is_not_passed)
{
    modelnet::SwarmNotNoGuestAgent2 note;
    note.check_id = "check-1";
    note.no_agent = true;
    note.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGuestAgent2Result result = modelnet::SwarmNoteNotNoGuestAgent2(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOT_PASSED");
    BOOST_CHECK_EQUAL(err, "NOT_PASSED");
}

BOOST_AUTO_TEST_CASE(want_pass_is_held)
{
    modelnet::SwarmNotNoGuestAgent2 note;
    note.check_id = "check-1";
    note.no_agent = false;
    note.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGuestAgent2Result result = modelnet::SwarmNoteNotNoGuestAgent2(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoGuestAgent2 note;
    note.check_id = "check-1";
    note.no_agent = false;
    note.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGuestAgent2Result result = modelnet::SwarmNoteNotNoGuestAgent2(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
