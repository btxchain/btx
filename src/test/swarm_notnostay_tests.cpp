// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnostay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_grant_id_is_grant)
{
    modelnet::SwarmNotNoStay note;
    note.revoked = true;
    note.want_erase = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoStayResult result = modelnet::SwarmNoteNotNoStay(note, err);
    BOOST_CHECK(!result.erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "GRANT");
    BOOST_CHECK_EQUAL(err, "GRANT");
}

BOOST_AUTO_TEST_CASE(revoked_is_stays_when_want_erase_is_false)
{
    modelnet::SwarmNotNoStay note;
    note.grant_id = "grant-1";
    note.revoked = true;
    note.want_erase = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoStayResult result = modelnet::SwarmNoteNotNoStay(note, err);
    BOOST_CHECK(!result.erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "STAYS");
    BOOST_CHECK_EQUAL(err, "STAYS");
}

BOOST_AUTO_TEST_CASE(want_erase_is_held)
{
    modelnet::SwarmNotNoStay note;
    note.grant_id = "grant-1";
    note.revoked = false;
    note.want_erase = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoStayResult result = modelnet::SwarmNoteNotNoStay(note, err);
    BOOST_CHECK(!result.erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoStay note;
    note.grant_id = "grant-1";
    note.revoked = false;
    note.want_erase = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoStayResult result = modelnet::SwarmNoteNotNoStay(note, err);
    BOOST_CHECK(!result.erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
