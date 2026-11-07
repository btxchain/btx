// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoplaintext.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoplaintext_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_member_id_is_member)
{
    modelnet::SwarmNotNoPlaintext note;
    note.revoked = true;
    note.want_erase = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPlaintextResult result = modelnet::SwarmNoteNotNoPlaintext(note, err);
    BOOST_CHECK(!result.erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "MEMBER");
    BOOST_CHECK_EQUAL(err, "MEMBER");
}

BOOST_AUTO_TEST_CASE(revoked_is_retained_when_want_erase_is_false)
{
    modelnet::SwarmNotNoPlaintext note;
    note.member_id = "member-1";
    note.revoked = true;
    note.want_erase = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPlaintextResult result = modelnet::SwarmNoteNotNoPlaintext(note, err);
    BOOST_CHECK(!result.erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "RETAINED");
    BOOST_CHECK_EQUAL(err, "RETAINED");
}

BOOST_AUTO_TEST_CASE(want_erase_is_retained)
{
    modelnet::SwarmNotNoPlaintext note;
    note.member_id = "member-1";
    note.revoked = false;
    note.want_erase = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPlaintextResult result = modelnet::SwarmNoteNotNoPlaintext(note, err);
    BOOST_CHECK(!result.erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "RETAINED");
    BOOST_CHECK_EQUAL(err, "RETAINED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoPlaintext note;
    note.member_id = "member-1";
    note.revoked = false;
    note.want_erase = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPlaintextResult result = modelnet::SwarmNoteNotNoPlaintext(note, err);
    BOOST_CHECK(!result.erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
