// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleak2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoleak2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_member_id_is_member)
{
    modelnet::SwarmNotNoLeak2 note;
    note.revoked = true;
    note.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeak2Result result = modelnet::SwarmNoteNotNoLeak2(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "MEMBER");
    BOOST_CHECK_EQUAL(err, "MEMBER");
}

BOOST_AUTO_TEST_CASE(revoked_is_not_read_when_want_read_is_false)
{
    modelnet::SwarmNotNoLeak2 note;
    note.member_id = "member-1";
    note.revoked = true;
    note.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeak2Result result = modelnet::SwarmNoteNotNoLeak2(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_READ");
    BOOST_CHECK_EQUAL(err, "NOT_READ");
}

BOOST_AUTO_TEST_CASE(want_read_is_held)
{
    modelnet::SwarmNotNoLeak2 note;
    note.member_id = "member-1";
    note.revoked = false;
    note.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeak2Result result = modelnet::SwarmNoteNotNoLeak2(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoLeak2 note;
    note.member_id = "member-1";
    note.revoked = false;
    note.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeak2Result result = modelnet::SwarmNoteNotNoLeak2(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
