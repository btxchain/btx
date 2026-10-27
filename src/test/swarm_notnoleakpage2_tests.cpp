// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleakpage2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoleakpage2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_member_id_is_member)
{
    modelnet::SwarmNotNoLeakPage2 note;
    note.revoked = true;
    note.gradient = true;
    note.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeakPage2Result result = modelnet::SwarmNoteNotNoLeakPage2(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "MEMBER");
    BOOST_CHECK_EQUAL(err, "MEMBER");
}

BOOST_AUTO_TEST_CASE(revoked_is_not_read_when_want_read_is_false)
{
    modelnet::SwarmNotNoLeakPage2 note;
    note.member_id = "member-1";
    note.revoked = true;
    note.gradient = false;
    note.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeakPage2Result result = modelnet::SwarmNoteNotNoLeakPage2(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_READ");
    BOOST_CHECK_EQUAL(err, "NOT_READ");
}

BOOST_AUTO_TEST_CASE(gradient_with_revoked_false_is_not_read)
{
    modelnet::SwarmNotNoLeakPage2 note;
    note.member_id = "member-1";
    note.revoked = false;
    note.gradient = true;
    note.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeakPage2Result result = modelnet::SwarmNoteNotNoLeakPage2(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_READ");
    BOOST_CHECK_EQUAL(err, "NOT_READ");
}

BOOST_AUTO_TEST_CASE(both_false_with_want_read_false_is_noted)
{
    modelnet::SwarmNotNoLeakPage2 note;
    note.member_id = "member-1";
    note.revoked = false;
    note.gradient = false;
    note.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeakPage2Result result = modelnet::SwarmNoteNotNoLeakPage2(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
