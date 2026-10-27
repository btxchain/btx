// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrevoke.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrevoke_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_member_id_is_member)
{
    modelnet::SwarmNotRevoke note;
    std::string err = "prior";
    const modelnet::SwarmNotRevokeResult result = modelnet::SwarmNoteNotRevoke(note, err);
    BOOST_CHECK_EQUAL(result.allowed, false);
    BOOST_CHECK_EQUAL(result.code, "MEMBER");
    BOOST_CHECK_EQUAL(err, "MEMBER");
}

BOOST_AUTO_TEST_CASE(want_read_is_not_live)
{
    modelnet::SwarmNotRevoke note;
    note.member_id = "member-a";
    note.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmNotRevokeResult result = modelnet::SwarmNoteNotRevoke(note, err);
    BOOST_CHECK_EQUAL(result.allowed, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_LIVE");
    BOOST_CHECK_EQUAL(err, "NOT_LIVE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotRevoke note;
    note.member_id = "member-a";
    note.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmNotRevokeResult result = modelnet::SwarmNoteNotRevoke(note, err);
    BOOST_CHECK_EQUAL(result.allowed, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
