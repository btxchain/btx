// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revoke.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_revoke_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_member_is_member)
{
    modelnet::SwarmRevoke member;
    member.member_id.clear();
    member.revoked = false;
    member.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmRevokeResult result = modelnet::SwarmNoteRevoke(member, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK_EQUAL(result.code, "MEMBER");
    BOOST_CHECK_EQUAL(err, "MEMBER");
}

BOOST_AUTO_TEST_CASE(revoked_true_want_read_false_is_not_read)
{
    modelnet::SwarmRevoke member;
    member.member_id = "member-a";
    member.revoked = true;
    member.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmRevokeResult result = modelnet::SwarmNoteRevoke(member, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK_EQUAL(result.code, "NOT_READ");
    BOOST_CHECK_EQUAL(err, "NOT_READ");
}

BOOST_AUTO_TEST_CASE(want_read_true_revoked_false_is_held)
{
    modelnet::SwarmRevoke member;
    member.member_id = "member-b";
    member.revoked = false;
    member.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmRevokeResult result = modelnet::SwarmNoteRevoke(member, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(revoked_false_want_read_false_is_noted)
{
    modelnet::SwarmRevoke member;
    member.member_id = "member-c";
    member.revoked = false;
    member.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmRevokeResult result = modelnet::SwarmNoteRevoke(member, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
