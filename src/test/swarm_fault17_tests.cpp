// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault17.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault17_tests, BasicTestingSetup)

static modelnet::SwarmFault17 Member()
{
    modelnet::SwarmFault17 in;
    in.member_id = "member-1";
    in.page_id = "page-1";
    in.revoked = false;
    in.want_read = false;
    return in;
}

static void ExpectDenied(const modelnet::SwarmFault17Result& result)
{
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_member_id_is_member)
{
    modelnet::SwarmFault17 in = Member();
    in.member_id.clear();
    in.revoked = true;
    in.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmFault17Result result = modelnet::SwarmRecoverFault17(in, err);
    BOOST_CHECK_EQUAL(result.code, "MEMBER");
    ExpectDenied(result);
    BOOST_CHECK_EQUAL(err, "MEMBER");
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_member)
{
    modelnet::SwarmFault17 in = Member();
    in.page_id.clear();
    in.revoked = true;
    in.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmFault17Result result = modelnet::SwarmRecoverFault17(in, err);
    BOOST_CHECK_EQUAL(result.code, "MEMBER");
    ExpectDenied(result);
    BOOST_CHECK_EQUAL(err, "MEMBER");
}

BOOST_AUTO_TEST_CASE(both_ids_empty_is_member)
{
    modelnet::SwarmFault17 in = Member();
    in.member_id.clear();
    in.page_id.clear();
    in.revoked = true;
    in.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmFault17Result result = modelnet::SwarmRecoverFault17(in, err);
    BOOST_CHECK_EQUAL(result.code, "MEMBER");
    ExpectDenied(result);
    BOOST_CHECK_EQUAL(err, "MEMBER");
}

BOOST_AUTO_TEST_CASE(revoked_with_want_read_is_revoked)
{
    modelnet::SwarmFault17 in = Member();
    in.revoked = true;
    in.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmFault17Result result = modelnet::SwarmRecoverFault17(in, err);
    BOOST_CHECK_EQUAL(result.code, "REVOKED");
    ExpectDenied(result);
    BOOST_CHECK_EQUAL(err, "REVOKED");
}

BOOST_AUTO_TEST_CASE(revoked_without_want_read_is_revoked)
{
    modelnet::SwarmFault17 in = Member();
    in.revoked = true;
    in.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmFault17Result result = modelnet::SwarmRecoverFault17(in, err);
    BOOST_CHECK_EQUAL(result.code, "REVOKED");
    ExpectDenied(result);
    BOOST_CHECK_EQUAL(err, "REVOKED");
}

BOOST_AUTO_TEST_CASE(want_read_is_held)
{
    modelnet::SwarmFault17 in = Member();
    in.revoked = false;
    in.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmFault17Result result = modelnet::SwarmRecoverFault17(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    ExpectDenied(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmFault17 in = Member();
    std::string err = "prior";
    const modelnet::SwarmFault17Result result = modelnet::SwarmRecoverFault17(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    ExpectDenied(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
