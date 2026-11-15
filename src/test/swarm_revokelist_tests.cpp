// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revokelist.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_revokelist_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(read_before_revoke_then_not_after)
{
    modelnet::SwarmRevokeList list;
    std::string err = "prior";

    BOOST_CHECK(!list.revoked("alice"));
    BOOST_CHECK(list.Read("alice", "page-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(list.bytes_moved(), 0);

    BOOST_CHECK(list.Revoke("alice", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(list.revoked("alice"));
    BOOST_CHECK_EQUAL(list.bytes_moved(), 0);

    err = "prior";
    BOOST_CHECK(!list.Read("alice", "page-2", err));
    BOOST_CHECK_EQUAL(err, "NOT_READ");
    BOOST_CHECK(list.revoked("alice"));
    BOOST_CHECK_EQUAL(list.bytes_moved(), 0);

    BOOST_CHECK(list.Read("bob", "page-2", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!list.revoked("bob"));
    BOOST_CHECK_EQUAL(list.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_member_is_member_and_replay_stays_revoked)
{
    modelnet::SwarmRevokeList list;
    std::string err = "prior";

    BOOST_CHECK(!list.Revoke("", err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK(!list.revoked(""));
    BOOST_CHECK_EQUAL(list.bytes_moved(), 0);

    BOOST_CHECK(list.Revoke("alice", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!list.Revoke("alice", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(list.revoked("alice"));
    BOOST_CHECK_EQUAL(list.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_member_or_page_is_page)
{
    modelnet::SwarmRevokeList list;
    std::string err = "prior";

    BOOST_CHECK(!list.Read("", "page-1", err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!list.Read("alice", "", err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!list.Read("", "", err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!list.revoked("alice"));
    BOOST_CHECK_EQUAL(list.bytes_moved(), 0);

    BOOST_CHECK(list.Revoke("alice", err));
    BOOST_CHECK(!list.Read("alice", "", err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK_EQUAL(list.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
