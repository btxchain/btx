// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/readfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_readfence_read_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_and_duplicate_revoke)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(!fence.Revoke("", err));
    BOOST_REQUIRE_EQUAL(err, "MEMBER");
    BOOST_REQUIRE(!fence.revoked(""));
    BOOST_REQUIRE_EQUAL(fence.revoke_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());

    err = "prior";
    BOOST_REQUIRE(fence.Revoke("alice", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.revoked("alice"));
    BOOST_REQUIRE_EQUAL(fence.revoke_count(), 1u);

    err = "prior";
    BOOST_REQUIRE(!fence.Revoke("alice", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(fence.revoked("alice"));
    BOOST_REQUIRE_EQUAL(fence.revoke_count(), 1u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
}

BOOST_AUTO_TEST_CASE(revoked_member_does_not_record_a_read)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Place("page", "fam", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.Revoke("alice", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!fence.Read("alice", "page", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_READ");
    BOOST_REQUIRE(!fence.recorded("alice", "page"));
    BOOST_REQUIRE_EQUAL(fence.read_count(), 0u);
    BOOST_REQUIRE(fence.placed("page"));
    BOOST_REQUIRE(fence.revoked("alice"));
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.process_started());

    err = "prior";
    BOOST_REQUIRE(!fence.Read("alice", "missing", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_READ");
    BOOST_REQUIRE(!fence.recorded("alice", "missing"));
    BOOST_REQUIRE_EQUAL(fence.read_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(unplaced_page_is_not_recorded)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(!fence.Read("bob", "missing", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE(!fence.recorded("bob", "missing"));
    BOOST_REQUIRE(!fence.revoked("bob"));
    BOOST_REQUIRE_EQUAL(fence.read_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());

    err = "prior";
    BOOST_REQUIRE(!fence.Read("", "missing", err));
    BOOST_REQUIRE_EQUAL(err, "MEMBER");
    BOOST_REQUIRE_EQUAL(fence.read_count(), 0u);

    err = "prior";
    BOOST_REQUIRE(!fence.Read("bob", "", err));
    BOOST_REQUIRE_EQUAL(err, "PAGE");
    BOOST_REQUIRE_EQUAL(fence.read_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(live_member_records_a_placed_page)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Place("page", "fam", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(fence.Read("bob", "page", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.recorded("bob", "page"));
    BOOST_REQUIRE(!fence.revoked("bob"));
    BOOST_REQUIRE_EQUAL(fence.read_count(), 1u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE(!fence.installed());

    BOOST_REQUIRE(fence.Read("bob", "page", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(fence.read_count(), 1u);

    BOOST_REQUIRE(fence.Read("cara", "page", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.recorded("cara", "page"));
    BOOST_REQUIRE_EQUAL(fence.read_count(), 2u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());

    BOOST_REQUIRE(fence.Revoke("bob", err));
    err = "prior";
    BOOST_REQUIRE(!fence.Read("bob", "page", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_READ");
    BOOST_REQUIRE(fence.recorded("bob", "page"));
    BOOST_REQUIRE_EQUAL(fence.read_count(), 2u);
    BOOST_REQUIRE(fence.recorded("cara", "page"));
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
}

BOOST_AUTO_TEST_SUITE_END()
