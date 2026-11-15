// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvfabric_revoke_tests, BasicTestingSetup)

static void ExpectNoMove(const modelnet::SwarmKvFabric& fabric, const modelnet::SwarmKvFabricResult& result)
{
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
}

BOOST_AUTO_TEST_CASE(revoke_then_read_is_not_recorded)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult placed = fabric.Place("page-1", "fam-a");
    BOOST_REQUIRE_EQUAL(placed.code, "PLACED");
    ExpectNoMove(fabric, placed);

    const modelnet::SwarmKvFabricResult revoked = fabric.Revoke("member-a");
    BOOST_REQUIRE_EQUAL(revoked.code, "REVOKED");
    BOOST_CHECK(fabric.revoked("member-a"));
    ExpectNoMove(fabric, revoked);

    const modelnet::SwarmKvFabricResult read = fabric.Read("member-a", "page-1");
    BOOST_CHECK_EQUAL(read.code, "NOT_READ");
    BOOST_CHECK(!fabric.read_recorded("member-a", "page-1"));
    ExpectNoMove(fabric, read);
}

BOOST_AUTO_TEST_CASE(non_revoked_member_records_placed_read)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult placed = fabric.Place("page-1", "fam-a");
    BOOST_REQUIRE_EQUAL(placed.code, "PLACED");
    ExpectNoMove(fabric, placed);

    const modelnet::SwarmKvFabricResult read = fabric.Read("member-b", "page-1");
    BOOST_REQUIRE_EQUAL(read.code, "READ");
    BOOST_CHECK(fabric.read_recorded("member-b", "page-1"));
    BOOST_CHECK(!fabric.revoked("member-b"));
    ExpectNoMove(fabric, read);
}

BOOST_AUTO_TEST_CASE(unplaced_page_is_not_read)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult shared = fabric.Share("page-1", "fam-a", "fam-b", true);
    BOOST_REQUIRE_EQUAL(shared.code, "SHARED");
    BOOST_CHECK(!fabric.placed("page-1"));
    ExpectNoMove(fabric, shared);

    const modelnet::SwarmKvFabricResult read = fabric.Read("member-b", "page-1");
    BOOST_CHECK_EQUAL(read.code, "NOT_READ");
    BOOST_CHECK(!fabric.read_recorded("member-b", "page-1"));
    ExpectNoMove(fabric, read);
}

BOOST_AUTO_TEST_CASE(revoked_member_does_not_block_another_member)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult placed = fabric.Place("page-1", "fam-a");
    BOOST_REQUIRE_EQUAL(placed.code, "PLACED");
    ExpectNoMove(fabric, placed);

    const modelnet::SwarmKvFabricResult revoked = fabric.Revoke("member-a");
    BOOST_REQUIRE_EQUAL(revoked.code, "REVOKED");
    ExpectNoMove(fabric, revoked);

    const modelnet::SwarmKvFabricResult blocked = fabric.Read("member-a", "page-1");
    BOOST_CHECK_EQUAL(blocked.code, "NOT_READ");
    BOOST_CHECK(!fabric.read_recorded("member-a", "page-1"));
    ExpectNoMove(fabric, blocked);

    const modelnet::SwarmKvFabricResult allowed = fabric.Read("member-b", "page-1");
    BOOST_REQUIRE_EQUAL(allowed.code, "READ");
    BOOST_CHECK(fabric.read_recorded("member-b", "page-1"));
    BOOST_CHECK(!fabric.read_recorded("member-a", "page-1"));
    ExpectNoMove(fabric, allowed);
}

BOOST_AUTO_TEST_CASE(read_recorded_before_revoke_stays_recorded)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult placed = fabric.Place("page-1", "fam-a");
    BOOST_REQUIRE_EQUAL(placed.code, "PLACED");
    ExpectNoMove(fabric, placed);

    const modelnet::SwarmKvFabricResult read = fabric.Read("member-a", "page-1");
    BOOST_REQUIRE_EQUAL(read.code, "READ");
    BOOST_CHECK(fabric.read_recorded("member-a", "page-1"));
    ExpectNoMove(fabric, read);

    const modelnet::SwarmKvFabricResult revoked = fabric.Revoke("member-a");
    BOOST_REQUIRE_EQUAL(revoked.code, "REVOKED");
    ExpectNoMove(fabric, revoked);

    const modelnet::SwarmKvFabricResult again = fabric.Read("member-a", "page-1");
    BOOST_CHECK_EQUAL(again.code, "NOT_READ");
    BOOST_CHECK(fabric.read_recorded("member-a", "page-1"));
    ExpectNoMove(fabric, again);
}

BOOST_AUTO_TEST_CASE(empty_member_or_page_is_page)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult placed = fabric.Place("page-1", "fam-a");
    BOOST_REQUIRE_EQUAL(placed.code, "PLACED");
    ExpectNoMove(fabric, placed);

    const modelnet::SwarmKvFabricResult revoke = fabric.Revoke("");
    BOOST_CHECK_EQUAL(revoke.code, "PAGE");
    BOOST_CHECK(!fabric.revoked(""));
    ExpectNoMove(fabric, revoke);

    const modelnet::SwarmKvFabricResult member = fabric.Read("", "page-1");
    BOOST_CHECK_EQUAL(member.code, "PAGE");
    BOOST_CHECK(!fabric.read_recorded("", "page-1"));
    ExpectNoMove(fabric, member);

    const modelnet::SwarmKvFabricResult page = fabric.Read("member-b", "");
    BOOST_CHECK_EQUAL(page.code, "PAGE");
    BOOST_CHECK(!fabric.read_recorded("member-b", ""));
    ExpectNoMove(fabric, page);
}

BOOST_AUTO_TEST_SUITE_END()
