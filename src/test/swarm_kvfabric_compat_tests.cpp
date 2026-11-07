// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvfabric_compat_tests, BasicTestingSetup)

static void ExpectNoMove(const modelnet::SwarmKvFabric& fabric, const modelnet::SwarmKvFabricResult& result)
{
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
}

BOOST_AUTO_TEST_CASE(empty_share_is_page)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult page = fabric.Share("", "fam-a", "fam-b", true);
    BOOST_CHECK_EQUAL(page.code, "PAGE");
    BOOST_CHECK(!fabric.shared(""));
    ExpectNoMove(fabric, page);

    const modelnet::SwarmKvFabricResult family_a = fabric.Share("page-1", "", "fam-b", true);
    BOOST_CHECK_EQUAL(family_a.code, "PAGE");
    BOOST_CHECK(!fabric.shared("page-1"));
    ExpectNoMove(fabric, family_a);

    const modelnet::SwarmKvFabricResult family_b = fabric.Share("page-1", "fam-a", "", true);
    BOOST_CHECK_EQUAL(family_b.code, "PAGE");
    BOOST_CHECK(!fabric.shared("page-1"));
    ExpectNoMove(fabric, family_b);
}

BOOST_AUTO_TEST_CASE(same_family_is_not_compat)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult result = fabric.Share("page-1", "fam", "fam", true);
    BOOST_CHECK_EQUAL(result.code, "NOT_COMPAT");
    BOOST_CHECK(!fabric.shared("page-1"));
    BOOST_CHECK(!fabric.shared("fam"));
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(compatible_false_is_not_compat)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult result = fabric.Share("page-1", "fam-a", "fam-b", false);
    BOOST_CHECK_EQUAL(result.code, "NOT_COMPAT");
    BOOST_CHECK(!fabric.shared("page-1"));
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(same_family_and_compatible_false_is_not_compat)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult result = fabric.Share("page-1", "fam", "fam", false);
    BOOST_CHECK_EQUAL(result.code, "NOT_COMPAT");
    BOOST_CHECK(!fabric.shared("page-1"));
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(real_share_records_page_id)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult refused = fabric.Share("page-1", "fam-a", "fam-a", true);
    BOOST_CHECK_EQUAL(refused.code, "NOT_COMPAT");
    BOOST_CHECK(!fabric.shared("page-1"));
    ExpectNoMove(fabric, refused);

    const modelnet::SwarmKvFabricResult result = fabric.Share("page-1", "fam-a", "fam-b", true);
    BOOST_REQUIRE_EQUAL(result.code, "SHARED");
    BOOST_CHECK(fabric.shared("page-1"));
    BOOST_CHECK(!fabric.shared("fam-a"));
    BOOST_CHECK(!fabric.shared("fam-b"));
    ExpectNoMove(fabric, result);

    const modelnet::SwarmKvFabricResult again = fabric.Share("page-1", "fam-c", "fam-d", true);
    BOOST_REQUIRE_EQUAL(again.code, "SHARED");
    BOOST_CHECK(fabric.shared("page-1"));
    ExpectNoMove(fabric, again);
}

BOOST_AUTO_TEST_CASE(refusal_does_not_mark_a_different_page)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult refused = fabric.Share("page-bad", "fam-a", "fam-b", false);
    BOOST_CHECK_EQUAL(refused.code, "NOT_COMPAT");
    BOOST_CHECK(!fabric.shared("page-bad"));
    ExpectNoMove(fabric, refused);

    const modelnet::SwarmKvFabricResult shared = fabric.Share("page-ok", "fam-a", "fam-b", true);
    BOOST_REQUIRE_EQUAL(shared.code, "SHARED");
    BOOST_CHECK(fabric.shared("page-ok"));
    BOOST_CHECK(!fabric.shared("page-bad"));
    ExpectNoMove(fabric, shared);
}

BOOST_AUTO_TEST_SUITE_END()
