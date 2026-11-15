// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_deduphold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_deduphold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id)
{
    modelnet::SwarmDedupHold page;
    page.page_id.clear();
    page.cross_realm = false;
    page.want_move = false;
    std::string err;
    const modelnet::SwarmDedupHoldResult result = modelnet::SwarmHoldDedup(page, err);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
}

BOOST_AUTO_TEST_CASE(cross_realm_holds)
{
    modelnet::SwarmDedupHold page;
    page.page_id = "page-a";
    page.cross_realm = true;
    page.want_move = false;
    std::string err;
    const modelnet::SwarmDedupHoldResult result = modelnet::SwarmHoldDedup(page, err);
    BOOST_CHECK_EQUAL(result.code, "CROSS");
    BOOST_CHECK_EQUAL(err, "CROSS");
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
}

BOOST_AUTO_TEST_CASE(want_move_held)
{
    modelnet::SwarmDedupHold page;
    page.page_id = "page-b";
    page.cross_realm = false;
    page.want_move = true;
    std::string err;
    const modelnet::SwarmDedupHoldResult result = modelnet::SwarmHoldDedup(page, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
}

BOOST_AUTO_TEST_CASE(noted_no_move)
{
    modelnet::SwarmDedupHold page;
    page.page_id = "page-c";
    page.cross_realm = false;
    page.want_move = false;
    std::string err = "stale";
    const modelnet::SwarmDedupHoldResult result = modelnet::SwarmHoldDedup(page, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
}

BOOST_AUTO_TEST_SUITE_END()
