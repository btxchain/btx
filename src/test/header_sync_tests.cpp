// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <node/header_sync.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(header_sync_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(locator_start_snaps_to_tip_when_best_header_is_behind)
{
    CBlockIndex behind;
    behind.nHeight = 199024;
    CBlockIndex tip;
    tip.nHeight = 199310;
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&behind, &tip), &tip);
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(nullptr, &tip), &tip);
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&behind, nullptr), &behind);
}

BOOST_AUTO_TEST_CASE(locator_start_keeps_suffix_that_extends_the_tip)
{
    CBlockIndex tip;
    tip.nHeight = 10;
    CBlockIndex child;
    child.nHeight = 11;
    child.pprev = &tip;
    BOOST_CHECK_EQUAL(child.GetAncestor(10), &tip);
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&child, &tip), &child);
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&tip, &tip), &tip);

    CBlockIndex other_parent;
    other_parent.nHeight = 10;
    CBlockIndex fork;
    fork.nHeight = 11;
    fork.pprev = &other_parent;
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&fork, &tip), &tip);
}

BOOST_AUTO_TEST_CASE(must_probe_table)
{
    // starting > tip, BestKnown null
    BOOST_CHECK(node::HeaderSyncMustProbe(/*tip=*/199310, /*start=*/199399,
                                          /*best_known_null=*/true,
                                          /*stale=*/false, /*inflight=*/true));
    // starting > tip, BestKnown pinned at our height
    BOOST_CHECK(node::HeaderSyncMustProbe(199310, 199399, false, false, false,
                                          /*best_known_height=*/199310));
    // starting > tip, BestKnown already ahead: do not probe
    BOOST_CHECK(!node::HeaderSyncMustProbe(199310, 199399, false, false, false,
                                           /*best_known_height=*/199343));
    // VERSION below tip, not stale: do not probe (pre-eb9ef0ef + same-height)
    BOOST_CHECK(!node::HeaderSyncMustProbe(199310, 199294, true, false, false));
    // VERSION below tip, stale: probe (live 0.34.3: 57 peers at 199294–199309)
    BOOST_CHECK(node::HeaderSyncMustProbe(199310, 199294, true, true, false));
    // BestKnown pinned at tip, starting below, stale: still probe for tip+1
    BOOST_CHECK(node::HeaderSyncMustProbe(199310, 199294, false, true, false,
                                          /*best_known_height=*/199310));
    // same-height stale, BestKnown null
    BOOST_CHECK(node::HeaderSyncMustProbe(199310, 199310, true, true, false));
}

BOOST_AUTO_TEST_CASE(duplicate_headers_followup_uses_batch_end)
{
    // Peer has fulfilled its advertised height: do not hot-loop the same
    // competing suffix merely because the active tip is still behind it.
    BOOST_CHECK(!node::DuplicateHeadersNeedFollowup(
        /*peer_starting_height=*/203881, /*last_header_height=*/203881));
    BOOST_CHECK(!node::DuplicateHeadersNeedFollowup(203880, 203881));
    // A partial duplicate batch below VERSION can still have a continuation.
    BOOST_CHECK(node::DuplicateHeadersNeedFollowup(203881, 203850));
}

BOOST_AUTO_TEST_SUITE_END()
