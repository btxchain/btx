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

BOOST_AUTO_TEST_CASE(locator_start_chases_heavier_disconnected_fork)
{
    // jarekpiot 2026-08-28: m_best_header on 0d5ffded@199398 must be the
    // locator origin, not the losing connected tip at 199326.
    CBlockIndex tip;
    tip.nHeight = 10;
    tip.nChainWork = arith_uint256{1};
    CBlockIndex other_parent;
    other_parent.nHeight = 10;
    other_parent.nChainWork = arith_uint256{1};
    CBlockIndex fork;
    fork.nHeight = 11;
    fork.pprev = &other_parent;
    fork.nChainWork = arith_uint256{2};
    BOOST_CHECK(fork.GetAncestor(10) != &tip);
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&fork, &tip), &fork);

    CBlockIndex lighter;
    lighter.nHeight = 11;
    lighter.pprev = &other_parent;
    lighter.nChainWork = arith_uint256{1};
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&lighter, &tip), &tip);
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
    // starting > tip, BestKnown already ahead on OUR chain: do not probe.
    // extends_tip must be explicit: default false means "not our chain"
    // (a forgotten argument must not seal a minority tip).
    BOOST_CHECK(!node::HeaderSyncMustProbe(199310, 199399, false, false, false,
                                           /*best_known_height=*/199343,
                                           /*best_known_extends_tip=*/true));
    BOOST_CHECK(node::HeaderSyncMustProbe(199310, 199399, false, false, false,
                                          /*best_known_height=*/199343));
    // Live 0.34.4: BestKnown 199382 on 33c834f8 does not extend 8b5da5a5
    // at 199310. Height-alone treated that as "ahead" and sent zero
    // getheaders while the peer advertised 199523.
    BOOST_CHECK(node::HeaderSyncMustProbe(199310, 199523, false, false, false,
                                          /*best_known_height=*/199382,
                                          /*best_known_extends_tip=*/false));
    BOOST_CHECK(!node::HeaderSyncMustProbe(199310, 199523, false, false, false,
                                           /*best_known_height=*/199382,
                                           /*best_known_extends_tip=*/true));
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

BOOST_AUTO_TEST_CASE(initial_sync_prefers_checkpoint_anchor_and_skips_low_work_failures)
{
    // MendeMatthias / v0.34.4: mainnet checkpoint 186000 is the
    // nMinimumChainWork IBD anchor. Peers at 128530 / 185109 / 189611 must
    // not take the single nSyncStarted slot when a 200131 peer is live.
    constexpr int32_t kAnchor{186000};
    BOOST_CHECK(node::InitialHeadersSyncPeerMeetsAnchor(200131, kAnchor));
    BOOST_CHECK(node::InitialHeadersSyncPeerMeetsAnchor(189611, kAnchor));
    BOOST_CHECK(!node::InitialHeadersSyncPeerMeetsAnchor(185109, kAnchor));
    BOOST_CHECK(!node::InitialHeadersSyncPeerMeetsAnchor(128530, kAnchor));
    BOOST_CHECK(node::InitialHeadersSyncPeerMeetsAnchor(186000, kAnchor));
    BOOST_CHECK(node::InitialHeadersSyncPeerMeetsAnchor(0, /*regtest*/ 0));
    BOOST_CHECK(node::InitialHeadersSyncPeerMeetsAnchor(-1, 0));

    BOOST_CHECK(node::InitialHeadersSyncPeerPreferred(200131, kAnchor, false));
    BOOST_CHECK(node::InitialHeadersSyncPeerPreferred(189611, kAnchor, false));
    BOOST_CHECK(!node::InitialHeadersSyncPeerPreferred(189611, kAnchor, true));
    BOOST_CHECK(!node::InitialHeadersSyncPeerPreferred(200131, kAnchor, true));
    BOOST_CHECK(!node::InitialHeadersSyncPeerPreferred(128530, kAnchor, false));

    // Preferred peer connected: a short peer must not claim.
    BOOST_CHECK(!node::MayClaimInitialHeadersSyncSlot(
        /*slot_free=*/true, /*sync=*/true, /*peer_preferred=*/false,
        /*any_preferred=*/true));
    // No preferred peer connected: a short peer may still claim so IBD
    // cannot deadlock.
    BOOST_CHECK(node::MayClaimInitialHeadersSyncSlot(
        true, true, /*peer_preferred=*/false, /*any_preferred=*/false));
    BOOST_CHECK(node::MayClaimInitialHeadersSyncSlot(
        true, true, /*peer_preferred=*/true, /*any_preferred=*/true));
    BOOST_CHECK(!node::MayClaimInitialHeadersSyncSlot(
        /*slot_free=*/false, true, true, true));
    BOOST_CHECK(!node::MayClaimInitialHeadersSyncSlot(
        true, /*sync=*/false, true, true));

    // A 200131 peer must take the slot from a 128530 holder.
    BOOST_CHECK(node::ShouldYieldInitialHeadersSyncSlot(
        /*holder_has_slot=*/true, /*holder_preferred=*/false,
        /*challenger_preferred=*/true));
    BOOST_CHECK(!node::ShouldYieldInitialHeadersSyncSlot(
        true, /*holder_preferred=*/true, true));
    BOOST_CHECK(!node::ShouldYieldInitialHeadersSyncSlot(
        false, false, true));
}

BOOST_AUTO_TEST_SUITE_END()
