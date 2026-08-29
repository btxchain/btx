// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <node/header_sync.h>
#include <test/util/setup_common.h>

#include <chrono>

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

BOOST_AUTO_TEST_CASE(locator_start_does_not_chase_long_competing_header_tower)
{
    // Direct predicate: a live consensus-archive node 2026-08-29 tip 199385 vs m_best_header
    // 199801 on withdrawn 33c834f8 (lead 416).
    BOOST_CHECK(!node::HeaderSyncChaseHeavierCompetingLocator(
        /*extends_active_tip=*/false, /*heavier=*/true, 199801, 199385));
    BOOST_CHECK(node::HeaderSyncChaseHeavierCompetingLocator(
        false, true, 11, 10));
    BOOST_CHECK(!node::HeaderSyncChaseHeavierCompetingLocator(
        /*extends_active_tip=*/true, true, 199801, 199385));
    BOOST_CHECK(!node::HeaderSyncChaseHeavierCompetingLocator(
        false, /*heavier=*/false, 11, 10));

    CBlockIndex tip;
    tip.nHeight = 10;
    tip.nChainWork = arith_uint256{1};
    CBlockIndex other_parent;
    other_parent.nHeight = 10;
    other_parent.nChainWork = arith_uint256{1};

    // Contiguous competing fork so GetAncestor(tip) walks pprev, not a skip.
    CBlockIndex fork[8];
    CBlockIndex* prev{&other_parent};
    arith_uint256 work{2};
    for (int i = 0; i < 8; ++i) {
        fork[i].nHeight = 11 + i;
        fork[i].pprev = prev;
        fork[i].nChainWork = work;
        work += 1;
        prev = &fork[i];
    }
    BOOST_CHECK_EQUAL(fork[5].GetAncestor(10), &other_parent);
    BOOST_CHECK(fork[5].GetAncestor(10) != &tip);
    BOOST_CHECK_EQUAL(
        fork[5].nHeight - tip.nHeight,
        node::HEADER_SYNC_SHORT_COMPETING_LOCATOR_LEAD);
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&fork[5], &tip), &fork[5]);

    BOOST_CHECK_EQUAL(
        fork[6].nHeight - tip.nHeight,
        node::HEADER_SYNC_SHORT_COMPETING_LOCATOR_LEAD + 1);
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&fork[6], &tip), &tip);
    BOOST_CHECK_EQUAL(node::HeaderSyncLocatorStart(&fork[7], &tip), &tip);
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
    // VERSION below tip, even when stale: do not probe (live 0.34.5 skip)
    BOOST_CHECK(!node::HeaderSyncMustProbe(199310, 199294, true, true, false));
    BOOST_CHECK(!node::HeaderSyncMustProbe(199310, 199294, false, true, false,
                                          /*best_known_height=*/199310));
    // height 0 / unset never probes
    BOOST_CHECK(!node::HeaderSyncMustProbe(199310, 0, true, true, false));
    BOOST_CHECK(!node::HeaderSyncMustProbe(199310, -1, true, true, false));
    // same-height stale, BestKnown null
    BOOST_CHECK(node::HeaderSyncMustProbe(199310, 199310, true, true, false));
    // SF-5: stale VERSION snapshot, BestKnown already above tip → probe.
    BOOST_CHECK(node::HeaderSyncMustProbe(199334, 199300, false, false, false,
                                          /*best_known_height=*/199340));
}

BOOST_AUTO_TEST_CASE(probe_interval_and_suffix_failover_helpers)
{
    using namespace std::chrono;
    BOOST_CHECK(node::HeaderSyncProbeIntervalElapsed(
        /*have_prior=*/false, 0us, 2min));
    BOOST_CHECK(!node::HeaderSyncProbeIntervalElapsed(
        true, 1s, 2min));
    BOOST_CHECK(!node::HeaderSyncProbeIntervalElapsed(
        true, 2min, 2min));
    BOOST_CHECK(node::HeaderSyncProbeIntervalElapsed(
        true, 2min + 1s, 2min));

    BOOST_CHECK(!node::FollowedHeaderSuffixNeedsDownloadFailover(
        /*tip=*/199334, /*uncapped_ahead=*/0));
    BOOST_CHECK(!node::FollowedHeaderSuffixNeedsDownloadFailover(199334, 1));
    BOOST_CHECK(node::FollowedHeaderSuffixNeedsDownloadFailover(199334, 2));
    BOOST_CHECK(node::FollowedHeaderSuffixNeedsDownloadFailover(199334, 960));
    BOOST_CHECK(!node::FollowedHeaderSuffixNeedsDownloadFailover(-1, 960));
    BOOST_CHECK(node::HeaderSyncAdvertisedHeightUnusable(199334, 0));
    BOOST_CHECK(node::HeaderSyncAdvertisedHeightUnusable(199334, -1));
    BOOST_CHECK(node::HeaderSyncAdvertisedHeightUnusable(199334, 199300));
    BOOST_CHECK(!node::HeaderSyncAdvertisedHeightUnusable(199334, 199334));
    BOOST_CHECK(!node::HeaderSyncAdvertisedHeightUnusable(199334, 200294));
    BOOST_CHECK(!node::HeaderSyncAdvertisedHeightUnusable(0, 0));
    BOOST_CHECK(!node::HeaderSyncAdvertisedHeightUnusable(-1, 0));
    BOOST_CHECK(!node::HeaderSyncAdvertisedHeightUnusable(199334, 199300, 199340));
    BOOST_CHECK(!node::HeaderSyncAdvertisedHeightUnusable(199334, 0, 199334));
    BOOST_CHECK(node::HeaderSyncAdvertisedHeightUnusable(199334, 199300, 199300));
    BOOST_CHECK(node::HeaderSyncMustProbe(
        199334, /*stale_version=*/199300, /*best_known_null=*/false,
        /*tip_is_stale=*/false, /*headers_in_flight=*/false,
        /*best_known=*/199340, /*extends_tip=*/true));
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

    BOOST_CHECK(!node::MayClaimInitialHeadersSyncSlot(
        true, true, true, true, /*peer_in_low_work_backoff=*/true));
    BOOST_CHECK(!node::MayClaimInitialHeadersSyncSlot(
        true, true, /*peer_preferred=*/false, /*any_preferred=*/false,
        /*peer_in_low_work_backoff=*/true));

    BOOST_CHECK_EQUAL(node::LowWorkHeadersFailureBackoff(0).count(), 0);
    BOOST_CHECK_EQUAL(node::LowWorkHeadersFailureBackoff(1).count(), 120);
    BOOST_CHECK_EQUAL(node::LowWorkHeadersFailureBackoff(2).count(), 240);
    BOOST_CHECK_EQUAL(node::LowWorkHeadersFailureBackoff(5).count(), 1920);
    BOOST_CHECK_EQUAL(node::LowWorkHeadersFailureBackoff(9).count(), 1920);
    BOOST_CHECK(!node::LowWorkHeadersFailureInBackoff(false, std::chrono::microseconds{10}, std::chrono::microseconds{20}));
    BOOST_CHECK(node::LowWorkHeadersFailureInBackoff(true, std::chrono::microseconds{10}, std::chrono::microseconds{20}));
    BOOST_CHECK(!node::LowWorkHeadersFailureInBackoff(true, std::chrono::microseconds{20}, std::chrono::microseconds{20}));

    {
        const auto floor{std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds{10})};
        const auto computed_fast{std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::milliseconds{250})};
        const auto cap_fast{std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::milliseconds{750})};
        BOOST_CHECK_EQUAL(
            node::BlockDownloadTimeoutRespectFloor(computed_fast, floor, cap_fast).count(),
            floor.count());
        const auto computed_normal{std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds{90})};
        const auto cap_normal{std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds{270})};
        BOOST_CHECK_EQUAL(
            node::BlockDownloadTimeoutRespectFloor(computed_normal, floor, cap_normal).count(),
            computed_normal.count());
    }

    // A 200131 peer must take the slot from a 128530 holder.
    BOOST_CHECK(node::ShouldYieldInitialHeadersSyncSlot(
        /*holder_has_slot=*/true, /*holder_preferred=*/false,
        /*challenger_preferred=*/true));
    BOOST_CHECK(!node::ShouldYieldInitialHeadersSyncSlot(
        true, /*holder_preferred=*/true, true));
    BOOST_CHECK(!node::ShouldYieldInitialHeadersSyncSlot(
        false, false, true));
}

BOOST_AUTO_TEST_CASE(far_behind_yields_gpu_protect)
{
    BOOST_CHECK(!node::CatchUpFarBehindYieldsGpuProtect(32));
    BOOST_CHECK(!node::CatchUpFarBehindYieldsGpuProtect(99));
    BOOST_CHECK(node::CatchUpFarBehindYieldsGpuProtect(100));
    BOOST_CHECK(node::CatchUpFarBehindYieldsGpuProtect(1136));
    BOOST_CHECK(node::FollowedHeaderSuffixNeedsDownloadFailover(199336, 1136));
}

BOOST_AUTO_TEST_CASE(seed_best_known_from_header_tower_skips_at_tip_peer)
{
    // A live consensus-archive node 2026-08-29: tip 199386, m_best_header 199801, 6 peers
    // advertising above, selector kept asking peer=29 at the frozen tip.
    constexpr int32_t kTip{199386};
    constexpr int32_t kTower{199801};
    BOOST_CHECK(node::HeaderSyncBestKnownStuckAtTip(kTip, /*null*/ -1));
    BOOST_CHECK(node::HeaderSyncBestKnownStuckAtTip(kTip, kTip));
    BOOST_CHECK(!node::HeaderSyncBestKnownStuckAtTip(kTip, kTower));

    BOOST_CHECK(node::HeaderSyncMaySeedBestKnownFromHeaderTower(
        kTip, /*advertised=*/kTower, /*best_known=*/-1, kTower,
        /*extends_or_heavier=*/true));
    BOOST_CHECK(node::HeaderSyncMaySeedBestKnownFromHeaderTower(
        kTip, kTower, /*best_known_at_tip=*/kTip, kTower, true));
    BOOST_CHECK(!node::HeaderSyncMaySeedBestKnownFromHeaderTower(
        kTip, /*at_tip_peer=*/kTip, -1, kTower, true));
    BOOST_CHECK(!node::HeaderSyncMaySeedBestKnownFromHeaderTower(
        kTip, kTower, /*already_ahead=*/kTower, kTower, true));
    // Retained-body drain: BestKnown is 199388 while the tower is 199801.
    // Must still raise to the tower or GETDATA never refills.
    BOOST_CHECK(node::HeaderSyncMaySeedBestKnownFromHeaderTower(
        kTip, kTower, /*retained_ahead=*/kTip + 2, kTower, true));
    BOOST_CHECK(!node::HeaderSyncMaySeedBestKnownFromHeaderTower(
        kTip, kTower, -1, kTower, /*not_extends_or_heavier=*/false));
    BOOST_CHECK(!node::HeaderSyncMaySeedBestKnownFromHeaderTower(
        kTip, kTower, -1, /*header_not_ahead=*/kTip, true));

    BOOST_CHECK_EQUAL(
        node::HeaderSyncSeedBestKnownHeight(kTip, kTower, kTower), kTower);
    BOOST_CHECK_EQUAL(
        node::HeaderSyncSeedBestKnownHeight(kTip, /*peer=*/199672, kTower),
        199672);
    BOOST_CHECK_EQUAL(
        node::HeaderSyncSeedBestKnownHeight(kTip, kTip, kTower), -1);

    BOOST_CHECK(node::HeaderSyncMustDriveFetchWhileStalled(
        /*inflight_empty=*/true, kTip, kTower, kTower, /*best_known=*/-1));
    BOOST_CHECK(node::HeaderSyncMustDriveFetchWhileStalled(
        true, kTip, kTower, /*at_tip_advertised=*/kTip, /*seeded=*/kTower));
    BOOST_CHECK(!node::HeaderSyncMustDriveFetchWhileStalled(
        /*inflight_busy=*/false, kTip, kTower, kTower, kTower));
    BOOST_CHECK(!node::HeaderSyncMustDriveFetchWhileStalled(
        true, kTip, kTower, kTip, kTip));
    BOOST_CHECK(!node::HeaderSyncMustDriveFetchWhileStalled(
        true, kTip, /*header_not_ahead=*/kTip, kTower, kTower));

    // Convergence spread: fetch fires for EVERY body-serving peer with spare
    // capacity even when the global in-flight map is NON-empty (peer 1 already
    // downloading), bounded by the download window -- so a self-qualified
    // archive behind a heavy tower pipelines across peers instead of ~1
    // block/min from one peer.
    BOOST_CHECK(node::HeaderSyncMaySpreadCatchUpFetch(
        /*behind_header_tower=*/true, /*peer_may_serve_bodies=*/true,
        /*peer_blocks_in_flight=*/0, /*max_blocks_per_peer=*/16,
        /*global_blocks_in_flight=*/16, /*download_window=*/1024));
    // Not behind the tower -> no spread.
    BOOST_CHECK(!node::HeaderSyncMaySpreadCatchUpFetch(
        false, true, 0, 16, 16, 1024));
    // Peer cannot serve bodies -> no spread.
    BOOST_CHECK(!node::HeaderSyncMaySpreadCatchUpFetch(
        true, false, 0, 16, 16, 1024));
    // Peer per-peer window already full -> no more from this peer.
    BOOST_CHECK(!node::HeaderSyncMaySpreadCatchUpFetch(
        true, true, /*peer_blocks_in_flight=*/16, 16, 16, 1024));
    // Global download window full -> stop adding work.
    BOOST_CHECK(!node::HeaderSyncMaySpreadCatchUpFetch(
        true, true, 0, 16, /*global_blocks_in_flight=*/1024, 1024));

    BOOST_CHECK(node::HeaderSyncIbdFetchFallbackMayDownload(
        /*peer_inflight=*/0, /*max_per_peer=*/16, /*downloading=*/0, /*cap=*/8));
    BOOST_CHECK(node::HeaderSyncIbdFetchFallbackMayDownload(1, 16, 1, 8));
    BOOST_CHECK(!node::HeaderSyncIbdFetchFallbackMayDownload(
        /*peer_full=*/16, 16, 1, 8));
    BOOST_CHECK(!node::HeaderSyncIbdFetchFallbackMayDownload(0, 16, /*at_cap=*/8, 8));

    BOOST_CHECK(node::HeaderSyncMayFetchParkedHeavierTower(
        /*stalled=*/true, /*trusted_mirror=*/false, /*parked=*/true,
        /*heavier=*/true, kTower, kTip));
    BOOST_CHECK(!node::HeaderSyncMayFetchParkedHeavierTower(
        true, false, true, true, kTip + 2, kTip));
    BOOST_CHECK(!node::HeaderSyncMayFetchParkedHeavierTower(
        true, false, true, true,
        kTip + node::HEADER_SYNC_SHORT_COMPETING_LOCATOR_LEAD, kTip));
    BOOST_CHECK(node::HeaderSyncMayFetchParkedHeavierTower(
        true, false, true, true,
        kTip + node::HEADER_SYNC_SHORT_COMPETING_LOCATOR_LEAD + 1, kTip));
    BOOST_CHECK(!node::HeaderSyncMayFetchParkedHeavierTower(
        /*not_stalled=*/false, false, true, true, kTower, kTip));
    BOOST_CHECK(!node::HeaderSyncMayFetchParkedHeavierTower(
        true, /*trusted_mirror=*/true, true, true, kTower, kTip));
    BOOST_CHECK(!node::HeaderSyncMayFetchParkedHeavierTower(
        true, false, /*not_parked=*/false, true, kTower, kTip));
    BOOST_CHECK(!node::HeaderSyncMayFetchParkedHeavierTower(
        true, false, true, /*not_heavier=*/false, kTower, kTip));

    BOOST_CHECK(!node::HeaderSyncSkipPeerWithoutBodyAvailability(
        /*has_served=*/true, false, false, /*any_served=*/true));
    BOOST_CHECK(!node::HeaderSyncSkipPeerWithoutBodyAvailability(
        false, /*manual=*/true, false, true));
    BOOST_CHECK(!node::HeaderSyncSkipPeerWithoutBodyAvailability(
        false, false, /*gpu=*/true, true));
    BOOST_CHECK(!node::HeaderSyncSkipPeerWithoutBodyAvailability(
        false, false, false, /*nobody_served_yet=*/false));
    BOOST_CHECK(node::HeaderSyncSkipPeerWithoutBodyAvailability(
        false, false, false, /*any_served=*/true));
    BOOST_CHECK(!node::HeaderSyncInFlightPayloadGrantsGrace(0));
    BOOST_CHECK(node::HeaderSyncInFlightPayloadGrantsGrace(1));
    BOOST_CHECK(node::HeaderSyncInFlightPayloadGrantsGrace(4095));
}

BOOST_AUTO_TEST_SUITE_END()
