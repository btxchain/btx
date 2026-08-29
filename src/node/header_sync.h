// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_HEADER_SYNC_H
#define BTX_NODE_HEADER_SYNC_H

#include <chain.h>

#include <algorithm>
#include <chrono>
#include <cstdint>

namespace node {

/**
 * Locator origin for getheaders.
 *
 * Bitcoin uses m_best_header as "headers ≥ tip". PreferTrustAdjustedHeader
 * can rank a fully-authenticated ancestor (live: headers=199024) above a
 * long unauthenticated connected tip (blocks=199310). Locators then start
 * 286 blocks behind the active chain, and the only peer advertising above
 * us answers from the 0.34.1 fork (33c834f8) in a hot loop.
 *
 * Use the connected tip when best_header is behind it, or on a competing
 * fork that is not strictly heavier. Keep a HEADER_ONLY suffix that
 * already extends the tip so we still ask for tip+N+1.
 *
 * A short heavier disconnected fork (lead ≤ HEADER_SYNC_SHORT_COMPETING_LOCATOR_LEAD)
 * is still the locator origin (jarekpiot: chasing 0d5ffded@199398 must not
 * restart at the losing connected tip). A long HEADER_ONLY competing
 * tower (a live consensus-archive node 2026-08-29: tip 199385, m_best_header 199801 on
 * withdrawn 33c834f8) must not be: locators from that tower never learn
 * tip-extending headers from peers advertising above us, so BestKnown
 * stays at the frozen tip and FindNextBlocks reports already_at_peer_best.
 */
inline constexpr int HEADER_SYNC_SHORT_COMPETING_LOCATOR_LEAD{6};

[[nodiscard]] inline bool HeaderSyncChaseHeavierCompetingLocator(
    bool extends_active_tip,
    bool heavier,
    int32_t best_header_height,
    int32_t tip_height)
{
    if (extends_active_tip || !heavier) return false;
    if (best_header_height <= tip_height) return false;
    return (best_header_height - tip_height) <=
           HEADER_SYNC_SHORT_COMPETING_LOCATOR_LEAD;
}

[[nodiscard]] inline const CBlockIndex* HeaderSyncLocatorStart(
    const CBlockIndex* best_header, const CBlockIndex* active_tip)
{
    if (active_tip == nullptr) return best_header;
    if (best_header == nullptr) return active_tip;
    const bool extends_tip{
        best_header->nHeight >= active_tip->nHeight &&
        best_header->GetAncestor(active_tip->nHeight) == active_tip};
    if (extends_tip) {
        return best_header;
    }
    if (best_header->nHeight < active_tip->nHeight) {
        return active_tip;
    }
    if (HeaderSyncChaseHeavierCompetingLocator(
            /*extends_active_tip=*/false,
            best_header->nChainWork > active_tip->nChainWork,
            best_header->nHeight, active_tip->nHeight)) {
        return best_header;
    }
    return active_tip;
}

/**
 * Whether `best_known` is a descendant of the connected tip (including
 * the tip itself). Null is not an extension: treating it as one sealed
 * minority-tip nodes out of getheaders whenever a caller omitted the
 * explicit BestKnown-is-null flag (live 0.34.4: default
 * `best_known_extends_tip=true` plus `pindexBestKnownBlock==nullptr`
 * counted as extending).
 */
[[nodiscard]] inline bool HeaderSyncBestKnownExtendsTip(
    const CBlockIndex* best_known, const CBlockIndex* active_tip)
{
    if (best_known == nullptr || active_tip == nullptr) return false;
    if (best_known->nHeight < active_tip->nHeight) return false;
    return best_known->GetAncestor(active_tip->nHeight) == active_tip;
}

/**
 * True when we must send getheaders to learn a peer's best block.
 *
 * True iff we have no best-known block for the peer and it advertises
 * above our local tip -- or, when our tip is STALE, at our tip or above
 * it. On a stalled chain every peer sits at exactly our height, so the
 * strict > form never probed anyone: peer tips stayed unknown
 * (synced_headers=-1), and the mining chain guard -- which counts only
 * peers with a KNOWN tip -- reported peer_count=0 /
 * insufficient_peer_consensus with dozens of live connections (measured
 * 2026-08-27 on <node>: 82 connections, peer_count 0). Learning a
 * same-height peer's tip is one rate-limited getheaders
 * (BEST_KNOWN_PROBE_INTERVAL) and is a read; it cannot feed us a chain
 * we would not validate.
 *
 * `headers_in_flight` is accepted so callers can pass the live
 * SendMessages snapshot; it is never a gate. Never consults
 * preferred-peer count, IBD, or MatMul service bits (0.34.1 F1).
 *
 * `best_known_height` is -1 when BestKnown is null. A peer whose
 * BestKnown is pinned at our own tip (or below) while VERSION
 * advertised above us must still be probed: otherwise getheaders
 * stops after the first duplicate batch and we never learn tip+1.
 *
 * `best_known_extends_tip` is false when BestKnown sits on a competing
 * fork (GetAncestor(tip) != tip). Height-alone treated that peer as
 * already "ahead" and sent zero getheaders (live 0.34.4: tip 199310 on
 * 8b5da5a5, BestKnown 199382 on 33c834f8, peer VERSION 199523, unauth
 * lead cap 72). A competing BestKnown is not an extension of our tip.
 *
 * VERSION is a handshake snapshot. Peers advertising height 0 / unset
 * or below our connected tip are never probed (live 0.34.5: 171
 * getheaders/sec to one peer, including height-0 advertisers). Same-
 * height peers are still probed when the tip is stale so we can learn
 * tip+1.
 */
[[nodiscard]] inline bool HeaderSyncAdvertisedHeightUnusable(
    int32_t local_tip_height,
    int32_t peer_starting_height,
    int32_t best_known_height = -1)
{
    // Live BestKnown is the real tip we have learned. VERSION is a
    // handshake snapshot: a peer that connected below tip (or at 0)
    // must not be permanently excluded after it catches up (SF-5).
    if (best_known_height >= 0) {
        return local_tip_height > 0 && best_known_height < local_tip_height;
    }
    // Unset VERSION (-1) is not a tip to chase. Height 0 is genesis:
    // skip it only once we ourselves are past genesis (live 0.34.5:
    // probes to peers advertising 0). A peer behind our connected tip
    // cannot supply the HEADER_ONLY suffix we are downloading.
    if (peer_starting_height < 0) return true;
    if (peer_starting_height == 0 && local_tip_height > 0) return true;
    if (local_tip_height > 0 && peer_starting_height < local_tip_height) {
        return true;
    }
    return false;
}

/**
 * Per-peer best-known probe pacing. `have_prior_probe` is false until
 * this peer has been asked. Elapsed time is not reset when headers
 * arrive — that was the live spam (duplicate suffix replies cleared
 * m_last_getheaders_timestamp). Send rate is m_last_getheaders_sent,
 * which connecting replies must not reset.
 */
[[nodiscard]] inline bool HeaderSyncProbeIntervalElapsed(
    bool have_prior_probe,
    std::chrono::microseconds since_prior,
    std::chrono::microseconds min_interval)
{
    if (!have_prior_probe) return true;
    return since_prior > min_interval;
}

/**
 * Uncapped tip-extending header lead vs the signed-frontier cap used
 * for 1-wide catch-up. A GPU at its own frontier with a 947-block
 * HEADER_ONLY suffix has capped ahead=0, so IsCatchUpBlockFetch is
 * false; download timeout / parallel-owner failover must still run.
 */
[[nodiscard]] inline bool FollowedHeaderSuffixNeedsDownloadFailover(
    int tip_height,
    int uncapped_followed_ahead,
    int stall_headers_ahead = 2)
{
    if (tip_height < 0) return false;
    return uncapped_followed_ahead >= stall_headers_ahead;
}

/** GPU-protect 1-wide / HEADER_ONLY competing must yield when the node is
 *  this far behind the followed header tip. A signer that cannot sync is
 *  worse than a signer whose GPU is briefly busy. Also the absolute
 *  no-pause / no-disconnect bar for slow block delivery: the eligible
 *  GETDATA pool is tiny (manual/noban + outbound archive/mirror), and
 *  disconnecting those sources is why catch-up sprinted then starved
 *  (live 0.34.5 after eae5de60: 19 blocks in 5 min, then 3 min dead,
 *  60 disconnects). */
inline constexpr int CATCHUP_FAR_BEHIND_YIELD{100};

[[nodiscard]] inline bool CatchUpFarBehindYieldsGpuProtect(
    int uncapped_followed_ahead,
    int far_behind_yield = CATCHUP_FAR_BEHIND_YIELD)
{
    return uncapped_followed_ahead >= far_behind_yield;
}

[[nodiscard]] inline bool HeaderSyncMustProbe(
    int32_t local_tip_height,
    int32_t peer_starting_height,
    bool best_known_is_null,
    bool tip_is_stale,
    bool headers_in_flight,
    int32_t best_known_height = -1,
    bool best_known_extends_tip = false)
{
    (void)headers_in_flight;
    const int32_t known_for_unusable = best_known_is_null ? -1 : best_known_height;
    if (HeaderSyncAdvertisedHeightUnusable(local_tip_height,
                                           peer_starting_height,
                                           known_for_unusable)) {
        return false;
    }
    // VERSION was behind (or height 0) but HEADERS/INV have already shown
    // this peer above tip: still probe. Do not take this path when VERSION
    // itself was usable — BestKnown ahead on our chain must stay a skip.
    const bool version_unusable =
        HeaderSyncAdvertisedHeightUnusable(local_tip_height, peer_starting_height);
    if (version_unusable && best_known_height > local_tip_height) {
        return true;
    }
    if (version_unusable) return false;
    const auto known_not_ahead = [&] {
        if (best_known_is_null) return true;
        if (!best_known_extends_tip) return true;
        return best_known_height <= local_tip_height;
    };
    if (peer_starting_height > local_tip_height) {
        return known_not_ahead();
    }
    if (!tip_is_stale || local_tip_height < 0) return false;
    return known_not_ahead();
}

/**
 * Mainnet checkpoint 186000 is the nMinimumChainWork IBD anchor. A peer
 * advertising below it cannot finish HeadersSyncState presync past that
 * work, so it burns the single nSyncStarted slot and disconnects
 * (MendeMatthias / v0.34.4: 128530 / 185109 / 189611 got 23–29 MB of
 * getheaders while 200131 got one 90-byte request).
 *
 * Anchor height <= 0 (regtest, empty checkpoints) treats every peer as
 * meeting the bar.
 */
[[nodiscard]] inline bool InitialHeadersSyncPeerMeetsAnchor(
    int32_t peer_starting_height, int32_t checkpoint_anchor_height)
{
    if (checkpoint_anchor_height <= 0) return true;
    return peer_starting_height >= checkpoint_anchor_height;
}

[[nodiscard]] inline bool InitialHeadersSyncPeerPreferred(
    int32_t peer_starting_height,
    int32_t checkpoint_anchor_height,
    bool peer_failed_low_work_headers_sync)
{
    if (peer_failed_low_work_headers_sync) return false;
    return InitialHeadersSyncPeerMeetsAnchor(peer_starting_height,
                                             checkpoint_anchor_height);
}

/** Claim the scarce initial IBD headers-sync slot (nSyncStarted == 0).
 *  When any connected peer is preferred, a non-preferred peer must not
 *  take it. When none is connected, a non-preferred peer may still claim
 *  so header sync cannot deadlock — except an address currently in
 *  low-work presync backoff: retrying it immediately was the live
 *  161-presync / 162-abort livelock (empty datadir, 45 minutes,
 *  headers=0). */
[[nodiscard]] inline bool MayClaimInitialHeadersSyncSlot(
    bool slot_free,
    bool sync_blocks_and_headers_from_peer,
    bool peer_preferred,
    bool any_preferred_peer_connected,
    bool peer_in_low_work_backoff = false)
{
    if (!slot_free || !sync_blocks_and_headers_from_peer) return false;
    if (peer_in_low_work_backoff) return false;
    if (any_preferred_peer_connected && !peer_preferred) return false;
    return true;
}

/** A preferred peer may take the slot from a non-preferred holder so a
 *  short-chain presync cannot occupy the only IBD slot while a
 *  checkpoint-height peer is live. */
[[nodiscard]] inline bool ShouldYieldInitialHeadersSyncSlot(
    bool holder_has_slot,
    bool holder_preferred,
    bool challenger_preferred)
{
    return holder_has_slot && !holder_preferred && challenger_preferred;
}

/** Progressive retry after a low-work HeadersSyncState abort. Base matches
 *  BEST_KNOWN_PROBE_INTERVAL (2 min); doubles per failure, capped. */
inline constexpr auto LOW_WORK_HEADERS_FAILURE_BACKOFF_BASE{std::chrono::minutes{2}};
inline constexpr auto LOW_WORK_HEADERS_FAILURE_BACKOFF_MAX{std::chrono::minutes{32}};

[[nodiscard]] inline std::chrono::seconds LowWorkHeadersFailureBackoff(int fail_count)
{
    if (fail_count <= 0) return std::chrono::seconds{0};
    int shift = fail_count - 1;
    if (shift > 4) shift = 4;
    auto delay = LOW_WORK_HEADERS_FAILURE_BACKOFF_BASE * (1 << shift);
    if (delay > LOW_WORK_HEADERS_FAILURE_BACKOFF_MAX) {
        delay = LOW_WORK_HEADERS_FAILURE_BACKOFF_MAX;
    }
    return std::chrono::duration_cast<std::chrono::seconds>(delay);
}

[[nodiscard]] inline bool LowWorkHeadersFailureInBackoff(
    bool recorded_failure,
    std::chrono::microseconds now,
    std::chrono::microseconds retry_after)
{
    if (!recorded_failure) return false;
    return now < retry_after;
}

/** Apply BLOCK_DOWNLOAD_TIMEOUT_MIN after the spacing cap, not before.
 *  Fast-phase spacing is 250ms so cap = 750ms < 10s floor; the previous
 *  min(max(computed, floor), cap) discarded the floor and disconnected
 *  the only genesis-to-anchor body source on its first timeout. */
[[nodiscard]] inline std::chrono::microseconds BlockDownloadTimeoutRespectFloor(
    std::chrono::microseconds computed,
    std::chrono::microseconds floor,
    std::chrono::microseconds cap)
{
    return std::max(std::min(computed, cap), floor);
}

/**
 * BestKnown cannot walk toward the HEADER_ONLY tower: unset, or at/below
 * the connected tip. A live consensus-archive node 2026-08-29: peer=29 BestKnown==tip
 * 199386, m_best_header=199801, inflight=0, select=already_at_peer_best.
 */
[[nodiscard]] inline bool HeaderSyncBestKnownStuckAtTip(
    int32_t tip_height,
    int32_t best_known_height)
{
    return best_known_height < 0 || best_known_height <= tip_height;
}

/**
 * Fill BestKnown from m_best_header so FindNextBlocks walks the tower.
 *
 * VERSION height is not a block hash, so a peer advertising T+400 never
 * becomes a GETDATA source until HEADERS arrive. When the node already
 * has those headers, waiting for a duplicate HEADERS batch leaves
 * last_common pinned at the tip. Seed only peers that advertised above
 * us; never an at-tip peer.
 *
 * Raise BestKnown even when it is already slightly above tip: draining
 * two retained bodies left BestKnown at 199389 while m_best_header was
 * 199801, then already_at_peer_best / root_retained_body issued no
 * GETDATA for the rest of the tower (live 2026-08-29). Do not replace a
 * BestKnown already at/above the seed target (min(advertised, tower)).
 *
 * `best_header_extends_or_heavier` is GetAncestor(tip)==tip OR
 * nChainWork > tip. Fetch only; ConnectTip still ExactReplays and PARK
 * still owns depth>6.
 */
[[nodiscard]] inline bool HeaderSyncMaySeedBestKnownFromHeaderTower(
    int32_t tip_height,
    int32_t peer_starting_height,
    int32_t best_known_height,
    int32_t best_header_height,
    bool best_header_extends_or_heavier)
{
    if (tip_height < 0 || best_header_height <= tip_height) return false;
    if (peer_starting_height <= tip_height) return false;
    if (!best_header_extends_or_heavier) return false;
    const int32_t target{std::min(peer_starting_height, best_header_height)};
    if (target <= tip_height) return false;
    if (best_known_height >= target) return false;
    return true;
}

/** Cap the seed at what the peer advertised so we do not ask a 199672
 *  peer for the 199801 tip. */
[[nodiscard]] inline int32_t HeaderSyncSeedBestKnownHeight(
    int32_t tip_height,
    int32_t peer_starting_height,
    int32_t best_header_height)
{
    const int32_t capped{std::min(peer_starting_height, best_header_height)};
    if (capped <= tip_height) return -1;
    return capped;
}

/**
 * inflight=0 while m_best_header is already ahead: SendMessages must
 * still run FindNextBlocks / GETDATA. Seeding BestKnown does not wait
 * for an inbound BLOCK. A live consensus-archive node 2026-08-29: seed logged seven
 * times, inflight stayed 0, no root-first GETDATA.
 */
[[nodiscard]] inline bool HeaderSyncMustDriveFetchWhileStalled(
    bool inflight_empty,
    int32_t tip_height,
    int32_t best_header_height,
    int32_t peer_starting_height,
    int32_t best_known_height,
    int stall_ahead = 2)
{
    if (!inflight_empty) return false;
    if (tip_height < 0) return false;
    if (best_header_height - tip_height < stall_ahead) return false;
    return peer_starting_height > tip_height ||
           best_known_height > tip_height;
}
/** N/A-seed convergence: once ONE peer has in-flight blocks,
 *  HeaderSyncMustDriveFetchWhileStalled (which requires a GLOBALLY empty
 *  in-flight map) stops firing, and in IBD the sync-slot gate blocks every
 *  other peer, so a self-qualified archive behind a heavy header tower fetches
 *  one-peer-at-a-time (~1 block/min against a 400+ block gap). Permit SPREADING
 *  the catch-up fetch across every body-serving peer concurrently: fire for a
 *  peer that can serve bodies and still has spare per-peer in-flight capacity,
 *  as long as the GLOBAL in-flight count is below the download window. This
 *  does not require the global map to be empty, so peers 2..N pipeline
 *  alongside peer 1. Per-peer MAX_BLOCKS_IN_TRANSIT_PER_PEER and the global
 *  BLOCK_DOWNLOAD_WINDOW still bound total outstanding work, and every body is
 *  still fully ExactReplay'd before ConnectTip. The connectability of the
 *  followed tower (extends / short-reorg / parked) is still decided by
 *  FindNextBlocksToDownload's branch gates. */
[[nodiscard]] inline bool HeaderSyncMaySpreadCatchUpFetch(
    bool behind_header_tower,
    bool peer_may_serve_bodies,
    size_t peer_blocks_in_flight,
    size_t max_blocks_per_peer,
    size_t global_blocks_in_flight,
    size_t download_window)
{
    if (!behind_header_tower) return false;
    if (!peer_may_serve_bodies) return false;
    if (peer_blocks_in_flight >= max_blocks_per_peer) return false;
    return global_blocks_in_flight < download_window;
}

/** IBD inbound/non-preferred fallback. One in-flight block anywhere used
 *  to exclude every fallback peer (mapBlocksInFlight.empty()). Per-peer
 *  slots plus a bounded global peer cap restore parallelism. */
[[nodiscard]] inline bool HeaderSyncIbdFetchFallbackMayDownload(
    size_t peer_blocks_in_flight,
    int max_blocks_per_peer,
    int peers_downloading,
    int max_parallel_peers)
{
    if (max_blocks_per_peer <= 0 || max_parallel_peers <= 0) return false;
    if (peer_blocks_in_flight >= static_cast<size_t>(max_blocks_per_peer)) {
        return false;
    }
    return peers_downloading < max_parallel_peers;
}

/** PARK must not freeze GETDATA of a long heavier HEADER_ONLY tower.
 *  FindNextBlocksToDownload used to return at PARKED_NEEDS_OPERATOR
 *  whenever BestKnown sat on a parked root (live 2026-08-29: seed to
 *  199801, phase=followed-branch-parked, inflight=0, zero root-first
 *  summaries). Short parked peers stay suppressed (lead ≤ 6, same as
 *  HeaderSyncChaseHeavierCompetingLocator). ConnectTip / DeepReorgShouldPark
 *  are unchanged — this is fetch only. */
[[nodiscard]] inline bool HeaderSyncMayFetchParkedHeavierTower(
    bool stalled_behind_header_tower,
    bool trusted_mirror,
    bool parked_best_known,
    bool best_work_gt_tip,
    int32_t best_known_height,
    int32_t tip_height)
{
    if (!stalled_behind_header_tower) return false;
    if (trusted_mirror) return false;
    if (!parked_best_known) return false;
    if (!best_work_gt_tip) return false;
    if (tip_height < 0) return false;
    return (best_known_height - tip_height) >
           HEADER_SYNC_SHORT_COMPETING_LOCATOR_LEAD;
}

/** Prefer peers that have delivered a body once any peer has. Header-only
 *  BestKnown work is not availability. Manual/noban/GPU/frontier stay
 *  eligible so bootstrap and the signer are not skipped. Fresh IBD (no
 *  peer has served) keeps the work-only gate. Fetch preference only. */
[[nodiscard]] inline bool HeaderSyncSkipPeerWithoutBodyAvailability(
    bool has_served_block,
    bool manual_or_noban,
    bool gpu_or_frontier_source,
    bool any_peer_has_served)
{
    if (has_served_block) return false;
    if (manual_or_noban || gpu_or_frontier_source) return false;
    return any_peer_has_served;
}

/** E-1: a request stays "delivering" only while it has received payload
 *  AND has been in flight less than this. A dribble of near-empty messages
 *  (e.g. a 33-byte zero-tx BLOCKTXN that never completes the compact block)
 *  must not grant INDEFINITE grace and pin the in-flight slot forever,
 *  defeating RB-5/N5 rotation and every download-expiry path. */
inline constexpr auto HEADER_SYNC_INFLIGHT_GRACE_MAX_AGE{std::chrono::minutes{5}};

/** ExpireOverdue grants grace iff this GETDATA has received payload
 *  bytes AND has not been in flight past HEADER_SYNC_INFLIGHT_GRACE_MAX_AGE.
 *  Peer-total nRecvBytes (pings, addrs, prior traffic) is not a substitute,
 *  and there is no 4KiB chatter margin (SF-6). The age cap is the E-1 fix:
 *  a genuinely-delivering peer finishes a block in well under the cap, while
 *  a trickle-staller's slot is reclaimed instead of pinned forever. Callers
 *  that pass only recv_bytes (unit tests, non-catch-up paths) keep the old
 *  unbounded-any-byte behavior via the defaults. */
[[nodiscard]] inline bool HeaderSyncInFlightPayloadGrantsGrace(
    uint64_t recv_bytes_for_request,
    std::chrono::microseconds request_age = std::chrono::microseconds::zero(),
    std::chrono::microseconds max_grace_age = std::chrono::microseconds::max())
{
    if (recv_bytes_for_request == 0) return false;
    return request_age < max_grace_age;
}
/** C2/E-1/E-6: which CONSENSUS peers get catch-up serve privileges (getdata
 *  drain, cached-MMATTEST serve, body-ingest bypass). Gate on ESTABLISHED
 *  progress (a real BestKnown from exchanged headers) so a silent inbound
 *  sybil that only advertised NODE_MATMUL_CONSENSUS + a low, unauthenticated
 *  VERSION height gets nothing. Fork-aware: a peer that is behind our tip
 *  (honest catch-up) OR on a competing fork at similar/greater height (needs
 *  our active-chain MMATTEST to corroborate) both qualify. */
[[nodiscard]] inline bool ConsensusCatchUpServeEligible(
    bool peer_is_consensus,
    bool best_known_established,
    bool peer_behind_our_tip,
    bool peer_on_competing_fork)
{
    if (!peer_is_consensus) return false;
    if (!best_known_established) return false;
    return peer_behind_our_tip || peer_on_competing_fork;
}

/** Direct-fetch cap: 1-wide catch-up used to request only the single
 *  lowest hole per HEADERS event. A proven body source (frontier / GPU /
 *  archive / already served a body) may take the full per-peer window of
 *  lowest missing hashes, still root-first (SF-7). */
[[nodiscard]] inline unsigned int HeadersDirectFetchCap(
    bool root_first_order,
    bool proven_body_source,
    bool one_wide,
    unsigned int max_in_transit,
    unsigned int catchup_one)
{
    if (root_first_order && proven_body_source) return max_in_transit;
    return one_wide ? catchup_one : max_in_transit;
}

} // namespace node

#endif // BTX_NODE_HEADER_SYNC_H
