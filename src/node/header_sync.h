// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_HEADER_SYNC_H
#define BTX_NODE_HEADER_SYNC_H

#include <chain.h>

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
 * already extends the tip so we still ask for tip+N+1. A heavier valid
 * disconnected fork above the tip is the locator origin (jarekpiot:
 * chasing 0d5ffded@199398 must not restart at the losing connected tip).
 */
[[nodiscard]] inline const CBlockIndex* HeaderSyncLocatorStart(
    const CBlockIndex* best_header, const CBlockIndex* active_tip)
{
    if (active_tip == nullptr) return best_header;
    if (best_header == nullptr) return active_tip;
    if (best_header->nHeight >= active_tip->nHeight &&
        best_header->GetAncestor(active_tip->nHeight) == active_tip) {
        return best_header;
    }
    if (best_header->nHeight < active_tip->nHeight) {
        return active_tip;
    }
    if (best_header->nChainWork > active_tip->nChainWork) {
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
 * 2026-08-27 on macpro2: 82 connections, peer_count 0). Learning a
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
    int32_t peer_starting_height)
{
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
 * m_last_getheaders_timestamp and immediately re-sent).
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
    if (HeaderSyncAdvertisedHeightUnusable(local_tip_height,
                                           peer_starting_height)) {
        return false;
    }
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
 *  so header sync cannot deadlock. */
[[nodiscard]] inline bool MayClaimInitialHeadersSyncSlot(
    bool slot_free,
    bool sync_blocks_and_headers_from_peer,
    bool peer_preferred,
    bool any_preferred_peer_connected)
{
    if (!slot_free || !sync_blocks_and_headers_from_peer) return false;
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

} // namespace node

#endif // BTX_NODE_HEADER_SYNC_H
