// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_HEADER_SYNC_H
#define BTX_NODE_HEADER_SYNC_H

#include <chain.h>

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
 * VERSION is a handshake snapshot. When the tip is stale, also probe
 * peers who advertised *below* us (live 0.34.3: 57 peers at
 * 199294–199309, the only peer above us on the 0.34.1 fork).
 */
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

} // namespace node

#endif // BTX_NODE_HEADER_SYNC_H
