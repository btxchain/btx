// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_HEADER_SYNC_H
#define BTX_NODE_HEADER_SYNC_H

#include <cstdint>

namespace node {

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
 */
[[nodiscard]] inline bool HeaderSyncMustProbe(
    int32_t local_tip_height,
    int32_t peer_starting_height,
    bool best_known_is_null,
    bool tip_is_stale,
    bool headers_in_flight)
{
    (void)headers_in_flight;
    if (!best_known_is_null) return false;
    if (peer_starting_height > local_tip_height) return true;
    return tip_is_stale && local_tip_height >= 0 &&
           peer_starting_height >= local_tip_height;
}

} // namespace node

#endif // BTX_NODE_HEADER_SYNC_H
