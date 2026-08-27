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
 * True iff the peer advertises above our local tip and we have no
 * best-known block for it. `tip_is_stale` and `headers_in_flight` are
 * accepted so callers can pass the live SendMessages snapshot; they are
 * never gates. Never consults preferred-peer count, IBD, or MatMul
 * service bits (0.34.1 F1).
 */
[[nodiscard]] inline bool HeaderSyncMustProbe(
    int32_t local_tip_height,
    int32_t peer_starting_height,
    bool best_known_is_null,
    bool tip_is_stale,
    bool headers_in_flight)
{
    (void)tip_is_stale;
    (void)headers_in_flight;
    return best_known_is_null && peer_starting_height > local_tip_height;
}

} // namespace node

#endif // BTX_NODE_HEADER_SYNC_H
