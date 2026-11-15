// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOOVERLAP2_H
#define BTX_MODELNET_SWARM_NOTNOOVERLAP2_H

#include <string>

namespace modelnet {

/**
 * A local note about one timeout. overlapping says the timeout still
 * overlaps a live claim. want_refund asks this note to refund.
 *
 * An overlapping timeout is held. This note refunds nothing and claims
 * nothing. refunded stays false, and claimed stays false, on every path.
 */
struct SwarmNotNoOverlap2 {
    std::string timeout_id;
    bool overlapping{false};
    bool want_refund{false};
};

/**
 * Outcome of noting a timeout. refunded stays false, and claimed stays
 * false, on every path. An overlapping timeout is held, and this note
 * refunds nothing and claims nothing.
 */
struct SwarmNotNoOverlap2Result {
    std::string code;
    bool refunded{false};
    bool claimed{false};
};

/**
 * Note a timeout without refunding or claiming it. Order, first match
 * wins: an empty timeout_id is TIMEOUT. If overlapping is true, the note
 * is HELD even when want_refund is false. want_refund is HELD. Otherwise
 * the note is NOTED and err is cleared. refunded stays false and claimed
 * stays false on every path. An overlapping timeout is held.
 */
SwarmNotNoOverlap2Result SwarmNoteNotNoOverlap2(const SwarmNotNoOverlap2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOOVERLAP2_H
