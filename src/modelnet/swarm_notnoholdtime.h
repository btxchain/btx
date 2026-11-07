// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOLDTIME_H
#define BTX_MODELNET_SWARM_NOTNOHOLDTIME_H

#include <string>

namespace modelnet {

/**
 * A local note about one dispute timeout. dispute_id names the dispute.
 * overlap records a window where one side can refund while the other
 * can still claim. want_refund asks this note to refund.
 *
 * A timeout that lets one side refund while the other can still claim
 * is held. refunded and claimed stay false on every path.
 */
struct SwarmNotNoHoldTime {
    std::string dispute_id;
    bool overlap{false};
    bool want_refund{false};
};

/**
 * Outcome of noting a dispute timeout. refunded and claimed stay false
 * on every path. A timeout that lets one side refund while the other
 * can still claim is held.
 */
struct SwarmNotNoHoldTimeResult {
    std::string code;
    bool refunded{false};
    bool claimed{false};
};

/**
 * Note a dispute timeout without refunding or claiming it. Order, first
 * match wins: an empty dispute_id is DISPUTE. overlap true is HELD even
 * when want_refund is false. want_refund is HELD. Otherwise the note is
 * NOTED and err is cleared. refunded and claimed stay false on every
 * path. A timeout that lets one side refund while the other can still
 * claim is held.
 */
SwarmNotNoHoldTimeResult SwarmNoteNotNoHoldTime(const SwarmNotNoHoldTime& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOLDTIME_H
