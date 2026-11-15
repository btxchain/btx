// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTIMEOUT_H
#define BTX_MODELNET_SWARM_NOTNOTIMEOUT_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one channel. refund_open says the refund path is
 * open. claim_open says the claim path is open. want_refund asks this
 * note to refund.
 *
 * A timeout that lets one side refund while the other can still claim
 * is held. This note refunds nothing. refunded stays false, and atoms
 * stays 0, on every path.
 */
struct SwarmNotNoTimeout {
    std::string channel_id;
    bool refund_open{false};
    bool claim_open{false};
    bool want_refund{false};
};

/**
 * Outcome of noting a channel timeout. refunded stays false, and atoms
 * stays 0, on every path. A timeout that lets one side refund while the
 * other can still claim is held, and this note refunds nothing.
 */
struct SwarmNotNoTimeoutResult {
    std::string code;
    bool refunded{false};
    int64_t atoms{0};
};

/**
 * Note a channel timeout without refunding it. Order, first match wins:
 * an empty channel_id is CHANNEL. If refund_open and claim_open are both
 * true, the note is RACE even when want_refund is false. want_refund is
 * HELD. Otherwise the note is NOTED and err is cleared. refunded stays
 * false and atoms stays 0 on every path. A timeout that lets one side
 * refund while the other can still claim is held, and this note refunds
 * nothing.
 */
SwarmNotNoTimeoutResult SwarmNoteNotNoTimeout(const SwarmNotNoTimeout& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTIMEOUT_H
