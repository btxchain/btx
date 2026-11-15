// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT14_H
#define BTX_MODELNET_SWARM_FAULT14_H

#include <string>

namespace modelnet {

/**
 * Live fault 14: a refund reaches maturity during a network disruption.
 * This note does not refund, broadcast, or commit. refunded, broadcast,
 * and committed stay false on every path.
 */
struct SwarmFault14 {
    std::string channel_id;
    bool mature{false};
    bool disrupted{false};
    bool refund_signed{false};
    bool want_broadcast{false};
};

/**
 * Outcome of recovering live fault 14. refunded, broadcast, and committed
 * stay false: a refund that reaches maturity during a network disruption
 * is not broadcast and is not committed.
 */
struct SwarmFault14Result {
    std::string code;
    bool refunded{false};
    bool broadcast{false};
    bool committed{false};
};

/**
 * Recover live fault 14 without refunding, broadcasting, or committing.
 * Order, first match wins:
 * an empty channel_id is CHANNEL. Every result bool stays false and err
 * is CHANNEL.
 * not refund_signed is UNSIGNED, even if want_broadcast or mature.
 * refunded and broadcast stay false and err is UNSIGNED.
 * want_broadcast is HELD. refunded and broadcast stay false and err is
 * cleared.
 * disrupted or mature is NOT_LIVE. refunded and broadcast stay false and
 * err is NOT_LIVE.
 * Otherwise the note is NOTED. refunded and broadcast stay false and err
 * is cleared.
 * refunded, broadcast, and committed stay false on every path.
 */
SwarmFault14Result SwarmRecoverFault14(const SwarmFault14& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT14_H
