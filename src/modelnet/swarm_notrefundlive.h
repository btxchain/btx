// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREFUNDLIVE_H
#define BTX_MODELNET_SWARM_NOTREFUNDLIVE_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_refund asks this note to treat a
 * refund that reached maturity during a network disruption as a live channel
 * and broadcast it.
 *
 * A refund reaching maturity during a network disruption is not a live
 * channel. refunded and broadcast stay false on every path.
 */
struct SwarmNotRefundLive {
    std::string channel_id;
    bool want_refund{false};
};

/**
 * Outcome of noting a refund. refunded and broadcast stay false on every
 * path: a refund reaching maturity during a network disruption is not a
 * live channel.
 */
struct SwarmNotRefundLiveResult {
    std::string code;
    bool refunded{false};
    bool broadcast{false};
};

/**
 * Note a refund without treating it as a live channel or broadcasting it.
 * Order, first match wins: an empty channel_id is CHANNEL. want_refund is
 * NOT_LIVE. Otherwise the note is NOTED and err is clear.
 * refunded and broadcast stay false on every path. A refund reaching
 * maturity during a network disruption is not a live channel.
 */
SwarmNotRefundLiveResult SwarmNoteNotRefundLive(const SwarmNotRefundLive& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREFUNDLIVE_H
