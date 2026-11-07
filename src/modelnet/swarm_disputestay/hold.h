// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_HOLD_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_HOLD_H

#include <string>

namespace modelnet {

/**
 * Settle refusal for a dispute.
 * An empty id is DISPUTE. Every other id is HELD.
 * settled() stays false. There is no setter that releases the hold,
 * and this type does not store an id or add atoms.
 */
class SwarmDisputeStayHold {
public:
    std::string refusal(const std::string& dispute) const;
    bool settled() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_HOLD_H
