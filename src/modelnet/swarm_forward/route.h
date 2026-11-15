// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_ROUTE_H
#define BITCOIN_MODELNET_SWARM_FORWARD_ROUTE_H

namespace modelnet {

/**
 * Route qualification for a forward hop.
 * A hashlock is not a qualified route. qualified() stays false whether
 * or not a hashlock was offered. Nothing is broadcast from here.
 */
class SwarmForwardRoute {
public:
    bool qualified(bool hashlock_present) const;
    bool broadcast() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_ROUTE_H
