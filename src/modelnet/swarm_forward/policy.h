// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_POLICY_H
#define BITCOIN_MODELNET_SWARM_FORWARD_POLICY_H

#include <modelnet/swarm_forward/route.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Observers for the forward plane.
 * qualified() is false. broadcast() is false. bytes_moved() is 0.
 * automatic_spend() is "0". A hashlock does not change any of these.
 */
class SwarmForwardPolicy {
public:
    bool qualified() const;
    bool broadcast() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;

private:
    SwarmForwardRoute m_route;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_POLICY_H
