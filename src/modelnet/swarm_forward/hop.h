// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_HOP_H
#define BITCOIN_MODELNET_SWARM_FORWARD_HOP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One accepted forward. No hashlock is stored. Storing a hop does not
 * qualify the route and does not broadcast.
 */
struct SwarmForwardHop {
    std::string channel;
    std::string payment_id;
    int64_t amount{0};
    bool incoming_committed{false};
    int incoming_expiry{0};
    int outgoing_expiry{0};
    int height{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_HOP_H
