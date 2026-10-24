// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_SECRET_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_SECRET_H

#include <cstddef>

namespace modelnet {

/**
 * The secret a watched sequence is not allowed to reveal.
 * released() stays false. bytes() stays 0.
 * There is no method that stores secret bytes or marks them released.
 */
class SwarmWatchHoldSecret {
public:
    bool released() const;
    std::size_t bytes() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_SECRET_H
