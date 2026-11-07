// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MINEHOLD_QUIET_H
#define BITCOIN_MODELNET_SWARM_MINEHOLD_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * Counters this plane keeps fixed. There is no setter.
 * bytes_moved() stays 0. broadcast() stays false. gpu() stays false.
 * Recording a name does not change them. Nothing is sent.
 */
class SwarmMineHoldQuiet {
public:
    int64_t bytes_moved() const;
    bool broadcast() const;
    bool gpu() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MINEHOLD_QUIET_H
