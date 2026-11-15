// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_QUIET_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Counters this plane keeps fixed. There is no setter.
 * atoms() stays 0. automatic_spend() stays "0".
 * broadcast() stays false. bytes_moved() stays 0.
 * Accepting a label does not change them. Nothing is spent.
 */
class SwarmPayLabelQuiet {
public:
    int64_t atoms() const;
    std::string automatic_spend() const;
    bool broadcast() const;
    int64_t bytes_moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_QUIET_H
