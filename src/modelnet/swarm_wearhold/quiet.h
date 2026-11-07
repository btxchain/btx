// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARHOLD_QUIET_H
#define BITCOIN_MODELNET_SWARM_WEARHOLD_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Status this plane keeps fixed. There is no setter.
 * automatic_spend() stays "0". broadcast() stays false.
 * bytes_moved() stays 0. gpu() stays false.
 * Measuring joules and refusing a charge do not change them.
 */
class SwarmWearHoldQuiet {
public:
    std::string automatic_spend() const;
    bool broadcast() const;
    int64_t bytes_moved() const;
    bool gpu() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARHOLD_QUIET_H
