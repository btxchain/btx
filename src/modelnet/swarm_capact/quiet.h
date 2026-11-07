// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_QUIET_H
#define BITCOIN_MODELNET_SWARM_CAPACT_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * What a capability action is not allowed to do.
 * launched() stays false. bytes_moved() stays 0. gpu() stays false.
 * automatic_spend() stays "0". There is no setter for any of them.
 * Nothing is launched.
 */
class SwarmCapActQuiet {
public:
    bool launched() const;
    int64_t bytes_moved() const;
    bool gpu() const;
    std::string automatic_spend() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_QUIET_H
