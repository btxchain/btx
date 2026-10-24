// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_QUIET_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * Status this plane keeps fixed.
 * bytes_moved() stays 0. gpu() stays false.
 * There is no setter for either of them.
 */
class SwarmFourScaleQuiet {
public:
    int64_t bytes_moved() const;
    bool gpu() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_QUIET_H
