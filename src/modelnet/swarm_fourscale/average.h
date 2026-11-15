// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_AVERAGE_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_AVERAGE_H

#include <string>

namespace modelnet {

/**
 * Refuses to average the four scales.
 * This function takes no book, so it cannot fold one step into another.
 * The answer is always NOT_AVERAGED.
 */
class SwarmFourScaleAverage {
public:
    bool refuse(std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_AVERAGE_H
