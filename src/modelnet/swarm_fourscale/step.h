// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_STEP_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_STEP_H

#include <modelnet/swarm_fourscale/book.h>

#include <string>

namespace modelnet {

/**
 * Adds 1 to one planted scale and leaves the other three where they are.
 * Before Open the answer is SCALE and nothing is stored.
 * An empty scale and any unknown scale are SCALE and nothing is stored.
 * A known scale returns true and clears err.
 */
class SwarmFourScaleStep {
public:
    bool Apply(SwarmFourScaleBook& book, const std::string& scale, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_STEP_H
