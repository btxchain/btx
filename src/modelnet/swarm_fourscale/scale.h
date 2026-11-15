// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_SCALE_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_SCALE_H

#include <modelnet/swarm_fourscale/book.h>

#include <string>

namespace modelnet {

/**
 * Accepts a step only for a scale Open has planted.
 * Before Open the answer is SCALE, including for a known name.
 * An empty scale and any other unknown name are SCALE.
 * This function does not write the book.
 */
class SwarmFourScaleScale {
public:
    bool accept(const SwarmFourScaleBook& book, const std::string& scale, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_SCALE_H
