// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_OPEN_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_OPEN_H

#include <modelnet/swarm_fourscale/book.h>

#include <string>

namespace modelnet {

/**
 * Plants online, daily, weekly, and generational at step 0.
 * The first call returns true and clears err.
 * A second call is REPLAY and leaves every step where it is.
 */
class SwarmFourScaleOpen {
public:
    bool Apply(SwarmFourScaleBook& book, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_OPEN_H
