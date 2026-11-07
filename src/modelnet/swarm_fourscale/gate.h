// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_GATE_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_GATE_H

#include <modelnet/swarm_fourscale/book.h>

#include <string>

namespace modelnet {

/**
 * What Open should do.
 * plant is true only for the first Open. code is REPLAY when the four
 * scales are already planted. This decision does not write the book.
 */
struct SwarmFourScaleOpenDecision {
    std::string code;
    bool plant{false};
};

/**
 * What Step should do.
 * advance is true only for a planted scale. Otherwise code is SCALE.
 * This decision does not write the book.
 */
struct SwarmFourScaleStepDecision {
    std::string code;
    bool advance{false};
};

/** First Open plants. A later Open is REPLAY and must not write. */
SwarmFourScaleOpenDecision SwarmFourScaleDecideOpen(const SwarmFourScaleBook& book);

/**
 * A known planted scale may advance.
 * Before Open, and for an empty or unknown scale, the code is SCALE.
 */
SwarmFourScaleStepDecision SwarmFourScaleDecideStep(const SwarmFourScaleBook& book, const std::string& scale);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_GATE_H
