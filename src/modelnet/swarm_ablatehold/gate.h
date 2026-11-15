// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ABLATEHOLD_GATE_H
#define BITCOIN_MODELNET_SWARM_ABLATEHOLD_GATE_H

#include <modelnet/swarm_ablatehold/book.h>

#include <string>

namespace modelnet {

/**
 * What Request should do with name.
 * code is ABLATION, REPLAY, or empty when the name may be stored.
 * store is true only for a new non-empty name.
 * Storing the name does not publish it. This function does not modify the book.
 */
struct SwarmAblateHoldDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Request.
 * An empty name is ABLATION and is not stored.
 * A name already stored is REPLAY. The first request stays.
 * Any other name may be stored. The caller then returns HELD.
 * ABLATION is decided before REPLAY. REPLAY is decided before HELD.
 */
SwarmAblateHoldDecision SwarmAblateHoldDecide(const SwarmAblateHoldBook& book, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ABLATEHOLD_GATE_H
