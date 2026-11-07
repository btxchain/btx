// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PASSHOLD_GATE_H
#define BITCOIN_MODELNET_SWARM_PASSHOLD_GATE_H

#include <modelnet/swarm_passhold/book.h>

#include <string>

namespace modelnet {

/**
 * What Request should do with name.
 * code is PASSTHROUGH, REPLAY, or empty when the name may be stored.
 * store is true only for a new non-empty name.
 * Storing the name does not start it and does not pass it.
 * This function does not modify the book.
 */
struct SwarmPassHoldDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Request.
 * An empty name is PASSTHROUGH and is not stored.
 * A name already stored is REPLAY. The first request stays.
 * Any other name may be stored. The caller then returns NOT_STARTED.
 * PASSTHROUGH is decided before REPLAY. REPLAY is decided before NOT_STARTED.
 */
SwarmPassHoldDecision SwarmPassHoldDecide(const SwarmPassHoldBook& book, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PASSHOLD_GATE_H
