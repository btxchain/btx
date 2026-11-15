// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_GATE_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_GATE_H

#include <modelnet/swarm_gradhold/book.h>

#include <string>

namespace modelnet {

/**
 * What Offer should do with update_id.
 * code is UPDATE, REPLAY, or empty when the id may be stored.
 * store is true only for a new non-empty id.
 * This function does not modify the book.
 */
struct SwarmGradHoldDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Offer.
 * An empty id is UPDATE and is not stored.
 * An id already stored is REPLAY. The first update stays.
 * Any other id may be stored.
 * UPDATE is decided before REPLAY.
 */
SwarmGradHoldDecision SwarmGradHoldDecide(const SwarmGradHoldBook& book, const std::string& update_id);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_GATE_H
