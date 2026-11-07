// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_GATE_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_GATE_H

#include <modelnet/swarm_holdrot/book.h>

#include <string>

namespace modelnet {

/**
 * What Rotate should do with holdout.
 * code is HOLDOUT, REPLAY, or empty when the holdout may be stored.
 * store is true only for a new non-empty holdout.
 * Storing the holdout does not mark it rotating.
 * This function does not modify the book.
 */
struct SwarmHoldoutRotateDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Rotate.
 * An empty holdout is HOLDOUT and is not stored.
 * A holdout already stored is REPLAY. The first holdout stays.
 * Any other holdout may be stored. The caller then returns NOT_ROTATING.
 * HOLDOUT is decided before REPLAY. REPLAY is decided before NOT_ROTATING.
 */
SwarmHoldoutRotateDecision SwarmHoldoutRotateDecide(const SwarmHoldoutRotateBook& book, const std::string& holdout);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_GATE_H
