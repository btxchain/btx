// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LOGINHOLD_GATE_H
#define BITCOIN_MODELNET_SWARM_LOGINHOLD_GATE_H

#include <modelnet/swarm_loginhold/book.h>

#include <string>

namespace modelnet {

/**
 * What Request should do with name.
 * code is LOGIN, REPLAY, or empty when the name may be stored.
 * store is true only for a new non-empty name.
 * Storing the name does not log it in.
 * This function does not modify the book.
 */
struct SwarmLoginHoldDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Request.
 * An empty name is LOGIN and is not stored.
 * A name already stored is REPLAY. The first request stays.
 * Any other name may be stored. The caller then returns HELD.
 * LOGIN is decided before REPLAY. REPLAY is decided before HELD.
 */
SwarmLoginHoldDecision SwarmLoginHoldDecide(const SwarmLoginHoldBook& book, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LOGINHOLD_GATE_H
