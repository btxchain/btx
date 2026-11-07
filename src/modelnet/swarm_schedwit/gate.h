// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_GATE_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_GATE_H

#include <modelnet/swarm_schedwit/book.h>

#include <string>

namespace modelnet {

/**
 * What Sign should do with witness.
 * code is WITNESS, REPLAY, or empty when the witness may be stored.
 * store is true only for a new non-empty witness.
 * Storing the witness does not sign it.
 * This function does not modify the book.
 */
struct SwarmSchedWitnessDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Sign.
 * An empty witness is WITNESS and is not stored.
 * A witness already stored is REPLAY. The first witness stays.
 * Any other witness may be stored. The caller then returns NOT_SIGNED.
 * WITNESS is decided before REPLAY. REPLAY is decided before NOT_SIGNED.
 */
SwarmSchedWitnessDecision SwarmSchedWitnessDecide(const SwarmSchedWitnessBook& book, const std::string& witness);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_GATE_H
