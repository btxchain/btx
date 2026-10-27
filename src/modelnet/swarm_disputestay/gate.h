// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_GATE_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_GATE_H

#include <modelnet/swarm_disputestay/book.h>

#include <string>

namespace modelnet {

/**
 * What Open should do with dispute.
 * code is DISPUTE, REPLAY, or empty when the id may be stored.
 * store is true only for a new non-empty id.
 * This function does not modify the book.
 */
struct SwarmDisputeStayDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Open.
 * An empty id is DISPUTE and is not stored.
 * An id already stored is REPLAY. The first dispute stays.
 * Any other id may be stored.
 * DISPUTE is decided before REPLAY.
 */
SwarmDisputeStayDecision SwarmDisputeStayDecide(const SwarmDisputeStayBook& book, const std::string& dispute);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_GATE_H
