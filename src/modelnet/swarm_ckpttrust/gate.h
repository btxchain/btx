// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_GATE_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_GATE_H

#include <modelnet/swarm_ckpttrust/book.h>

#include <string>

namespace modelnet {

/**
 * What Trust should do with claim.
 * code is CLAIM, REPLAY, or empty when the claim may be stored.
 * store is true only for a new non-empty claim.
 * Storing the claim does not mark it trusted.
 * A checkpoint-only claim is not lineage authority.
 * This function does not modify the book.
 */
struct SwarmCheckpointTrustDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Trust.
 * An empty claim is CLAIM and is not stored.
 * A claim already stored is REPLAY. The first claim stays.
 * Any other claim may be stored. The caller then returns NOT_TRUST.
 * CLAIM is decided before REPLAY. REPLAY is decided before NOT_TRUST.
 */
SwarmCheckpointTrustDecision SwarmCheckpointTrustDecide(const SwarmCheckpointTrustBook& book, const std::string& claim);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_GATE_H
