// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_GATE_H
#define BITCOIN_MODELNET_SWARM_NATPUB_GATE_H

#include <modelnet/swarm_natpub/book.h>

#include <string>

namespace modelnet {

/**
 * What Claim should do with endpoint.
 * code is ENDPOINT, REPLAY, or empty when the endpoint may be stored.
 * store is true only for a new non-empty endpoint.
 * This function does not modify the book.
 */
struct SwarmNatPubDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Claim.
 * An empty endpoint is ENDPOINT and is not stored.
 * An endpoint already stored is REPLAY. The first endpoint stays.
 * Any other endpoint may be stored.
 * ENDPOINT is decided before REPLAY.
 */
SwarmNatPubDecision SwarmNatPubDecide(const SwarmNatPubBook& book, const std::string& endpoint);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_GATE_H
