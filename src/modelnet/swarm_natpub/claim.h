// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_CLAIM_H
#define BITCOIN_MODELNET_SWARM_NATPUB_CLAIM_H

#include <modelnet/swarm_natpub/book.h>
#include <modelnet/swarm_natpub/shelf.h>

#include <string>

namespace modelnet {

/**
 * Claims one endpoint and leaves it unpublished.
 * An empty endpoint is ENDPOINT and the book stays as it was.
 * A new non-empty endpoint is stored and the call returns false with HELD.
 * A second Claim of the same endpoint is REPLAY and leaves the first.
 * Those checks run in that order. published() stays false.
 */
class SwarmNatPubClaim {
public:
    bool Apply(SwarmNatPubBook& book,
               SwarmNatPubShelf& shelf,
               const std::string& endpoint,
               std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_CLAIM_H
