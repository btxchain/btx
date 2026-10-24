// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_KEEP_H
#define BITCOIN_MODELNET_SWARM_NATPUB_KEEP_H

#include <modelnet/swarm_natpub/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the endpoint already stored.
 * An unknown endpoint reads as empty. This function does not write the
 * book and does not publish the claim.
 */
class SwarmNatPubKeep {
public:
    std::string first(const SwarmNatPubBook& book, const std::string& endpoint) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_KEEP_H
