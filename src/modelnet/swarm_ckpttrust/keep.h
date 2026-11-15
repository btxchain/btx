// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_KEEP_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_KEEP_H

#include <modelnet/swarm_ckpttrust/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the claim already stored.
 * An unknown claim reads as empty. This function does not write the book
 * and does not mark the claim trusted.
 */
class SwarmCheckpointTrustKeep {
public:
    std::string first(const SwarmCheckpointTrustBook& book, const std::string& claim) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_KEEP_H
