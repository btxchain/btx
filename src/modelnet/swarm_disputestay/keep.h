// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_KEEP_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_KEEP_H

#include <modelnet/swarm_disputestay/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the dispute id already stored.
 * An unknown id reads as empty. This function does not write the book
 * and does not settle the dispute.
 */
class SwarmDisputeStayKeep {
public:
    std::string first(const SwarmDisputeStayBook& book, const std::string& dispute) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_KEEP_H
