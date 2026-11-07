// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LOGINHOLD_KEEP_H
#define BITCOIN_MODELNET_SWARM_LOGINHOLD_KEEP_H

#include <modelnet/swarm_loginhold/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the name already stored.
 * An unknown name reads as empty. This function does not write the book
 * and does not log the request in.
 */
class SwarmLoginHoldKeep {
public:
    std::string first(const SwarmLoginHoldBook& book, const std::string& name) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LOGINHOLD_KEEP_H
