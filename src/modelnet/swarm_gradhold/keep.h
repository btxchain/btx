// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_KEEP_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_KEEP_H

#include <modelnet/swarm_gradhold/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the update id already stored.
 * An unknown id reads as empty. This function does not write the book
 * and does not export the update.
 */
class SwarmGradHoldKeep {
public:
    std::string first(const SwarmGradHoldBook& book, const std::string& update_id) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_KEEP_H
