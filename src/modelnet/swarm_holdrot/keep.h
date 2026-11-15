// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_KEEP_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_KEEP_H

#include <modelnet/swarm_holdrot/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the holdout already stored.
 * An unknown holdout reads as empty. This function does not write the book
 * and does not mark the holdout rotating.
 */
class SwarmHoldoutRotateKeep {
public:
    std::string first(const SwarmHoldoutRotateBook& book, const std::string& holdout) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_KEEP_H
