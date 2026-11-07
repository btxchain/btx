// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_KEEP_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_KEEP_H

#include <modelnet/swarm_closemargin/book.h>

#include <cstdint>

namespace modelnet {

/**
 * Reads the block count already stored.
 * An unknown count reads as 0. This function does not write the book
 * and does not shrink the margin.
 */
class SwarmCloseMarginHoldKeep {
public:
    int64_t first(const SwarmCloseMarginHoldBook& book, int64_t blocks) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_KEEP_H
