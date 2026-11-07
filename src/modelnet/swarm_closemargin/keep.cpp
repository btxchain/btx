// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/keep.h>

#include <cstdint>

namespace modelnet {

int64_t SwarmCloseMarginHoldKeep::first(const SwarmCloseMarginHoldBook& book, int64_t blocks) const
{
    if (!book.contains(blocks)) return 0;
    return book.blocks_of(blocks);
}

} // namespace modelnet
