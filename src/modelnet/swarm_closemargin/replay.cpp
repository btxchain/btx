// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/replay.h>

#include <modelnet/swarm_closemargin/limits.h>

#include <cstdint>

namespace modelnet {

bool SwarmCloseMarginHoldIsReplay(const SwarmCloseMarginHoldBook& book, int64_t blocks)
{
    if (blocks != kSwarmCloseMarginHoldMarginBlocks) return false;
    return book.contains(blocks);
}

} // namespace modelnet
