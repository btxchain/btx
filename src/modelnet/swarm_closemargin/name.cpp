// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/name.h>

#include <modelnet/swarm_closemargin/limits.h>

#include <cstdint>

namespace modelnet {

int64_t SwarmCloseMarginHoldName::copy(int64_t blocks) const
{
    if (blocks != kSwarmCloseMarginHoldMarginBlocks) return 0;
    return blocks;
}

} // namespace modelnet
