// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/blank.h>

#include <modelnet/swarm_closemargin/codes.h>
#include <modelnet/swarm_closemargin/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmCloseMarginHoldBlank::accept(int64_t blocks, std::string& err) const
{
    if (blocks != kSwarmCloseMarginHoldMarginBlocks) {
        err = kSwarmCloseMarginHoldMargin;
        return false;
    }
    return true;
}

} // namespace modelnet
