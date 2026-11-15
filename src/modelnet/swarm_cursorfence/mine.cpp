// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/mine.h>

#include <modelnet/swarm_cursorfence/codes.h>

namespace modelnet {

bool SwarmCursorFenceMine(std::string& err)
{
    err = kSwarmCursorFenceHeld;
    return false;
}

} // namespace modelnet
