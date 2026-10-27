// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/mine.h>

#include <modelnet/swarm_canaryback/codes.h>

namespace modelnet {

bool SwarmCanaryBackMine::Apply(std::string& err) const
{
    err = kSwarmCanaryBackHeld;
    return false;
}

} // namespace modelnet
