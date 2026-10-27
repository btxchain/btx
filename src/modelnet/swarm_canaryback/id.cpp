// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/id.h>

#include <modelnet/swarm_canaryback/codes.h>

namespace modelnet {

bool SwarmCanaryBackIdGate::accept(const std::string& id, std::string& err) const
{
    if (id.empty()) {
        err = kSwarmCanaryBackId;
        return false;
    }
    return true;
}

} // namespace modelnet
