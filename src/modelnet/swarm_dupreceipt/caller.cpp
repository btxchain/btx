// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/caller.h>

#include <modelnet/swarm_dupreceipt/codes.h>

namespace modelnet {

bool SwarmDupCaller::accept(bool research_key, bool scheduler, std::string& err) const
{
    if (research_key || scheduler) {
        err = kSwarmDupNotSigned;
        return false;
    }
    return true;
}

} // namespace modelnet
