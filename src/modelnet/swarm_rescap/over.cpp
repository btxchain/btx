// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/over.h>

#include <modelnet/swarm_rescap/codes.h>
#include <modelnet/swarm_rescap/limits.h>

namespace modelnet {

bool SwarmResCapOver::accept(int64_t threads, std::string& err) const
{
    if (threads > kSwarmResCapThreadCap) {
        err = kSwarmResCapCapped;
        return false;
    }
    return true;
}

} // namespace modelnet
