// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalboard/realm.h>

#include <modelnet/swarm_evalboard/codes.h>
#include <modelnet/swarm_evalboard/limits.h>

namespace modelnet {

bool SwarmEvalRealm::Graduate(const std::string& subject, std::string& err)
{
    // subject is ignored. Graduation does not select a realm id.
    (void)subject;
    err = kSwarmEvalRealm;
    return false;
}

bool SwarmEvalRealm::graduated() const
{
    return false;
}

const char* SwarmEvalRealm::active_id() const
{
    return kSwarmEvalActiveId;
}

uint64_t SwarmEvalRealm::bytes_moved() const
{
    return kSwarmEvalBytesMoved;
}

bool SwarmEvalRealm::gpu() const
{
    return kSwarmEvalGpu;
}

bool SwarmEvalRealm::mines() const
{
    return kSwarmEvalMines;
}

bool SwarmEvalRealm::broadcasts() const
{
    return kSwarmEvalBroadcasts;
}

} // namespace modelnet
