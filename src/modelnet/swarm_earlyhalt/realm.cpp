// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/realm.h>

#include <modelnet/swarm_earlyhalt/codes.h>
#include <modelnet/swarm_earlyhalt/limits.h>

namespace modelnet {

bool SwarmEarlyHaltRealm::Promote(std::string& err) const
{
    err = kSwarmEarlyHaltRealm;
    return false;
}

int64_t SwarmEarlyHaltRealm::bytes_moved() const
{
    return kSwarmEarlyHaltBytesMoved;
}

bool SwarmEarlyHaltRealm::gpu() const
{
    return kSwarmEarlyHaltGpu;
}

bool SwarmEarlyHaltRealm::graduated() const
{
    return kSwarmEarlyHaltGraduated;
}

bool SwarmEarlyHaltRealm::mined() const
{
    return kSwarmEarlyHaltMined;
}

} // namespace modelnet
