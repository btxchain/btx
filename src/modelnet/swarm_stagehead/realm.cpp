// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/realm.h>

#include <modelnet/swarm_stagehead/codes.h>
#include <modelnet/swarm_stagehead/limits.h>

namespace modelnet {

bool SwarmStageRealm::Promote(std::string& err) const
{
    err = kSwarmStageRealm;
    return false;
}

int64_t SwarmStageRealm::bytes_moved() const
{
    return kSwarmStageBytesMoved;
}

bool SwarmStageRealm::mined() const
{
    return false;
}

bool SwarmStageRealm::graduated() const
{
    return false;
}

bool SwarmStageRealm::broadcast() const
{
    return false;
}

bool SwarmStageRealm::spent() const
{
    return false;
}

} // namespace modelnet
