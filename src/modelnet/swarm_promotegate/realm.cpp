// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/realm.h>

#include <modelnet/swarm_promotegate/codes.h>
#include <modelnet/swarm_promotegate/limits.h>

namespace modelnet {

bool SwarmPromoteRealm::Promote(std::string& err) const
{
    err = kSwarmPromoteRealm;
    return false;
}

int64_t SwarmPromoteRealm::bytes_moved() const
{
    return kSwarmPromoteBytesMoved;
}

bool SwarmPromoteRealm::mined() const
{
    return false;
}

bool SwarmPromoteRealm::graduated() const
{
    return false;
}

bool SwarmPromoteRealm::broadcast() const
{
    return false;
}

bool SwarmPromoteRealm::spent() const
{
    return false;
}

} // namespace modelnet
