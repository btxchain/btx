// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/revoke.h>

#include <modelnet/swarm_readfence/codes.h>

namespace modelnet {

bool SwarmReadRevoke::Apply(SwarmReadRoster& roster, const std::string& member, std::string& err) const
{
    if (member.empty()) {
        err = kSwarmReadMember;
        return false;
    }
    if (roster.revoked(member) || !roster.Revoke(member)) {
        err = kSwarmReadReplay;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
