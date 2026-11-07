// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/key.h>

#include <modelnet/swarm_adminhold/codes.h>
#include <modelnet/swarm_adminhold/limits.h>

namespace modelnet {

bool SwarmAdminHoldKey::accept(const std::vector<unsigned char>& sponsor_key, std::string& err) const
{
    if (sponsor_key.size() != kSwarmAdminHoldSponsorKeyBytes) {
        err = kSwarmAdminHoldKey;
        return false;
    }
    return true;
}

} // namespace modelnet
