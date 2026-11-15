// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/grant.h>

#include <modelnet/swarm_capact/codes.h>
#include <modelnet/swarm_capact/gate.h>

namespace modelnet {

bool SwarmCapActGrantApply(SwarmCapActGrants& grants, const std::string& name, std::string& err)
{
    const std::string refusal = SwarmCapActGrantRefusal(grants, name);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!grants.store(name)) {
        err = grants.contains(name) ? std::string{kSwarmCapActReplay} : std::string{kSwarmCapActCapability};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
