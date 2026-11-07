// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/act.h>

#include <modelnet/swarm_capact/actgate.h>
#include <modelnet/swarm_capact/codes.h>

namespace modelnet {

bool SwarmCapActApply(const SwarmCapActGrants& grants,
                       SwarmCapActActions& actions,
                       const std::string& name,
                       std::string& err)
{
    const std::string refusal = SwarmCapActActRefusal(grants, actions, name);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!actions.store(name)) {
        if (actions.contains(name)) {
            err = std::string{kSwarmCapActReplay};
        } else if (!grants.contains(name)) {
            err = std::string{kSwarmCapActNotActed};
        } else {
            err = std::string{kSwarmCapActCapability};
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
