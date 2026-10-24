// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/replay.h>

namespace modelnet {

bool SwarmCapActGrantIsReplay(const SwarmCapActGrants& grants, const std::string& name)
{
    if (name.empty()) return false;
    return grants.contains(name);
}

bool SwarmCapActActionIsReplay(const SwarmCapActActions& actions, const std::string& name)
{
    if (name.empty()) return false;
    return actions.contains(name);
}

} // namespace modelnet
