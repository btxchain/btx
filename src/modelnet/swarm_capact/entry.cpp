// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/entry.h>

namespace modelnet {

SwarmCapActActionEntry SwarmCapActMakeAction(const std::string& name)
{
    SwarmCapActActionEntry entry;
    entry.name = name;
    return entry;
}

bool SwarmCapActActionUsable(const SwarmCapActActionEntry& entry)
{
    return !entry.name.empty();
}

} // namespace modelnet
