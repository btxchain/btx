// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/replay.h>

namespace modelnet {

bool SwarmPrivFamIsReplay(const SwarmPrivFamRoster& roster, const std::string& family)
{
    if (family.empty()) return false;
    return roster.contains(family);
}

} // namespace modelnet
