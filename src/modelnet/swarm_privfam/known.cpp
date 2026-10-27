// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/known.h>

#include <modelnet/swarm_privfam/blank.h>

namespace modelnet {

bool SwarmPrivFamKnown(const SwarmPrivFamRoster& roster, const std::string& family)
{
    if (SwarmPrivFamBlank(family)) return false;
    return roster.contains(family);
}

} // namespace modelnet
