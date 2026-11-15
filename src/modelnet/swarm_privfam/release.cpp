// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/release.h>

#include <modelnet/swarm_privfam/blank.h>
#include <modelnet/swarm_privfam/codes.h>
#include <modelnet/swarm_privfam/known.h>

namespace modelnet {

std::string SwarmPrivFamReleaseRefusal(const SwarmPrivFamRoster& roster, const std::string& family)
{
    if (SwarmPrivFamBlank(family)) return std::string{kSwarmPrivFamFamily};
    if (!SwarmPrivFamKnown(roster, family)) return std::string{kSwarmPrivFamFamily};
    return std::string{kSwarmPrivFamNotPublished};
}

} // namespace modelnet
