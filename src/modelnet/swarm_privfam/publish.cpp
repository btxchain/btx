// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/publish.h>

#include <modelnet/swarm_privfam/codes.h>
#include <modelnet/swarm_privfam/release.h>

namespace modelnet {

bool SwarmPrivFamPublish(SwarmPrivFamShelf& shelf,
                          const SwarmPrivFamRoster& roster,
                          const std::string& family,
                          std::string& err)
{
    err = SwarmPrivFamReleaseRefusal(roster, family);
    if (shelf.mark(family)) {
        err = std::string{kSwarmPrivFamNotPublished};
    }
    if (err.empty()) err = std::string{kSwarmPrivFamFamily};
    return false;
}

} // namespace modelnet
