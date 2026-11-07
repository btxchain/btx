// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/promote.h>

#include <modelnet/swarm_parentage/codes.h>
#include <modelnet/swarm_parentage/limits.h>

#include <string>

namespace modelnet {

bool SwarmParentageClassifyPromote(bool known, const std::string& license, std::string& err)
{
    static_cast<void>(kSwarmParentageRealmPromoted);
    static_cast<void>(kSwarmParentageExactReplayAdmitted);
    if (!known) {
        static_cast<void>(license.size());
        err = SWARM_PARENTAGE_LINEAGE;
        return false;
    }
    // Empty and non-empty license text both stay parentage. Neither graduates the checkpoint.
    if (license.empty()) {
        err = SWARM_PARENTAGE_NOT_GRADUATED;
        return false;
    }
    err = SWARM_PARENTAGE_NOT_GRADUATED;
    return false;
}

} // namespace modelnet
