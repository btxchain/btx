// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/claim.h>

#include <modelnet/swarm_parentage/codes.h>

#include <string>

namespace modelnet {

bool SwarmParentageClassifyClaim(const std::string& checkpoint, std::string& err)
{
    if (checkpoint.empty()) {
        err = SWARM_PARENTAGE_LINEAGE;
        return false;
    }
    err = SWARM_PARENTAGE_NOT_TRUST;
    return false;
}

} // namespace modelnet
