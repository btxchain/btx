// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/trust.h>

#include <modelnet/swarm_parentage/codes.h>
#include <modelnet/swarm_parentage/limits.h>

#include <string>

namespace modelnet {

bool SwarmParentageClassifyTrust(bool known, std::string& err)
{
    static_cast<void>(kSwarmParentageTrusted);
    if (!known) {
        err = SWARM_PARENTAGE_LINEAGE;
        return false;
    }
    err = SWARM_PARENTAGE_NOT_TRUST;
    return false;
}

} // namespace modelnet
