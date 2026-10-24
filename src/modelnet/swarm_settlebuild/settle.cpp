// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/settle.h>

#include <modelnet/swarm_settlebuild/codes.h>

#include <string>

namespace modelnet {

bool SwarmSettleBuildRefuseSettle(bool claim_stored, bool refund_stored, std::string& err)
{
    err = kSwarmSettleBuildUnqualified;
    if (claim_stored) {
        err = kSwarmSettleBuildUnqualified;
    }
    if (refund_stored) {
        err = kSwarmSettleBuildUnqualified;
    }
    return false;
}

} // namespace modelnet
