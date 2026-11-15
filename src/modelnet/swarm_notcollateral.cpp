// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcollateral.h>

#include <string>

namespace modelnet {

SwarmNotCollateralResult SwarmNoteNotCollateral(const SwarmNotCollateral& note, std::string& err)
{
    SwarmNotCollateralResult result;
    result.reserved = false;
    // Two pools reserving the same collateral has not been shown as a live reservation.
    if (note.pool_id.empty()) {
        result.code = "POOL";
        result.reserved = false;
        err = "POOL";
        return result;
    }
    if (note.want_reserve) {
        result.code = "NOT_LIVE";
        result.reserved = false;
        err = "NOT_LIVE";
        return result;
    }
    result.code = "NOTED";
    result.reserved = false;
    err.clear();
    return result;
}

} // namespace modelnet
