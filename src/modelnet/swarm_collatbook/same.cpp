// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/same.h>

#include <modelnet/swarm_collatbook/codes.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {

bool SwarmCollatNoteFirst(SwarmCollateralBook& book, const std::string& pool, const std::string& outpoint, std::string& err)
{
    if (!SwarmSameCollateral(book, pool, pool, outpoint, err)) {
        if (err.empty()) {
            err = SWARM_COLLAT_REUSE;
        }
        return false;
    }
    return true;
}

bool SwarmCollatRefuseSecond(SwarmCollateralBook& book, const std::string& winner, const std::string& challenger,
                             const std::string& outpoint, std::string& err)
{
    std::string helper_err;
    // The winner is pool_a. When the outpoint is new to the helper, it
    // records pool_a and then rejects the challenger. A success that
    // clears helper_err is still a refusal: the second reservation is
    // not stored.
    const bool same = SwarmSameCollateral(book, winner, challenger, outpoint, helper_err);
    (void)same;
    if (helper_err.empty()) {
        err = SWARM_COLLAT_REUSE;
    } else {
        err = helper_err;
    }
    return false;
}

} // namespace modelnet
