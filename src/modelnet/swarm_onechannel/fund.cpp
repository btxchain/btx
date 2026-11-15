// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/fund.h>

#include <modelnet/swarm_onechannel/atoms.h>
#include <modelnet/swarm_onechannel/codes.h>
#include <modelnet/swarm_onechannel/record.h>

#include <string>

namespace modelnet {

bool SwarmOneChannelDecideFund(const SwarmOneChannelPool* existing,
                               bool refund_bound,
                               bool& mark_funded,
                               std::string& err)
{
    mark_funded = false;
    if (existing == nullptr) {
        err = SWARM_ONECHANNEL_POOL;
        return false;
    }
    if (!refund_bound) {
        err = SWARM_ONECHANNEL_FUNDING;
        return false;
    }
    mark_funded = true;
    err.clear();
    return true;
}

void SwarmOneChannelApplyFund(SwarmOneChannelPool& row)
{
    row.funded = true;
    row.holds_money = true;
    // Funding does not move atoms. The quote and the channel binding stay.
    static_cast<void>(SwarmOneChannelFundingMovesAtoms());
    row.atoms = SwarmOneChannelKeepAtoms(row.atoms);
}

} // namespace modelnet
