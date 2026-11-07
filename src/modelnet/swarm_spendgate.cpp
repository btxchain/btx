// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_spendgate.h>

#include <cstdint>

namespace modelnet {

SwarmSpendResult SwarmRefuseSchedulerSpend(const SwarmSpendRequest& request, std::string& err)
{
    SwarmSpendResult result;
    result.signed_spend = false;
    if (request.scheduler_id.empty() || request.atoms <= 0) {
        result.signed_spend = false;
        result.code = "SPEND";
        err = "SPEND";
        return result;
    }
    if (request.spend_key_present) {
        result.signed_spend = false;
        result.code = "KEY_REFUSED";
        err = "KEY_REFUSED";
        return result;
    }
    result.signed_spend = false;
    result.code = "REFUSED";
    err.clear();
    return result;
}

} // namespace modelnet
