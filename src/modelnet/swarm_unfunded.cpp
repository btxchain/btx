// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_unfunded.h>

#include <cstdint>

namespace modelnet {

SwarmPoolAdvertResult SwarmNotePoolAdvert(const SwarmPoolAdvert& advert, std::string& err)
{
    SwarmPoolAdvertResult result;
    result.balance_advertised = false;
    result.spendable = false;
    if (advert.pool_id.empty() || advert.advertised_atoms < 0) {
        result.balance_advertised = false;
        result.spendable = false;
        result.code = "POOL";
        err = "POOL";
        return result;
    }
    if (!advert.funded) {
        result.balance_advertised = false;
        result.spendable = false;
        result.code = "UNFUNDED";
        err = "UNFUNDED";
        return result;
    }
    if (advert.want_advertise_balance) {
        result.balance_advertised = false;
        result.spendable = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.balance_advertised = false;
    result.spendable = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
