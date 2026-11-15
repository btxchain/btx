// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_poolrank.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmPoolRankResult SwarmRankPoolLocal(const SwarmPoolRank& pool, std::string& err)
{
    SwarmPoolRankResult result;
    result.holds_money = false;
    result.spent = false;
    result.rank = 0;
    // An unfunded pool holds no money. This rank does not spend.
    if (pool.pool_id.empty()) {
        result.code = "POOL";
        result.holds_money = false;
        result.spent = false;
        result.rank = 0;
        err = "POOL";
        return result;
    }
    if (!pool.funded) {
        result.code = "UNFUNDED";
        result.holds_money = false;
        result.spent = false;
        result.rank = 0;
        err = "UNFUNDED";
        return result;
    }
    if (pool.reward < 0 || pool.expense < 0) {
        result.code = "RANGE";
        result.holds_money = false;
        result.spent = false;
        result.rank = 0;
        err = "RANGE";
        return result;
    }
    const int64_t delta = pool.reward - pool.expense;
    const int64_t rank = delta < 0 ? 0 : delta;
    if (pool.want_spend) {
        result.code = "HELD";
        result.holds_money = false;
        result.spent = false;
        result.rank = rank;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.holds_money = false;
    result.spent = false;
    result.rank = rank;
    err.clear();
    return result;
}

} // namespace modelnet
