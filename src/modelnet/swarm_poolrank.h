// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_POOLRANK_H
#define BTX_MODELNET_SWARM_POOLRANK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A pool rank record. pool_id names the pool. funded records whether the
 * pool is funded. reward and expense are the recorded amounts.
 * want_spend asks this record to spend.
 *
 * An unfunded pool holds no money. This rank does not spend.
 */
struct SwarmPoolRank {
    std::string pool_id;
    bool funded{false};
    int64_t reward{0};
    int64_t expense{0};
    bool want_spend{false};
};

/**
 * Outcome of ranking a pool. holds_money and spent stay false on every
 * path. rank is 0 unless a non-negative reward minus expense is recorded.
 */
struct SwarmPoolRankResult {
    std::string code;
    bool holds_money{false};
    bool spent{false};
    int64_t rank{0};
};

/**
 * Rank a pool locally without treating it as holding money or spending.
 * Order, first match wins: an empty pool_id is POOL. funded false is
 * UNFUNDED. reward or expense below 0 is RANGE. want_spend is HELD.
 * Otherwise the record is NOTED and err is clear.
 * holds_money and spent stay false on every path. Rank is reward minus
 * expense when that difference is non-negative, otherwise 0, and only on
 * the HELD and NOTED paths.
 * An unfunded pool holds no money. This rank does not spend.
 */
SwarmPoolRankResult SwarmRankPoolLocal(const SwarmPoolRank& pool, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_POOLRANK_H
