// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTUNFUNDED_H
#define BTX_MODELNET_SWARM_NOTUNFUNDED_H

#include <string>

namespace modelnet {

/**
 * A local note about one pool. funded records whether the pool holds
 * money. want_advertise asks this note to advertise the pool as holding
 * money.
 *
 * An unfunded pool is not advertised as holding money. holds_money and
 * advertised stay false on every path.
 */
struct SwarmNotUnfunded {
    std::string pool_id;
    bool funded{false};
    bool want_advertise{false};
};

/**
 * Outcome of noting a pool. holds_money and advertised stay false on
 * every path: an unfunded pool is not advertised as holding money.
 */
struct SwarmNotUnfundedResult {
    std::string code;
    bool holds_money{false};
    bool advertised{false};
};

/**
 * Note a pool without advertising it as holding money.
 * Order, first match wins: an empty pool_id is POOL.
 * funded false is NOT_HOLDING, even when want_advertise is false.
 * want_advertise is NOT_HOLDING.
 * Otherwise the note is NOTED and err is clear.
 * holds_money and advertised stay false on every path. An unfunded pool
 * is not advertised as holding money.
 */
SwarmNotUnfundedResult SwarmNoteNotUnfunded(const SwarmNotUnfunded& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTUNFUNDED_H
