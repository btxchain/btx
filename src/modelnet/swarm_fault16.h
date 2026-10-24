// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT16_H
#define BTX_MODELNET_SWARM_FAULT16_H

#include <string>

namespace modelnet {

/**
 * Live fault 16: two pools attempt to reserve the same collateral.
 * Local note only. reserved, broadcast, and committed stay false.
 * This function does not reserve collateral, broadcast, or commit.
 */
struct SwarmFault16 {
    std::string pool_a;
    std::string pool_b;
    std::string collateral_id;
    bool same_collateral{false};
    bool want_reserve{false};
};

/**
 * Outcome of a local note that two pools attempted the same collateral.
 * reserved, broadcast, and committed stay false on every path.
 */
struct SwarmFault16Result {
    std::string code;
    bool reserved{false};
    bool broadcast{false};
    bool committed{false};
};

/**
 * Classify a local attempt by two pools to reserve the same collateral.
 * Order, first match wins:
 * 1. An empty pool_a, pool_b, or collateral_id is POOL. Every result
 *    bool stays false and err is POOL.
 * 2. pool_a equal to pool_b, or same_collateral, is COLLATERAL_REUSE.
 *    reserved stays false and err is COLLATERAL_REUSE, even if
 *    want_reserve is set.
 * 3. want_reserve is HELD. reserved stays false and err is cleared.
 * 4. Otherwise NOTED. reserved stays false and err is cleared.
 * reserved, broadcast, and committed stay false on every path.
 */
SwarmFault16Result SwarmRecoverFault16(const SwarmFault16& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT16_H
