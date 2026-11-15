// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCOLLATERAL_H
#define BTX_MODELNET_SWARM_NOTCOLLATERAL_H

#include <string>

namespace modelnet {

/**
 * A local note about one collateral pool. want_reserve asks this note to
 * reserve the same collateral for a second pool.
 *
 * Two pools reserving the same collateral has not been shown as a live
 * reservation. reserved stays false on every path.
 */
struct SwarmNotCollateral {
    std::string pool_id;
    bool want_reserve{false};
};

/**
 * Outcome of noting collateral. reserved stays false on every path: two
 * pools reserving the same collateral has not been shown as a live
 * reservation.
 */
struct SwarmNotCollateralResult {
    std::string code;
    bool reserved{false};
};

/**
 * Note collateral without showing a live reservation.
 * Order, first match wins: an empty pool_id is POOL.
 * want_reserve is NOT_LIVE.
 * Otherwise the note is NOTED and err is clear.
 * reserved stays false on every path. Two pools reserving the same
 * collateral has not been shown as a live reservation.
 */
SwarmNotCollateralResult SwarmNoteNotCollateral(const SwarmNotCollateral& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCOLLATERAL_H
