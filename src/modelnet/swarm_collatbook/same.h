// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COLLATBOOK_SAME_H
#define BITCOIN_MODELNET_SWARM_COLLATBOOK_SAME_H

#include <modelnet/swarm_paymesh.h>

#include <string>

namespace modelnet {

/**
 * Record the first pool on this outpoint in the paymesh collateral book.
 * Calls SwarmSameCollateral with that pool on both sides.
 * A failure leaves err as the helper set it, or COLLATERAL_REUSE when
 * the helper set none. This does not store a collatbook row.
 */
bool SwarmCollatNoteFirst(SwarmCollateralBook& book, const std::string& pool, const std::string& outpoint, std::string& err);

/**
 * A second pool wants an outpoint the first pool already reserved.
 * Calls SwarmSameCollateral with the winner as pool_a, so the helper
 * cannot record the challenger as the first pool.
 * Always returns false and stores no reservation. err is the helper's
 * error, or COLLATERAL_REUSE when the helper set none.
 */
bool SwarmCollatRefuseSecond(SwarmCollateralBook& book, const std::string& winner, const std::string& challenger,
                             const std::string& outpoint, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COLLATBOOK_SAME_H
