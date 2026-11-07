// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COLLATBOOK_CODES_H
#define BITCOIN_MODELNET_SWARM_COLLATBOOK_CODES_H

namespace modelnet {

/** Empty pool or empty outpoint. Nothing is stored. */
inline constexpr char SWARM_COLLAT_COLLATERAL[] = "COLLATERAL";

/** Bucket is neither escrow nor collateral. Nothing is stored. */
inline constexpr char SWARM_COLLAT_BUCKET[] = "BUCKET";

/** The same pool reserved the same outpoint and bucket again. No second row. */
inline constexpr char SWARM_COLLAT_REPLAY[] = "REPLAY";

/** The same pool asked for the other bucket of an outpoint it already holds. */
inline constexpr char SWARM_COLLAT_BOTH[] = "BOTH";

/**
 * Another pool asked for an outpoint the first pool already reserved.
 * Also used when SwarmSameCollateral leaves the error empty.
 */
inline constexpr char SWARM_COLLAT_REUSE[] = "COLLATERAL_REUSE";

/** Reservations are not merged. Nothing moves. */
inline constexpr char SWARM_COLLAT_NOT_MERGED[] = "NOT_MERGED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COLLATBOOK_CODES_H
