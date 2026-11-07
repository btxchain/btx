// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_CODES_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_CODES_H

namespace modelnet {

/** budget < 1. The row is not stored. */
inline constexpr char kSwarmEarlyHaltBudget[] = "BUDGET";

/** A second Open. The first budget stays. */
inline constexpr char kSwarmEarlyHaltReplay[] = "REPLAY";

/**
 * Step before Open, or Promote before any score was stored.
 * Nothing is stored.
 */
inline constexpr char kSwarmEarlyHaltStep[] = "STEP";

/**
 * The run is early-stopped, or the remainder is already zero.
 * A later Step stores nothing. Promote of an early-stopped run
 * leaves the row in place.
 */
inline constexpr char kSwarmEarlyHaltStopped[] = "STOPPED";

/** Realm promotion is refused. The row stays. Nothing graduates. */
inline constexpr char kSwarmEarlyHaltRealm[] = "REALM";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_CODES_H
