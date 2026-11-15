// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_CODES_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_CODES_H

namespace modelnet {

/** Stage id is empty. Nothing is stored. The active id stays. */
inline constexpr char kSwarmCanaryBackId[] = "ID";

/**
 * Adopt with nothing staged, or Regress before any Adopt.
 * The active id stays. A Regress on this path changes nothing.
 */
inline constexpr char kSwarmCanaryBackStage[] = "STAGE";

/** A second Adopt of the same staged id. The active id stays. */
inline constexpr char kSwarmCanaryBackReplay[] = "REPLAY";

/**
 * Regress when the one restore from the last Adopt is already spent.
 * The active id stays.
 */
inline constexpr char kSwarmCanaryBackRollback[] = "ROLLBACK";

/** Graduate is refused. graduated() stays false. The active id stays. */
inline constexpr char kSwarmCanaryBackRealm[] = "REALM";

/** Mine is refused. blocks() stays 0. */
inline constexpr char kSwarmCanaryBackHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_CODES_H
