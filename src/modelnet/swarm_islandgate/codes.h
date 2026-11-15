// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_CODES_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_CODES_H

namespace modelnet {

/** island is empty. Nothing is stored. */
inline constexpr char kSwarmIslandGateIsland[] = "ISLAND";

/** epoch is below now. Nothing is stored. */
inline constexpr char kSwarmIslandGateStale[] = "STALE";

/** The island is already stored. The first epoch stays. */
inline constexpr char kSwarmIslandGateReplay[] = "REPLAY";

/** Exchange holds. No bytes move. */
inline constexpr char kSwarmIslandGateHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_CODES_H
