// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SYNCHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_SYNCHOLD_CODES_H

namespace modelnet {

/** Empty name. Nothing is stored. */
inline constexpr char kSwarmSyncHoldSync[] = "SYNC";

/** A second Request of a name already stored. The first request stays. */
inline constexpr char kSwarmSyncHoldReplay[] = "REPLAY";

/**
 * The name is stored and the sync is refused.
 * synced() stays false.
 */
inline constexpr char kSwarmSyncHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SYNCHOLD_CODES_H
