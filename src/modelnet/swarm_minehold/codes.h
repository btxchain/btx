// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MINEHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_MINEHOLD_CODES_H

namespace modelnet {

/** Empty name. Nothing is stored. */
inline constexpr char kSwarmMineHoldMine[] = "MINE";

/** A second Request of a name already stored. The first request stays. */
inline constexpr char kSwarmMineHoldReplay[] = "REPLAY";

/**
 * The name is stored and the mine request is refused.
 * mined() stays false. blocks() stays 0.
 */
inline constexpr char kSwarmMineHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MINEHOLD_CODES_H
