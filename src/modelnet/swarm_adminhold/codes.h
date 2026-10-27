// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_CODES_H

namespace modelnet {

/** The channel is empty, or the move names a channel that was never stored. */
inline constexpr char kSwarmAdminHoldChannel[] = "CHANNEL";

/** refund_height is below 1. The row is not stored. */
inline constexpr char kSwarmAdminHoldHeight[] = "HEIGHT";

/** sponsor_key size is other than 1312. The row is not stored. */
inline constexpr char kSwarmAdminHoldKey[] = "KEY";

/** A second Open of a channel already stored. The first height and key stay. */
inline constexpr char kSwarmAdminHoldReplay[] = "REPLAY";

/**
 * MoveHeight or MoveKey of a stored channel.
 * The stored refund height and sponsor key stay.
 */
inline constexpr char kSwarmAdminHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_CODES_H
