// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_CODES_H

namespace modelnet {

/** Empty channel id, or Exit/Refund of a channel that was never opened. */
inline constexpr char kReorgHoldChannel[] = "CHANNEL";

/** earned below 0, or an add that would wrap the plane counter. Nothing is stored. */
inline constexpr char kReorgHoldAtoms[] = "ATOMS";

/** The channel is already open, or Reorg already froze the plane. */
inline constexpr char kReorgHoldReplay[] = "REPLAY";

/** The plane is frozen. The channel stays, nothing is paid, and no transaction is built. */
inline constexpr char kReorgHoldFrozen[] = "FROZEN";

/** Exit before Reorg. The channel stays open and is not paid. */
inline constexpr char kReorgHoldOpen[] = "OPEN";

/** Refund before Reorg. Nothing is broadcast and no transaction is built. */
inline constexpr char kReorgHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_CODES_H
