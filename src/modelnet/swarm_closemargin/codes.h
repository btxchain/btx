// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_CODES_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_CODES_H

namespace modelnet {

/** A block count other than 160. Nothing is stored. */
inline constexpr char kSwarmCloseMarginHoldMargin[] = "MARGIN";

/** A second Shrink of 160. The first request stays. */
inline constexpr char kSwarmCloseMarginHoldReplay[] = "REPLAY";

/**
 * The block count 160 is stored and the shrink is refused.
 * margin_blocks() stays 160. shrunk() stays false.
 */
inline constexpr char kSwarmCloseMarginHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_CODES_H
