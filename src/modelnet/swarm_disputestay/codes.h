// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_CODES_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_CODES_H

namespace modelnet {

/** Empty dispute id. Nothing is stored. */
inline constexpr char kSwarmDisputeStayDispute[] = "DISPUTE";

/** A second Open of an id already stored. The first dispute stays. */
inline constexpr char kSwarmDisputeStayReplay[] = "REPLAY";

/**
 * Settle refused.
 * A known id and an unknown id both stay unsettled. Nothing is stored
 * by Settle, and no atoms are added.
 */
inline constexpr char kSwarmDisputeStayHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_CODES_H
