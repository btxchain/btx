// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_CODES_H
#define BITCOIN_MODELNET_SWARM_RESCAP_CODES_H

namespace modelnet {

/** threads is below 1. Nothing is stored. */
inline constexpr char kSwarmResCapCap[] = "CAP";

/**
 * threads is above 64, or a count from 1 through 64 was stored.
 * Above 64 stores nothing. A count inside the cap is stored and
 * raised() stays false.
 */
inline constexpr char kSwarmResCapCapped[] = "CAPPED";

/** A second Raise of a thread count already stored. The first count stays. */
inline constexpr char kSwarmResCapReplay[] = "REPLAY";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_CODES_H
