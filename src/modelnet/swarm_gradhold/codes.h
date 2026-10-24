// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_CODES_H

namespace modelnet {

/** Empty update id. Nothing is stored. */
inline constexpr char kSwarmGradHoldUpdate[] = "UPDATE";

/** A second Offer of an id already stored. The first update stays. */
inline constexpr char kSwarmGradHoldReplay[] = "REPLAY";

/**
 * Export refused.
 * A known id and an unknown id both stay unexported. Nothing is stored.
 */
inline constexpr char kSwarmGradHoldNotExported[] = "NOT_EXPORTED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_CODES_H
