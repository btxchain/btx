// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MIXEDHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_MIXEDHOLD_CODES_H

namespace modelnet {

/** Empty name. Nothing is stored. */
inline constexpr char kSwarmMixedHoldPrecision[] = "PRECISION";

/** A second Request of a name already stored. The first request stays. */
inline constexpr char kSwarmMixedHoldReplay[] = "REPLAY";

/**
 * The name is stored and the mixed-precision request is refused.
 * running() stays false.
 */
inline constexpr char kSwarmMixedHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MIXEDHOLD_CODES_H
