// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_WEARHOLD_CODES_H

namespace modelnet {

/** joules is below 1. Nothing is stored. */
inline constexpr char kSwarmWearHoldMeasure[] = "MEASURE";

/** A second Measure of a count at least 1. The first joule count stays. */
inline constexpr char kSwarmWearHoldReplay[] = "REPLAY";

/**
 * Charge refused.
 * A joule measurement is not a BTX charge. No atoms are added.
 */
inline constexpr char kSwarmWearHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARHOLD_CODES_H
