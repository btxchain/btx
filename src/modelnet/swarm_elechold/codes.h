// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_CODES_H

namespace modelnet {

/** watt_hours is below 1. Nothing is stored. */
inline constexpr char kSwarmElecHoldMeasure[] = "MEASURE";

/** A second Measure of a count at least 1. The first watt-hour count stays. */
inline constexpr char kSwarmElecHoldReplay[] = "REPLAY";

/**
 * Charge refused.
 * A watt-hour measurement is not a BTX charge. No atoms are added.
 */
inline constexpr char kSwarmElecHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_CODES_H
