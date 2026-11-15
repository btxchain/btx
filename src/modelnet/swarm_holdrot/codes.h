// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_CODES_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_CODES_H

namespace modelnet {

/** Empty holdout. Nothing is stored. */
inline constexpr char kSwarmHoldoutRotateHoldout[] = "HOLDOUT";

/** A second Rotate of a holdout already stored. The first holdout stays. */
inline constexpr char kSwarmHoldoutRotateReplay[] = "REPLAY";

/**
 * The holdout is stored and rotation is refused.
 * rotated() stays false.
 */
inline constexpr char kSwarmHoldoutRotateNotRotating[] = "NOT_ROTATING";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_CODES_H
