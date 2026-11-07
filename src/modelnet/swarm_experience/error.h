// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_ERROR_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_ERROR_H

namespace modelnet {

/** Empty id, or TrainFrom on an id that was never stored. */
inline constexpr char kExperienceTrajectory[] = "TRAJECTORY";

/** kind is not public_trajectory or synthetic_trajectory. */
inline constexpr char kExperiencePrivateData[] = "PRIVATE_DATA";

/** id is already stored. The first outcome stays. */
inline constexpr char kExperienceReplay[] = "REPLAY";

/** outcome_ppm is outside 0..1000000. Nothing is stored. */
inline constexpr char kExperienceRange[] = "RANGE";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_ERROR_H
