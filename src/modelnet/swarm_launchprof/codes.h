// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROF_CODES_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROF_CODES_H

namespace modelnet {

/** Empty name. Nothing is stored. */
inline constexpr char kSwarmLaunchProfileProfile[] = "PROFILE";

/** A second Rename of a name already stored. The first name stays. */
inline constexpr char kSwarmLaunchProfileReplay[] = "REPLAY";

/**
 * The name is stored and the profile stays unchanged.
 * profile() stays BTX035-LAUNCH-DECODER-2x64. renamed() stays false.
 */
inline constexpr char kSwarmLaunchProfileHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROF_CODES_H
