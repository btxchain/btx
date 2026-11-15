// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_CODES_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_CODES_H

namespace modelnet {

/** Disable, rename, seed, training, or private-prompt change is refused. */
inline constexpr char kSwarmNodeDefaultHeld[] = "HELD";

/** The arm is not an operator signature. A research key or scheduler counts. */
inline constexpr char kSwarmNodeDefaultNotSigned[] = "NOT_SIGNED";

/** The spend bound is below 1. Nothing is recorded. */
inline constexpr char kSwarmNodeDefaultBound[] = "BOUND";

/** The plane is already armed. The recorded bound stays. */
inline constexpr char kSwarmNodeDefaultReplay[] = "REPLAY";

/** The thread request is above 64 or below 0. The count stays 64. */
inline constexpr char kSwarmNodeDefaultCapped[] = "CAPPED";

/** The vram request is not 0. The claim stays 0. */
inline constexpr char kSwarmNodeDefaultVramZero[] = "VRAM_ZERO";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_CODES_H
