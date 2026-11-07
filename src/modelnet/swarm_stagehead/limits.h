// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STAGEHEAD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_STAGEHEAD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Active id before any adopt. */
inline constexpr char kSwarmStageBase[] = "base";

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmStageBytesMoved = 0;

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STAGEHEAD_LIMITS_H
