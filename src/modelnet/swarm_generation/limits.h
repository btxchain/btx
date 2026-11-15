// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_LIMITS_H
#define BITCOIN_MODELNET_SWARM_GENERATION_LIMITS_H

#include <cstdint>

namespace modelnet {

inline constexpr int64_t kSwarmGenerationBytesMoved = 0;
inline constexpr int64_t kSwarmGenerationAtomsMoved = 0;
inline constexpr int kSwarmGenerationExploreMin = 0;
inline constexpr int kSwarmGenerationExploreMax = 100;
inline constexpr int kSwarmGenerationQuorumReports = 2;

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_LIMITS_H
