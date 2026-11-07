// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVMOVE_ENGINE_H
#define BITCOIN_MODELNET_SWARM_KVMOVE_ENGINE_H

#include <string>

namespace modelnet {

/**
 * Which move path an engine name selects.
 * Memory copies resident bytes in process.
 * Absent is nixl, mooncake, or rdma: those names copy nothing.
 * Other is every remaining name, including the empty string.
 */
enum class SwarmKvMoveEngineKind : int {
    Memory = 0,
    Absent = 1,
    Other = 2,
};

/** Classify an engine name. Matching is exact and case-sensitive. */
SwarmKvMoveEngineKind SwarmKvMoveClassifyEngine(const std::string& engine);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVMOVE_ENGINE_H
