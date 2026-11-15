// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_KIND_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_KIND_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * How one Admit attempt relates to the island id and the clock.
 * Fresh is the only result that may be stored. The other results store nothing.
 * This does not look at islands already stored.
 */
enum class SwarmIslandGateKind {
    Fresh,
    Island,
    Stale,
};

/**
 * Classify one Admit attempt.
 * Empty island is Island, including when epoch < now.
 * Otherwise epoch < now is Stale. epoch >= now is Fresh.
 */
SwarmIslandGateKind SwarmIslandGateClassify(const std::string& island, int64_t epoch, int64_t now);

/**
 * Refusal code for a non-fresh kind, or nullptr for Fresh.
 */
const char* SwarmIslandGateKindCode(SwarmIslandGateKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_KIND_H
