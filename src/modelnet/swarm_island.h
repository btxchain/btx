// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ISLAND_H
#define BTX_MODELNET_SWARM_ISLAND_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Admission record for one geographically distributed training island.
 * Accepting it does not average weights, does not launch torch, and does
 * not move bytes.
 */
struct SwarmIslandUpdate {
    std::string island_id;
    std::string recipe;
    std::string base_checkpoint;
    std::string update_digest;
    int64_t staleness{0};
    bool bytes_averaged{false};
};

/**
 * Admit an island update when the recipe and base match and the staleness
 * is within the caller-supplied limit. This function does not average
 * weights, does not launch torch, and does not move bytes.
 */
bool SwarmAcceptIslandUpdate(SwarmIslandUpdate& update, const std::string& expected_recipe, const std::string& expected_base, int64_t staleness_limit, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ISLAND_H
