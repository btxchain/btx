// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/allocate.h>

#include <modelnet/swarm_generation/codes.h>
#include <modelnet/swarm_generation/limits.h>

#include <cstdint>

namespace modelnet {

bool SwarmGenerationAllocate::Apply(SwarmGenerationStrategy& strategy, int slots, int exploration_percent, std::string& err) const
{
    if (slots < 1) {
        return SwarmGenerationFail(err, kSwarmGenerationSlots);
    }
    if (exploration_percent < kSwarmGenerationExploreMin || exploration_percent > kSwarmGenerationExploreMax) {
        return SwarmGenerationFail(err, kSwarmGenerationExplore);
    }
    // Niches are not ranked against each other. Pareto is not used.
    // The exploration share is integer division of slots * percent / 100.
    const int64_t product = static_cast<int64_t>(slots) * static_cast<int64_t>(exploration_percent);
    const int share = static_cast<int>(product / 100);
    strategy.allocate(slots, exploration_percent, share);
    return SwarmGenerationOk(err);
}

} // namespace modelnet
