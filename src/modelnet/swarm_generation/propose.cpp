// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/propose.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationPropose::Apply(const SwarmGenerationStrategy& strategy, SwarmGenerationFrontier& frontier, const std::string& experiment, std::string& err) const
{
    if (!strategy.has_weakness()) {
        return SwarmGenerationFail(err, kSwarmGenerationNoWeakness);
    }
    frontier.add(experiment, strategy.latest_weakness());
    return SwarmGenerationOk(err);
}

} // namespace modelnet
