// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/adopt.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationAdopt::Apply(SwarmGenerationChannels& channels, SwarmGenerationAdoptions& adoptions,
                                 SwarmGenerationRollbacks& rollbacks, const std::string& channel, std::string& err) const
{
    std::string previous;
    std::string adopted;
    if (!channels.adopt(channel, previous, adopted)) {
        return SwarmGenerationFail(err, kSwarmGenerationNotStaged);
    }
    rollbacks.push(channel, previous);
    adoptions.add(channel, adopted);
    return SwarmGenerationOk(err);
}

} // namespace modelnet
