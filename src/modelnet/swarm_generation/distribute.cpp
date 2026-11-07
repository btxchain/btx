// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/distribute.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationDistribute::Apply(const SwarmGenerationPopulation& population, const std::string& candidate_id, std::string& err) const
{
    (void)population;
    (void)candidate_id;
    return SwarmGenerationFail(err, kSwarmGenerationEngineAbsent);
}

} // namespace modelnet
