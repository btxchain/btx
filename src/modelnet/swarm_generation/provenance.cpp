// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/provenance.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationProvenance::Apply(SwarmGenerationPopulation& population, const std::string& candidate_id, const std::string& parent, std::string& err) const
{
    if (!population.mark_verified(candidate_id, parent)) {
        return SwarmGenerationFail(err, kSwarmGenerationProvenance);
    }
    return SwarmGenerationOk(err);
}

} // namespace modelnet
