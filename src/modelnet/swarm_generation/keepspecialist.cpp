// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/keepspecialist.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationKeepSpecialist::Apply(SwarmGenerationSpecialists& specialists, const std::string& name,
                                          const std::string& candidate_id, std::string& err) const
{
    if (name.empty()) {
        return SwarmGenerationFail(err, kSwarmGenerationSpecialist);
    }
    specialists.add(name, candidate_id);
    return SwarmGenerationOk(err);
}

} // namespace modelnet
