// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stepwork/record.h>

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_stepwork/admit.h>
#include <modelnet/swarm_stepwork/kind.h>
#include <modelnet/swarm_stepwork/outcome.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmStepWorkRecord(SwarmIntCycle& cycle,
                         SwarmExperience& experience,
                         const std::string& id,
                         int64_t steps,
                         bool is_private,
                         std::string& err)
{
    if (!SwarmStepWorkAdmitRecord(experience, id, steps, is_private, err)) return false;

    std::string kind;
    if (!SwarmStepWorkPublicKind(kind, err)) return false;

    int64_t outcome_ppm = 0;
    if (!SwarmStepWorkOutcomePpm(steps, outcome_ppm, err)) return false;

    if (!cycle.Run(static_cast<uint64_t>(steps), err)) return false;

    if (!experience.Store(id, kind, outcome_ppm, err)) return false;

    experience.Enqueue();
    err.clear();
    return true;
}

} // namespace modelnet
