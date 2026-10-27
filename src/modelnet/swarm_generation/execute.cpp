// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/execute.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationExecute::Apply(SwarmGenerationTraining& training, const SwarmGenerationLineage& lineage, std::string& err) const
{
    training.add(lineage.cycle(), kSwarmGenerationEngineAbsent);
    return SwarmGenerationFail(err, kSwarmGenerationEngineAbsent);
}

} // namespace modelnet
