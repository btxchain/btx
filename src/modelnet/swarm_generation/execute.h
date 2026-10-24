// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_EXECUTE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_EXECUTE_H

#include <modelnet/swarm_generation/lineage.h>
#include <modelnet/swarm_generation/training.h>

#include <string>

namespace modelnet {

class SwarmGenerationExecute {
public:
    bool Apply(SwarmGenerationTraining& training, const SwarmGenerationLineage& lineage, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_EXECUTE_H
