// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_PROVENANCE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_PROVENANCE_H

#include <modelnet/swarm_generation/population.h>

#include <string>

namespace modelnet {

class SwarmGenerationProvenance {
public:
    bool Apply(SwarmGenerationPopulation& population, const std::string& candidate_id, const std::string& parent, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_PROVENANCE_H
