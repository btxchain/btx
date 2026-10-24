// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_KEEPSPECIALIST_H
#define BITCOIN_MODELNET_SWARM_GENERATION_KEEPSPECIALIST_H

#include <modelnet/swarm_generation/specialist.h>

#include <string>

namespace modelnet {

class SwarmGenerationKeepSpecialist {
public:
    bool Apply(SwarmGenerationSpecialists& specialists, const std::string& name, const std::string& candidate_id, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_KEEPSPECIALIST_H
