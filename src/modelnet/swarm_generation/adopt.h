// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_ADOPT_H
#define BITCOIN_MODELNET_SWARM_GENERATION_ADOPT_H

#include <modelnet/swarm_generation/adoption.h>
#include <modelnet/swarm_generation/channel.h>
#include <modelnet/swarm_generation/rollback.h>

#include <string>

namespace modelnet {

class SwarmGenerationAdopt {
public:
    bool Apply(SwarmGenerationChannels& channels, SwarmGenerationAdoptions& adoptions, SwarmGenerationRollbacks& rollbacks,
               const std::string& channel, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_ADOPT_H
