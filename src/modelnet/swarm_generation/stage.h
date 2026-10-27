// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_STAGE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_STAGE_H

#include <modelnet/swarm_generation/channel.h>
#include <modelnet/swarm_generation/commitment.h>

#include <string>

namespace modelnet {

class SwarmGenerationStage {
public:
    bool Apply(SwarmGenerationChannels& channels, const SwarmGenerationCommitment& commitment, const std::string& channel,
               const std::string& candidate_id, const std::string& policy, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_STAGE_H
