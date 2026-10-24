// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/stage.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationStage::Apply(SwarmGenerationChannels& channels, const SwarmGenerationCommitment& commitment,
                                 const std::string& channel, const std::string& candidate_id, const std::string& policy,
                                 std::string& err) const
{
    const bool known_policy = policy == kSwarmGenerationFollow || policy == kSwarmGenerationPin || policy == kSwarmGenerationRefuse;
    if (!known_policy) {
        return SwarmGenerationFail(err, kSwarmGenerationPolicy);
    }
    if (!commitment.qualified(candidate_id)) {
        return SwarmGenerationFail(err, kSwarmGenerationNotGraduated);
    }
    if (policy == kSwarmGenerationFollow) {
        channels.stage_follow(channel, candidate_id);
    } else {
        channels.note_policy(channel, policy);
    }
    return SwarmGenerationOk(err);
}

} // namespace modelnet
