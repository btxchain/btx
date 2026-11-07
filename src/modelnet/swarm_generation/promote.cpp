// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/promote.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationPromote::Apply(const SwarmGenerationCommitment& commitment, SwarmGenerationCertificates& certificates,
                                   const SwarmGenerationLineage& lineage, const std::string& candidate_id, std::string& err) const
{
    if (!commitment.qualified(candidate_id)) {
        return SwarmGenerationFail(err, kSwarmGenerationNotGraduated);
    }
    certificates.add(candidate_id, lineage.cycle());
    return SwarmGenerationOk(err);
}

} // namespace modelnet
