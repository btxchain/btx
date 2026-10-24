// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_PROMOTE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_PROMOTE_H

#include <modelnet/swarm_generation/certificate.h>
#include <modelnet/swarm_generation/commitment.h>
#include <modelnet/swarm_generation/lineage.h>

#include <string>

namespace modelnet {

class SwarmGenerationPromote {
public:
    bool Apply(const SwarmGenerationCommitment& commitment, SwarmGenerationCertificates& certificates,
               const SwarmGenerationLineage& lineage, const std::string& candidate_id, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_PROMOTE_H
