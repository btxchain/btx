// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_EVALUATE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_EVALUATE_H

#include <modelnet/swarm_generation/commitment.h>

#include <string>

namespace modelnet {

class SwarmGenerationEvaluate {
public:
    bool Apply(SwarmGenerationCommitment& commitment, const std::string& candidate_id, const std::string& author,
               const std::string& evaluator, const std::string& author_domain, const std::string& evaluator_domain,
               bool author_sees_holdout, bool safety_regression, bool broad_regression, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_EVALUATE_H
