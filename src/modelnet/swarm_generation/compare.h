// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_COMPARE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_COMPARE_H

#include <modelnet/swarm_generation/branch.h>
#include <modelnet/swarm_generation/performance.h>

#include <string>

namespace modelnet {

class SwarmGenerationCompare {
public:
    bool Apply(SwarmGenerationBranches& branches, SwarmGenerationPerformance& performance, const std::string& left,
               const std::string& right, bool compatible, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_COMPARE_H
