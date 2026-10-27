// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/compare.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationCompare::Apply(SwarmGenerationBranches& branches, SwarmGenerationPerformance& performance,
                                   const std::string& left, const std::string& right, bool compatible, std::string& err) const
{
    if (!compatible) {
        branches.add(left, right);
        return SwarmGenerationFail(err, kSwarmGenerationNotAveraged);
    }
    performance.add(left, right);
    return SwarmGenerationOk(err);
}

} // namespace modelnet
