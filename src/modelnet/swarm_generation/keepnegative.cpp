// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/keepnegative.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationKeepNegative::Apply(SwarmGenerationNegatives& negatives, const std::string& result, std::string& err) const
{
    if (result.empty()) {
        return SwarmGenerationFail(err, kSwarmGenerationNegative);
    }
    negatives.add(result);
    return SwarmGenerationOk(err);
}

} // namespace modelnet
