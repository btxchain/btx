// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/identify.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationIdentify::Apply(SwarmGenerationStrategy& strategy, int cycle, const std::string& weakness, std::string& err) const
{
    if (weakness.empty()) {
        return SwarmGenerationFail(err, kSwarmGenerationWeakness);
    }
    if (!strategy.identify(weakness, cycle)) {
        return SwarmGenerationFail(err, kSwarmGenerationReplay);
    }
    return SwarmGenerationOk(err);
}

} // namespace modelnet
