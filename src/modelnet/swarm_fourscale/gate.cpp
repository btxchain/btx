// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/gate.h>

#include <modelnet/swarm_fourscale/codes.h>
#include <modelnet/swarm_fourscale/replay.h>
#include <modelnet/swarm_fourscale/scale.h>

namespace modelnet {

SwarmFourScaleOpenDecision SwarmFourScaleDecideOpen(const SwarmFourScaleBook& book)
{
    if (SwarmFourScaleIsReplay(book)) {
        return SwarmFourScaleOpenDecision{std::string{kSwarmFourScaleReplay}, false};
    }
    return SwarmFourScaleOpenDecision{{}, true};
}

SwarmFourScaleStepDecision SwarmFourScaleDecideStep(const SwarmFourScaleBook& book, const std::string& scale)
{
    std::string err;
    if (!SwarmFourScaleScale{}.accept(book, scale, err)) {
        return SwarmFourScaleStepDecision{err, false};
    }
    return SwarmFourScaleStepDecision{{}, true};
}

} // namespace modelnet
