// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/step.h>

#include <modelnet/swarm_fourscale/codes.h>
#include <modelnet/swarm_fourscale/gate.h>

namespace modelnet {

bool SwarmFourScaleStep::Apply(SwarmFourScaleBook& book, const std::string& scale, std::string& err) const
{
    const SwarmFourScaleStepDecision decision = SwarmFourScaleDecideStep(book, scale);
    if (!decision.advance || !decision.code.empty()) {
        err = decision.code.empty() ? std::string{kSwarmFourScaleScale} : decision.code;
        return false;
    }
    if (!book.advance(scale)) {
        err = kSwarmFourScaleScale;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
