// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/open.h>

#include <modelnet/swarm_fourscale/codes.h>
#include <modelnet/swarm_fourscale/gate.h>

namespace modelnet {

bool SwarmFourScaleOpen::Apply(SwarmFourScaleBook& book, std::string& err) const
{
    const SwarmFourScaleOpenDecision decision = SwarmFourScaleDecideOpen(book);
    if (!decision.plant || !decision.code.empty()) {
        err = decision.code.empty() ? std::string{kSwarmFourScaleReplay} : decision.code;
        return false;
    }
    if (!book.open() || !book.opened()) {
        err = book.opened() ? std::string{kSwarmFourScaleReplay} : std::string{kSwarmFourScaleScale};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
