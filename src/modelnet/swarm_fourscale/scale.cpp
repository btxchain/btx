// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/scale.h>

#include <modelnet/swarm_fourscale/codes.h>
#include <modelnet/swarm_fourscale/names.h>

namespace modelnet {

bool SwarmFourScaleScale::accept(const SwarmFourScaleBook& book, const std::string& scale, std::string& err) const
{
    if (!book.opened() || SwarmFourScaleIndex(scale) < 0 || !book.holds(scale)) {
        err = kSwarmFourScaleScale;
        return false;
    }
    return true;
}

} // namespace modelnet
