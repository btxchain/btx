// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/average.h>

#include <modelnet/swarm_fourscale/codes.h>

namespace modelnet {

bool SwarmFourScaleAverage::refuse(std::string& err) const
{
    err = kSwarmFourScaleNotAveraged;
    return false;
}

} // namespace modelnet
