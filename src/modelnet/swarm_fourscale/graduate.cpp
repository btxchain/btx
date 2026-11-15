// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/graduate.h>

#include <modelnet/swarm_fourscale/codes.h>

namespace modelnet {

bool SwarmFourScaleGraduate::refuse(std::string& err) const
{
    err = kSwarmFourScaleRealm;
    return false;
}

} // namespace modelnet
