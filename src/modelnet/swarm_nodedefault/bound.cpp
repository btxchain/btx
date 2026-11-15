// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/bound.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

bool SwarmNodeDefaultBound::Accept(int64_t atoms, std::string& err) const
{
    if (atoms < 1) {
        err = kSwarmNodeDefaultBound;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
