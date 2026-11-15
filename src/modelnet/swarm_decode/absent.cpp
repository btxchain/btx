// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/absent.h>

#include <modelnet/swarm_decode/codes.h>

#include <string>

namespace modelnet {

bool SwarmDecodeProductionPull(std::string& err)
{
    err = kSwarmDecodeEngineAbsent;
    return false;
}

} // namespace modelnet
