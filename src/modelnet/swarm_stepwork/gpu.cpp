// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stepwork/gpu.h>

#include <modelnet/swarm_stepwork/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmStepWorkRefuseGpu(const std::string&, int64_t, std::string& err)
{
    err = kSwarmStepWorkEngineAbsent;
    return false;
}

} // namespace modelnet
