// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/run.h>

#include <modelnet/swarm_sandboxgate/codes.h>

#include <string>

namespace modelnet {

bool SwarmSandboxGateRunRefuse(const std::string& worker, std::string& err)
{
    if (worker.empty()) {
        err = kSwarmSandboxGateSandboxAbsent;
        return false;
    }
    err = kSwarmSandboxGateSandboxAbsent;
    return false;
}

} // namespace modelnet
