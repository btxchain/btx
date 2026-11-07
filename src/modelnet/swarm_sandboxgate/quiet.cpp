// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/quiet.h>

#include <modelnet/swarm_sandboxgate/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmSandboxGateQuiet::launched() const
{
    return kSwarmSandboxGateLaunched;
}

bool SwarmSandboxGateQuiet::connected() const
{
    return kSwarmSandboxGateConnected;
}

bool SwarmSandboxGateQuiet::gpu() const
{
    return kSwarmSandboxGateGpu;
}

int64_t SwarmSandboxGateQuiet::bytes_moved() const
{
    return kSwarmSandboxGateBytesMoved;
}

std::string SwarmSandboxGateQuiet::automatic_spend() const
{
    return std::string{kSwarmSandboxGateAutomaticSpend};
}

} // namespace modelnet
