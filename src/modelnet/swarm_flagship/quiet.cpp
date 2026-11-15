// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/quiet.h>

#include <modelnet/swarm_flagship/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmFlagshipQuiet::passed() const
{
    return kSwarmFlagshipPassed;
}

bool SwarmFlagshipQuiet::gpu_passed() const
{
    return kSwarmFlagshipGpuPassed;
}

bool SwarmFlagshipQuiet::windows_passed() const
{
    return kSwarmFlagshipWindowsPassed;
}

bool SwarmFlagshipQuiet::pay_passed() const
{
    return kSwarmFlagshipPayPassed;
}

bool SwarmFlagshipQuiet::launched() const
{
    return kSwarmFlagshipLaunched;
}

bool SwarmFlagshipQuiet::gpu() const
{
    return kSwarmFlagshipGpu;
}

bool SwarmFlagshipQuiet::broadcast() const
{
    return kSwarmFlagshipBroadcast;
}

std::uint64_t SwarmFlagshipQuiet::bytes_moved() const
{
    return kSwarmFlagshipBytesMoved;
}

std::uint64_t SwarmFlagshipQuiet::atoms_moved() const
{
    return kSwarmFlagshipAtomsMoved;
}

std::string SwarmFlagshipQuiet::automatic_spend() const
{
    return std::string{kSwarmFlagshipAutomaticSpend};
}

} // namespace modelnet
