// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/quiet.h>

namespace modelnet {

bool SwarmFaultQuiet::launched() const
{
    return false;
}

bool SwarmFaultQuiet::gpu() const
{
    return false;
}

int64_t SwarmFaultQuiet::bytes_moved() const
{
    return 0;
}

int64_t SwarmFaultQuiet::atoms_moved() const
{
    return 0;
}

std::string SwarmFaultQuiet::automatic_spend() const
{
    return "0";
}

bool SwarmFaultQuiet::broadcast() const
{
    return false;
}

bool SwarmFaultQuiet::mined() const
{
    return false;
}

bool SwarmFaultQuiet::saved() const
{
    return false;
}

bool SwarmFaultQuiet::qualified() const
{
    return false;
}

bool SwarmFaultQuiet::admitted() const
{
    return false;
}

bool SwarmFaultQuiet::running() const
{
    return false;
}

} // namespace modelnet
