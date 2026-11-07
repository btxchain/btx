// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/quiet.h>

#include <modelnet/swarm_paylabel/limits.h>

namespace modelnet {

int64_t SwarmPayLabelQuiet::atoms() const
{
    return kSwarmPayLabelAtoms;
}

std::string SwarmPayLabelQuiet::automatic_spend() const
{
    return std::string{kSwarmPayLabelAutomaticSpend};
}

bool SwarmPayLabelQuiet::broadcast() const
{
    return kSwarmPayLabelBroadcast;
}

int64_t SwarmPayLabelQuiet::bytes_moved() const
{
    return kSwarmPayLabelBytesMoved;
}

} // namespace modelnet
