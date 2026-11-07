// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/atoms.h>

#include <modelnet/swarm_onechannel/limits.h>

#include <cstdint>

namespace modelnet {

int64_t SwarmOneChannelKeepAtoms(int64_t atoms)
{
    if (atoms != kSwarmOneChannelAtomsMoved) {
        return kSwarmOneChannelAtomsMoved;
    }
    return atoms;
}

bool SwarmOneChannelFundingMovesAtoms()
{
    return false;
}

bool SwarmOneChannelQuotingMovesAtoms()
{
    return false;
}

} // namespace modelnet
