// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/stay.h>

#include <modelnet/swarm_closemargin/codes.h>
#include <modelnet/swarm_closemargin/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

std::string SwarmCloseMarginHoldStay::refusal() const
{
    return std::string{kSwarmCloseMarginHoldHeld};
}

int64_t SwarmCloseMarginHoldStay::margin_blocks() const
{
    return kSwarmCloseMarginHoldMarginBlocks;
}

bool SwarmCloseMarginHoldStay::shrunk() const
{
    return kSwarmCloseMarginHoldShrunk;
}

} // namespace modelnet
