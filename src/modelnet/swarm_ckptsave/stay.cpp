// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/stay.h>

#include <modelnet/swarm_ckptsave/codes.h>
#include <modelnet/swarm_ckptsave/limits.h>

namespace modelnet {

std::string SwarmCkptSaveStay::refusal() const
{
    return std::string{kSwarmCkptSaveHeld};
}

bool SwarmCkptSaveStay::saved() const
{
    return kSwarmCkptSaveSaved;
}

} // namespace modelnet
