// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/replay.h>

#include <modelnet/swarm_idledrain/codes.h>

namespace modelnet {

bool SwarmIdleDrainReplay::claimed(bool already, std::string& err) const
{
    if (!already) return false;
    err = kSwarmIdleDrainReplay;
    return true;
}

} // namespace modelnet
