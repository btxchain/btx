// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/reason.h>

namespace modelnet {

bool SwarmIdleDrainReason::Matches(const std::string& reason) const
{
    return reason == kSwarmIdleDrainBattery
        || reason == kSwarmIdleDrainThermal
        || reason == kSwarmIdleDrainMetered;
}

} // namespace modelnet
