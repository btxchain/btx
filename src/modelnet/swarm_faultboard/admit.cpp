// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/admit.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <string>

namespace modelnet {

bool SwarmFaultDatasetWithdrawn(const SwarmFaultQuiet& quiet, std::string& err)
{
    const bool running = quiet.running();
    (void)running;
    err = kSwarmFaultDataset;
    return false;
}

bool SwarmFaultFalseCompat(const SwarmFaultQuiet& quiet, std::string& err)
{
    const bool admitted = quiet.admitted();
    (void)admitted;
    err = kSwarmFaultFamilyNotCompat;
    return false;
}

} // namespace modelnet
