// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/quiet.h>

#include <modelnet/swarm_familyadmit/limits.h>

namespace modelnet {

int64_t SwarmFamilyAdmitQuiet::bytes_moved() const
{
    return kSwarmFamilyAdmitBytesMoved;
}

bool SwarmFamilyAdmitQuiet::launched() const
{
    return kSwarmFamilyAdmitLaunched;
}

} // namespace modelnet
