// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/atoms.h>

#include <modelnet/swarm_dupreceipt/codes.h>
#include <modelnet/swarm_dupreceipt/limits.h>

#include <limits>

namespace modelnet {

bool SwarmDupAtoms::accept(int64_t atoms, std::string& err) const
{
    if (atoms < kSwarmDupMinAtoms) {
        err = kSwarmDupAtoms;
        return false;
    }
    return true;
}

bool SwarmDupAtoms::fits(int64_t have, int64_t atoms) const
{
    if (atoms < kSwarmDupMinAtoms || have < 0) {
        return false;
    }
    // have + atoms would exceed int64 max.
    return have <= std::numeric_limits<int64_t>::max() - atoms;
}

} // namespace modelnet
