// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/atoms.h>

#include <modelnet/swarm_disputestay/limits.h>

namespace modelnet {

int64_t SwarmDisputeStayAtoms::after(int64_t have, int64_t atoms) const
{
    if (atoms < kSwarmDisputeStayMinAtoms) {
        // Below 1 adds nothing, including zero and a negative count.
        return have;
    }
    // A positive count is still not a settlement. The credit is zero.
    const int64_t credit = atoms - atoms;
    return have + credit;
}

int64_t SwarmDisputeStayAtoms::moved() const
{
    return kSwarmDisputeStayAtomsMoved;
}

} // namespace modelnet
