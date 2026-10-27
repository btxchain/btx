// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/liquidity.h>

#include <modelnet/swarm_forward/codes.h>

namespace modelnet {

bool SwarmForwardLiquidity::Atoms(int64_t amount, std::string& err) const
{
    if (amount < 1) {
        err = kSwarmForwardAtoms;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmForwardLiquidity::Fits(int64_t remaining, int64_t amount, std::string& err) const
{
    if (amount > remaining) {
        err = kSwarmForwardShort;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
