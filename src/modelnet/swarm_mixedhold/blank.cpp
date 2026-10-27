// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/blank.h>

#include <modelnet/swarm_mixedhold/codes.h>

namespace modelnet {

bool SwarmMixedHoldBlank::accept(const std::string& name, std::string& err) const
{
    if (name.empty()) {
        err = kSwarmMixedHoldPrecision;
        return false;
    }
    return true;
}

} // namespace modelnet
