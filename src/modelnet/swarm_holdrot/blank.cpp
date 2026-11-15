// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/blank.h>

#include <modelnet/swarm_holdrot/codes.h>

namespace modelnet {

bool SwarmHoldoutRotateBlank::accept(const std::string& holdout, std::string& err) const
{
    if (holdout.empty()) {
        err = kSwarmHoldoutRotateHoldout;
        return false;
    }
    return true;
}

} // namespace modelnet
