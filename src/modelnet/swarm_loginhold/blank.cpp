// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/blank.h>

#include <modelnet/swarm_loginhold/codes.h>

namespace modelnet {

bool SwarmLoginHoldBlank::accept(const std::string& name, std::string& err) const
{
    if (name.empty()) {
        err = kSwarmLoginHoldLogin;
        return false;
    }
    return true;
}

} // namespace modelnet
