// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/names.h>

#include <modelnet/swarm_sigcover/codes.h>

#include <string>

namespace modelnet {

bool SwarmSigCoverIdPresent(const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = SWARM_SIGCOVER_SIGHASH;
        return false;
    }
    return true;
}

} // namespace modelnet
