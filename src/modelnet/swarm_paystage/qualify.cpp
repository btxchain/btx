// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/qualify.h>

namespace modelnet {

bool SwarmPayRefuseQualified(bool qualified, std::string& err)
{
    if (qualified) {
        err = "UNQUALIFIED";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
