// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/p2p03/p2p03.h>

namespace modelnet {

bool P2p03::JoinFamily(int nodes, bool scheduler, int gpus, std::string& err)
{
    if (nodes < 1) {
        err = "FIELD";
        return false;
    }
    if (scheduler) {
        err = "SCHEDULER";
        return false;
    }
    if (gpus >= 2) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (nodes >= 3) {
        m_joined = nodes;
        err.clear();
        return true;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
