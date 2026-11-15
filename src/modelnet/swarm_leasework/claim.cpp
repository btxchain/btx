// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/claim.h>

#include <modelnet/swarm_leasework/codes.h>

namespace modelnet {

bool LeaseWorkClaim(LeaseWorkBook& book, LeaseWorkLeader& leader, const std::string& worker, std::string& err)
{
    if (worker.empty()) {
        err = kLeaseWorkTask;
        return false;
    }
    if (leader.claimed()) {
        err = kLeaseWorkReplay;
        return false;
    }
    if (!book.holds(worker)) {
        err = kLeaseWorkTask;
        return false;
    }
    if (!book.worker_live(worker)) {
        err = kLeaseWorkExpired;
        return false;
    }
    if (!leader.Claim(worker)) {
        err = kLeaseWorkReplay;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
