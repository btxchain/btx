// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/grant.h>

#include <modelnet/swarm_leasework/codes.h>
#include <modelnet/swarm_leasework/expiry.h>

namespace modelnet {

bool LeaseWorkGrant(LeaseWorkBook& book, const LeaseWorkEpoch& epoch, const std::string& task,
                    const std::string& worker, int64_t now_ms, int64_t until_ms, std::string& err)
{
    if (task.empty() || worker.empty()) {
        err = kLeaseWorkTask;
        return false;
    }
    if (LeaseWorkTimeOutOfRange(now_ms, until_ms)) {
        err = kLeaseWorkRange;
        return false;
    }
    if (LeaseWorkGrantExpired(now_ms, until_ms)) {
        err = kLeaseWorkExpired;
        return false;
    }
    if (book.contains(task)) {
        err = kLeaseWorkReplay;
        return false;
    }
    if (!book.Insert(task, worker, epoch.current(), now_ms, until_ms)) {
        err = kLeaseWorkReplay;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
