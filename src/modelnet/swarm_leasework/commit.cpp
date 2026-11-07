// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/commit.h>

#include <modelnet/swarm_leasework/codes.h>
#include <modelnet/swarm_leasework/hash.h>

namespace modelnet {

bool LeaseWorkCommit(LeaseWorkBook& book, const LeaseWorkEpoch& epoch, const LeaseWorkLeader& leader,
                     const std::string& task, int64_t commit_epoch, const std::string& result_hash, std::string& err)
{
    if (!book.contains(task)) {
        err = kLeaseWorkTask;
        return false;
    }
    if (commit_epoch != epoch.current()) {
        err = kLeaseWorkStaleEpoch;
        return false;
    }
    if (!leader.right()) {
        err = kLeaseWorkLeader;
        return false;
    }
    if (result_hash.empty()) {
        err = kLeaseWorkHash;
        return false;
    }
    const LeaseWorkHashKind kind = LeaseWorkClassifyHash(book.committed(task), book.result_hash(task), result_hash);
    if (kind == LeaseWorkHashKind::Replay) {
        err = kLeaseWorkReplay;
        return false;
    }
    if (kind == LeaseWorkHashKind::Conflict) {
        err = kLeaseWorkConflict;
        return false;
    }
    if (!book.StoreHash(task, result_hash)) {
        err = book.committed(task) ? kLeaseWorkConflict : kLeaseWorkTask;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
