// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_COMMIT_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_COMMIT_H

#include <modelnet/swarm_leasework/book.h>
#include <modelnet/swarm_leasework/epoch.h>
#include <modelnet/swarm_leasework/leader.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Store one result hash for a task.
 * Order, first match wins: an unknown task is TASK. An epoch other than
 * the current epoch is STALE_EPOCH and does not store the hash. No commit
 * right is LEADER and does not store the hash. An empty hash is HASH.
 * The first hash wins. The same hash again is REPLAY. A different hash is
 * CONFLICT and the first hash stays.
 */
bool LeaseWorkCommit(LeaseWorkBook& book, const LeaseWorkEpoch& epoch, const LeaseWorkLeader& leader,
                     const std::string& task, int64_t commit_epoch, const std::string& result_hash, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_COMMIT_H
