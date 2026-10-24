// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_H

#include <modelnet/swarm_leasework/book.h>
#include <modelnet/swarm_leasework/epoch.h>
#include <modelnet/swarm_leasework/leader.h>
#include <modelnet/swarm_leasework/silence.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Lease-fence plane.
 * The epoch starts at 1. Every epoch starts with no commit right.
 * A grant is stored when until_ms >= now_ms. That bound is inclusive.
 * This plane does not spawn a process and does not broadcast.
 *
 * Grant stores one worker for a task at the current epoch.
 * An empty task or worker is TASK. A negative bound is RANGE.
 * until_ms < now_ms is EXPIRED and stores nothing.
 * A duplicate task is REPLAY and keeps the first worker.
 *
 * BumpEpoch increments the epoch and clears the leader right to commit.
 * Stored grants stay, so the same task is still REPLAY.
 * The new epoch has no commit right until ClaimLeader for a worker that
 * still holds a live grant. A stored grant is live while until_ms is at
 * or after the latest now_ms stored on any grant.
 *
 * Commit stores one result hash.
 * An unknown task is TASK. An epoch other than the current epoch is
 * STALE_EPOCH and does not store the hash. No commit right is LEADER
 * and does not store the hash. An empty hash is HASH.
 * The first hash wins. The same hash again is REPLAY. A different hash
 * is CONFLICT and the first hash stays.
 *
 * bytes_moved() stays 0. launched() stays false.
 */
class SwarmLeaseWork {
public:
    bool Grant(const std::string& task, const std::string& worker, int64_t now_ms, int64_t until_ms, std::string& err);
    void BumpEpoch();
    bool ClaimLeader(const std::string& worker, std::string& err);
    bool Commit(const std::string& task, int64_t epoch, const std::string& result_hash, std::string& err);

    int64_t epoch() const;
    std::string leader() const;
    bool commit_right() const;
    bool has(const std::string& task) const;
    std::string worker(const std::string& task) const;
    int64_t grant_epoch(const std::string& task) const;
    int64_t until_ms(const std::string& task) const;
    bool committed(const std::string& task) const;
    std::string result_hash(const std::string& task) const;
    bool live(const std::string& worker) const;
    std::size_t grants() const;

    int64_t bytes_moved() const;
    bool launched() const;
    bool broadcast() const;

private:
    LeaseWorkBook m_book;
    LeaseWorkEpoch m_epoch;
    LeaseWorkLeader m_leader;
    LeaseWorkSilence m_silence;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_H
