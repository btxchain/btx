// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LEASEFENCE_H
#define BTX_MODELNET_SWARM_LEASEFENCE_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory lease fence for one job at a time. The epoch starts at 1.
 * A grant stores a worker, a job, the fence epoch, and an expiry. A commit
 * stores one result for that grant. Time is the caller-supplied now_ms.
 * This fence does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or address.
 */
class SwarmLeaseFence {
public:
    /** Fence epoch. Starts at 1. */
    int64_t epoch() const;

    /** Move the fence epoch forward by 1. Outstanding grants keep their epoch. */
    void BumpEpoch();

    /**
     * Order, first match wins: an empty worker or job is JOB. until_ms <= now_ms
     * is LEASE_EXPIRED and stores nothing. An epoch other than the fence epoch
     * is STALE_EPOCH and stores nothing. A second grant of the same job, while
     * the stored grant is still uncommitted and unexpired (until_ms > now_ms),
     * is REPLAY and leaves the stored grant in place. Otherwise the grant is
     * stored, replacing any previous row for that job, and err is cleared.
     */
    bool Grant(const std::string& worker, const std::string& job, int64_t epoch, int64_t until_ms, int64_t now_ms,
               std::string& err);

    /**
     * Order, first match wins: no grant for the job is JOB. A worker other than
     * the granted worker is WORKER. An epoch other than the epoch stored on the
     * grant, or other than the fence epoch, is STALE_EPOCH and does not store
     * the result. BumpEpoch moves the fence epoch, so a later commit of that
     * grant is STALE_EPOCH. now_ms > until_ms is LEASE_EXPIRED and does not
     * store. An empty result is HASH and does not store. The first valid commit
     * stores the result and clears err. The same result again is idempotent and
     * clears err. A different result is CONFLICT and the first result stays.
     */
    bool Commit(const std::string& worker, const std::string& job, int64_t epoch, int64_t now_ms,
                const std::string& result, std::string& err);

private:
    struct GrantRow {
        std::string worker;
        int64_t epoch{0};
        int64_t until_ms{0};
        bool committed{false};
        std::string result;
    };

    int64_t m_epoch{1};
    std::map<std::string, GrantRow> m_grants;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LEASEFENCE_H
