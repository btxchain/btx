// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasefence.h>

namespace modelnet {

int64_t SwarmLeaseFence::epoch() const
{
    return m_epoch;
}

void SwarmLeaseFence::BumpEpoch()
{
    ++m_epoch;
}

bool SwarmLeaseFence::Grant(const std::string& worker, const std::string& job, int64_t epoch, int64_t until_ms,
                            int64_t now_ms, std::string& err)
{
    if (worker.empty() || job.empty()) {
        err = "JOB";
        return false;
    }
    if (until_ms <= now_ms) {
        err = "LEASE_EXPIRED";
        return false;
    }
    if (epoch != m_epoch) {
        err = "STALE_EPOCH";
        return false;
    }
    const auto it = m_grants.find(job);
    if (it != m_grants.end() && !it->second.committed && it->second.until_ms > now_ms) {
        err = "REPLAY";
        return false;
    }
    GrantRow row;
    row.worker = worker;
    row.epoch = epoch;
    row.until_ms = until_ms;
    row.committed = false;
    m_grants[job] = row;
    err.clear();
    return true;
}

bool SwarmLeaseFence::Commit(const std::string& worker, const std::string& job, int64_t epoch, int64_t now_ms,
                             const std::string& result, std::string& err)
{
    const auto it = m_grants.find(job);
    if (it == m_grants.end()) {
        err = "JOB";
        return false;
    }
    GrantRow& row = it->second;
    if (row.worker != worker) {
        err = "WORKER";
        return false;
    }
    if (epoch != row.epoch || epoch != m_epoch) {
        err = "STALE_EPOCH";
        return false;
    }
    if (now_ms > row.until_ms) {
        err = "LEASE_EXPIRED";
        return false;
    }
    if (result.empty()) {
        err = "HASH";
        return false;
    }
    if (row.committed) {
        if (row.result == result) {
            err.clear();
            return true;
        }
        err = "CONFLICT";
        return false;
    }
    row.result = result;
    row.committed = true;
    err.clear();
    return true;
}

} // namespace modelnet
