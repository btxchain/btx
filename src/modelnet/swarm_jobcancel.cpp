// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_jobcancel.h>

namespace modelnet {

bool SwarmJobCancel::Open(const std::string& task, std::string& err)
{
    if (task.empty()) {
        err = "TASK";
        return false;
    }
    if (m_jobs.find(task) != m_jobs.end()) {
        err = "REPLAY";
        return false;
    }
    m_jobs.emplace(task, Job{});
    err.clear();
    return true;
}

bool SwarmJobCancel::Finish(const std::string& task, const std::string& result, std::string& err)
{
    const auto it = m_jobs.find(task);
    if (it == m_jobs.end()) {
        err = "TASK";
        return false;
    }
    if (result.empty()) {
        err = "HASH";
        return false;
    }
    Job& job = it->second;
    if (job.cancelled) {
        err = "CANCELLED";
        return false;
    }
    if (job.finished) {
        if (job.result == result) {
            err.clear();
            return true;
        }
        err = "CONFLICT";
        return false;
    }
    job.finished = true;
    job.result = result;
    err.clear();
    return true;
}

bool SwarmJobCancel::Cancel(const std::string& task, std::string& err)
{
    const auto it = m_jobs.find(task);
    if (it == m_jobs.end()) {
        err = "TASK";
        return false;
    }
    if (it->second.finished) {
        err = "FINISHED";
        return false;
    }
    it->second.cancelled = true;
    err.clear();
    return true;
}

bool SwarmJobCancel::cancelled(const std::string& task) const
{
    const auto it = m_jobs.find(task);
    return it != m_jobs.end() && it->second.cancelled;
}

std::string SwarmJobCancel::result(const std::string& task) const
{
    const auto it = m_jobs.find(task);
    if (it == m_jobs.end()) {
        return {};
    }
    return it->second.result;
}

} // namespace modelnet
