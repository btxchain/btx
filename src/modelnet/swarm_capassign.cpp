// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capassign.h>

#include <algorithm>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool Lists(const std::vector<std::string>& capabilities, const std::string& required)
{
    return std::find(capabilities.begin(), capabilities.end(), required) != capabilities.end();
}

} // namespace

bool SwarmCapAssign::AddWorker(const std::string& worker, const std::vector<std::string>& capabilities,
                                std::string& err)
{
    if (worker.empty()) {
        err = "WORKER";
        return false;
    }
    if (m_capabilities.find(worker) != m_capabilities.end()) {
        err = "REPLAY";
        return false;
    }
    m_capabilities.emplace(worker, capabilities);
    m_order.push_back(worker);
    err.clear();
    return true;
}

bool SwarmCapAssign::Assign(const std::string& task, const std::string& required, std::string& worker_out,
                             std::string& err)
{
    if (task.empty() || required.empty()) {
        err = "TASK";
        return false;
    }
    const auto existing = m_assigned.find(task);
    if (existing != m_assigned.end()) {
        worker_out = existing->second;
        err = "REPLAY";
        return false;
    }
    for (const std::string& worker : m_order) {
        const auto it = m_capabilities.find(worker);
        if (it == m_capabilities.end()) {
            continue;
        }
        if (!Lists(it->second, required)) {
            continue;
        }
        m_assigned.emplace(task, worker);
        worker_out = worker;
        err.clear();
        return true;
    }
    worker_out.clear();
    err = "NOT_ACTED";
    return false;
}

std::string SwarmCapAssign::WorkerFor(const std::string& task) const
{
    const auto it = m_assigned.find(task);
    if (it == m_assigned.end()) {
        return {};
    }
    return it->second;
}

} // namespace modelnet
