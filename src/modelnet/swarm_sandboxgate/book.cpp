// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/book.h>

#include <modelnet/swarm_sandboxgate/clock.h>
#include <modelnet/swarm_sandboxgate/prefix.h>
#include <modelnet/swarm_sandboxgate/record.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmSandboxGateBook::worker_granted(const std::string& worker) const
{
    if (worker.empty()) return false;
    const auto found = m_by_worker.find(worker);
    if (found == m_by_worker.end()) return false;
    return !found->second.empty();
}

bool SwarmSandboxGateBook::prefix_held(const std::string& worker, const std::string& path_prefix) const
{
    if (worker.empty() || path_prefix.empty()) return false;
    const auto found = m_by_worker.find(worker);
    if (found == m_by_worker.end()) return false;
    return found->second.find(path_prefix) != found->second.end();
}

std::vector<SwarmSandboxGateGrant> SwarmSandboxGateBook::grants_for(const std::string& worker) const
{
    std::vector<SwarmSandboxGateGrant> grants;
    const auto found = m_by_worker.find(worker);
    if (found == m_by_worker.end()) return grants;
    grants.reserve(found->second.size());
    for (const auto& entry : found->second) {
        grants.push_back(entry.second);
    }
    return grants;
}

std::vector<SwarmSandboxGateGrant> SwarmSandboxGateBook::matching(const std::string& worker,
                                                                  const std::string& path) const
{
    std::vector<SwarmSandboxGateGrant> grants;
    const auto found = m_by_worker.find(worker);
    if (found == m_by_worker.end()) return grants;
    for (const auto& entry : found->second) {
        if (SwarmSandboxGateStrictPrefix(entry.second.path_prefix, path)) {
            grants.push_back(entry.second);
        }
    }
    return grants;
}

bool SwarmSandboxGateBook::network_live(const std::string& worker, int64_t now_ms) const
{
    for (const SwarmSandboxGateGrant& grant : grants_for(worker)) {
        if (grant.network && SwarmSandboxGateLive(grant.until_ms, now_ms)) return true;
    }
    return false;
}

bool SwarmSandboxGateBook::store(const SwarmSandboxGateGrant& grant)
{
    if (!SwarmSandboxGateGrantUsable(grant)) return false;
    if (prefix_held(grant.worker, grant.path_prefix)) return false;
    m_by_worker[grant.worker].emplace(grant.path_prefix, grant);
    return true;
}

} // namespace modelnet
