// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/dag.h>

#include <modelnet/swarm_agents/codes.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmAgentDag::Reaches(const std::string& start, const std::string& target) const
{
    std::vector<std::string> stack;
    stack.push_back(start);
    std::map<std::string, bool> seen;
    while (!stack.empty()) {
        const std::string cur = stack.back();
        stack.pop_back();
        if (cur == target) {
            return true;
        }
        if (!seen.emplace(cur, true).second) {
            continue;
        }
        const auto it = m_nodes.find(cur);
        if (it == m_nodes.end()) {
            continue;
        }
        for (const std::string& dep : it->second.deps) {
            stack.push_back(dep);
        }
    }
    return false;
}

bool SwarmAgentDag::DepsCommitted(const Node& node) const
{
    for (const std::string& dep : node.deps) {
        const auto it = m_nodes.find(dep);
        if (it == m_nodes.end() || it->second.cancelled || !it->second.committed) {
            return false;
        }
    }
    return true;
}

bool SwarmAgentDag::Add(const std::string& task, const std::vector<std::string>& deps, std::string& err)
{
    if (task.empty()) {
        err = kAgentTask;
        return false;
    }
    if (m_nodes.find(task) != m_nodes.end()) {
        err = kAgentReplay;
        return false;
    }
    for (const std::string& dep : deps) {
        if (dep == task) {
            continue;
        }
        if (m_nodes.find(dep) == m_nodes.end()) {
            err = kAgentDep;
            return false;
        }
    }
    for (const std::string& dep : deps) {
        if (Reaches(dep, task)) {
            err = kAgentCycle;
            return false;
        }
    }
    Node node;
    node.deps = deps;
    m_nodes.emplace(task, node);
    m_order.push_back(task);
    err.clear();
    return true;
}

std::vector<std::string> SwarmAgentDag::Ready() const
{
    std::vector<std::string> ready;
    for (const std::string& task : m_order) {
        const Node& node = m_nodes.at(task);
        if (node.committed || node.cancelled) {
            continue;
        }
        if (!DepsCommitted(node)) {
            continue;
        }
        ready.push_back(task);
    }
    return ready;
}

bool SwarmAgentDag::Commit(const std::string& task, const std::string& hash, std::string& err)
{
    const auto it = m_nodes.find(task);
    if (it == m_nodes.end()) {
        err = kAgentTask;
        return false;
    }
    Node& node = it->second;
    if (node.cancelled) {
        err = kAgentCancelled;
        return false;
    }
    if (hash.empty()) {
        err = kAgentHash;
        return false;
    }
    if (!DepsCommitted(node)) {
        err = kAgentNotReady;
        return false;
    }
    if (node.committed) {
        if (node.result_hash == hash) {
            err.clear();
            return true;
        }
        err = kAgentConflict;
        return false;
    }
    node.committed = true;
    node.result_hash = hash;
    err.clear();
    return true;
}

bool SwarmAgentDag::Cancel(const std::string& task, std::string& err)
{
    const auto it = m_nodes.find(task);
    if (it == m_nodes.end()) {
        err = kAgentTask;
        return false;
    }
    if (it->second.committed) {
        err = kAgentCommitted;
        return false;
    }
    it->second.cancelled = true;
    err.clear();
    return true;
}

std::string SwarmAgentDag::CommittedHash(const std::string& task) const
{
    const auto it = m_nodes.find(task);
    if (it == m_nodes.end() || !it->second.committed) {
        return std::string();
    }
    return it->second.result_hash;
}

} // namespace modelnet
