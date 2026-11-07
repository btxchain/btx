// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_taskdag.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmTaskDag::Reaches(const std::string& start, const std::string& target) const
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

bool SwarmTaskDag::Add(const std::string& id, const std::vector<std::string>& deps, std::string& err)
{
    if (id.empty()) {
        err = "TASK";
        return false;
    }
    if (m_nodes.find(id) != m_nodes.end()) {
        err = "REPLAY";
        return false;
    }
    for (const std::string& dep : deps) {
        if (dep == id) {
            continue;
        }
        if (m_nodes.find(dep) == m_nodes.end()) {
            err = "DEP";
            return false;
        }
    }
    for (const std::string& dep : deps) {
        if (Reaches(dep, id)) {
            err = "CYCLE";
            return false;
        }
    }
    Node node;
    node.deps = deps;
    m_nodes.emplace(id, node);
    m_order.push_back(id);
    err.clear();
    return true;
}

std::vector<std::string> SwarmTaskDag::Ready() const
{
    std::vector<std::string> ready;
    for (const std::string& id : m_order) {
        const Node& node = m_nodes.at(id);
        if (node.committed || node.cancelled) {
            continue;
        }
        bool deps_committed = true;
        for (const std::string& dep : node.deps) {
            const auto it = m_nodes.find(dep);
            if (it == m_nodes.end() || !it->second.committed) {
                deps_committed = false;
                break;
            }
        }
        if (deps_committed) {
            ready.push_back(id);
        }
    }
    return ready;
}

bool SwarmTaskDag::Commit(const std::string& id, const std::string& result_hash, std::string& err)
{
    const auto it = m_nodes.find(id);
    if (it == m_nodes.end()) {
        err = "TASK";
        return false;
    }
    Node& node = it->second;
    if (node.cancelled) {
        err = "CANCELLED";
        return false;
    }
    if (result_hash.empty()) {
        err = "HASH";
        return false;
    }
    for (const std::string& dep : node.deps) {
        const auto dep_it = m_nodes.find(dep);
        if (dep_it == m_nodes.end() || !dep_it->second.committed) {
            err = "NOT_READY";
            return false;
        }
    }
    if (node.committed) {
        if (node.result_hash == result_hash) {
            err.clear();
            return true;
        }
        err = "CONFLICT";
        return false;
    }
    node.committed = true;
    node.result_hash = result_hash;
    err.clear();
    return true;
}

bool SwarmTaskDag::Cancel(const std::string& id, std::string& err)
{
    const auto it = m_nodes.find(id);
    if (it == m_nodes.end()) {
        err = "TASK";
        return false;
    }
    if (it->second.committed) {
        err = "COMMITTED";
        return false;
    }
    it->second.cancelled = true;
    err.clear();
    return true;
}

} // namespace modelnet
