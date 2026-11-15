// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>

#include <modelnet/swarm_agents/codes.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmAgentPlane::Add(const std::string& task, const std::vector<std::string>& deps, std::string& err)
{
    return m_dag.Add(task, deps, err);
}

std::vector<std::string> SwarmAgentPlane::Ready() const
{
    return m_dag.Ready();
}

bool SwarmAgentPlane::Commit(const std::string& task, const std::string& hash, std::string& err)
{
    if (!m_dag.Commit(task, hash, err)) {
        return false;
    }
    return m_trace.Append(task, kAgentEventCommit, err);
}

bool SwarmAgentPlane::Cancel(const std::string& task, std::string& err)
{
    if (!m_dag.Cancel(task, err)) {
        return false;
    }
    return m_trace.Append(task, kAgentEventCancel, err);
}

std::string SwarmAgentPlane::CommittedHash(const std::string& task) const
{
    return m_dag.CommittedHash(task);
}

bool SwarmAgentPlane::Run(const SwarmAgentRunRequest& request, std::string& err)
{
    if (request.task.empty()) {
        err = kAgentTask;
        return false;
    }
    if (m_results.find(request.task) != m_results.end()) {
        err = kAgentReplay;
        return false;
    }
    if (!m_gate.Admit(request, err)) {
        return false;
    }
    SwarmAgentBuiltinResult built;
    if (!m_registry.Run(request.kind, built, err) || !built.has_result || built.launched) {
        return false;
    }
    m_results.emplace(request.task, built);
    err.clear();
    return true;
}

bool SwarmAgentPlane::ran(const std::string& task) const
{
    const auto it = m_results.find(task);
    if (it == m_results.end()) {
        return false;
    }
    return it->second.ran;
}

bool SwarmAgentPlane::launched() const
{
    return false;
}

bool SwarmAgentPlane::has_result(const std::string& task) const
{
    const auto it = m_results.find(task);
    if (it == m_results.end()) {
        return false;
    }
    return it->second.has_result;
}

uint64_t SwarmAgentPlane::step(const std::string& task) const
{
    const auto it = m_results.find(task);
    if (it == m_results.end()) {
        return 0;
    }
    return it->second.step;
}

std::string SwarmAgentPlane::result_hash(const std::string& task) const
{
    const auto it = m_results.find(task);
    if (it == m_results.end() || !it->second.has_result) {
        return std::string();
    }
    return it->second.result_hash;
}

bool SwarmAgentPlane::Grant(const std::string& lease, int64_t until, int64_t now, std::string& err)
{
    return m_lease.Grant(lease, until, now, err);
}

bool SwarmAgentPlane::admitted() const
{
    return m_lease.admitted();
}

uint64_t SwarmAgentPlane::epoch() const
{
    return m_lease.epoch();
}

const std::string& SwarmAgentPlane::lease_id() const
{
    return m_lease.lease_id();
}

int64_t SwarmAgentPlane::lease_until() const
{
    return m_lease.until();
}

bool SwarmAgentPlane::CommitEpoch(uint64_t epoch, const std::string& task, const std::string& hash, std::string& err)
{
    if (!m_lease.Matches(epoch, err)) {
        return false;
    }
    return Commit(task, hash, err);
}

bool SwarmAgentPlane::Charge(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err)
{
    return m_account.Charge(agent, threads, memory_mib, err);
}

bool SwarmAgentPlane::Release(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err)
{
    return m_account.Release(agent, threads, memory_mib, err);
}

int64_t SwarmAgentPlane::Threads(const std::string& agent) const
{
    return m_account.Threads(agent);
}

int64_t SwarmAgentPlane::Memory(const std::string& agent) const
{
    return m_account.Memory(agent);
}

bool SwarmAgentPlane::Append(const std::string& task, const std::string& event, std::string& err)
{
    return m_trace.Append(task, event, err);
}

std::vector<SwarmAgentTraceRow> SwarmAgentPlane::Trace() const
{
    return m_trace.Rows();
}

bool SwarmAgentPlane::Publish(const std::string& key, const std::string& hash, std::string& err)
{
    return m_shared.Publish(key, hash, err);
}

bool SwarmAgentPlane::Attach(const std::string& consumer, const std::string& key, const std::string& hash, std::string& err)
{
    return m_shared.Attach(consumer, key, hash, err);
}

std::string SwarmAgentPlane::Shared(const std::string& key) const
{
    return m_shared.Shared(key);
}

bool SwarmAgentPlane::attached(const std::string& consumer, const std::string& key) const
{
    return m_shared.attached(consumer, key);
}

} // namespace modelnet
