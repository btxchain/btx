// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentclass/swarm_agentclass.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmAgentClass::Admit(const std::string& task, const std::string& worker, const std::string& prefix, int64_t until_ms,
                            std::string& err)
{
    if (task.empty() || worker.empty() || prefix.empty()) {
        err = SWARM_AGENTCLASS_TASK;
        return false;
    }
    if (until_ms < 0) {
        err = SWARM_AGENTCLASS_TIMEOUT;
        return false;
    }
    if (!m_run.AddTask(task, "", SWARM_AGENTCLASS_SHA256, err)) {
        return false;
    }
    if (!m_exec.Allow(prefix, err)) {
        if (err != SWARM_AGENTCLASS_REPLAY) {
            return false;
        }
    }
    const std::vector<std::string> capabilities{std::string{SWARM_AGENTCLASS_SHA256}};
    if (!m_gate.Grant(worker, prefix, capabilities, false, until_ms, err)) {
        if (err != SWARM_AGENTCLASS_REPLAY) {
            return false;
        }
    }
    m_worker = worker;
    err.clear();
    return true;
}

bool SwarmAgentClass::Work(const std::string& task, const std::string& worker, const std::string& path, const std::string& payload,
                           int64_t now_ms, std::string& err)
{
    if (!m_run.has_task(task)) {
        err = SWARM_AGENTCLASS_TASK;
        return false;
    }
    if (!m_gate.Act(worker, path, SWARM_AGENTCLASS_SHA256, now_ms, err)) {
        return false;
    }
    return m_exec.Execute(SWARM_AGENTCLASS_SHA256, path, payload, err);
}

bool SwarmAgentClass::Net(const std::string& worker, const std::string& host, int64_t now_ms, std::string& err)
{
    return m_gate.Net(worker, host, now_ms, err);
}

bool SwarmAgentClass::Spawn(std::string& err)
{
    std::string run_err;
    std::string gate_err;
    (void)m_run.Run(run_err);
    (void)m_gate.Run(m_worker, gate_err);
    err = SWARM_AGENTCLASS_SANDBOX_ABSENT;
    return false;
}

bool SwarmAgentClass::Private(const std::string& worker, const std::string& payload, int64_t now_ms, std::string& err)
{
    (void)payload;
    if (m_gate.Act(worker, SWARM_AGENTCLASS_PRIVATE_PATH, SWARM_AGENTCLASS_SHA256, now_ms, err)) {
        err = "PRIVATE_DATA";
    }
    return false;
}

std::string SwarmAgentClass::digest() const
{
    return m_exec.result();
}

bool SwarmAgentClass::ran() const
{
    return m_exec.ran();
}

bool SwarmAgentClass::launched() const
{
    return m_run.launched() || m_exec.launched() || m_gate.launched();
}

bool SwarmAgentClass::connected() const
{
    return m_exec.connected() || m_gate.connected();
}

} // namespace modelnet
