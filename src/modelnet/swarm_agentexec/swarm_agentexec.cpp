// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/swarm_agentexec.h>

#include <modelnet/swarm_agentexec/allow.h>
#include <modelnet/swarm_agentexec/execute.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmAgentExec::Allow(const std::string& prefix, std::string& err)
{
    return SwarmAgentExecAllow(m_book, prefix, err);
}

bool SwarmAgentExec::Execute(const std::string& tool, const std::string& path, const std::string& payload, std::string& err)
{
    return SwarmAgentExecExecute(m_book, m_journal, m_result, tool, path, payload, err);
}

bool SwarmAgentExec::ran() const
{
    return m_result.ran();
}

std::string SwarmAgentExec::result() const
{
    return m_result.result();
}

bool SwarmAgentExec::launched() const
{
    return m_quiet.launched();
}

bool SwarmAgentExec::connected() const
{
    return m_quiet.connected();
}

bool SwarmAgentExec::gpu() const
{
    return m_quiet.gpu();
}

bool SwarmAgentExec::broadcast() const
{
    return m_quiet.broadcast();
}

int64_t SwarmAgentExec::atoms_moved() const
{
    return m_quiet.atoms_moved();
}

std::string SwarmAgentExec::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

} // namespace modelnet
