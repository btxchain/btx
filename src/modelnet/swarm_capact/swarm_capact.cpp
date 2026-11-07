// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/swarm_capact.h>

#include <modelnet/swarm_capact/act.h>
#include <modelnet/swarm_capact/grant.h>

namespace modelnet {

bool SwarmCapAct::Grant(const std::string& name, std::string& err)
{
    return SwarmCapActGrantApply(m_grants, name, err);
}

bool SwarmCapAct::Act(const std::string& name, std::string& err)
{
    return SwarmCapActApply(m_grants, m_actions, name, err);
}

bool SwarmCapAct::granted(const std::string& name) const
{
    return m_grants.contains(name);
}

bool SwarmCapAct::acted(const std::string& name) const
{
    return m_actions.contains(name);
}

std::size_t SwarmCapAct::grant_count() const
{
    return m_grants.size();
}

std::size_t SwarmCapAct::action_count() const
{
    return m_actions.size();
}

bool SwarmCapAct::launched() const
{
    return m_quiet.launched();
}

int64_t SwarmCapAct::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmCapAct::gpu() const
{
    return m_quiet.gpu();
}

std::string SwarmCapAct::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

} // namespace modelnet
