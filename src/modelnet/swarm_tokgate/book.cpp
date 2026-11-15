// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/book.h>

#include <modelnet/swarm_tokgate/blank.h>
#include <modelnet/swarm_tokgate/catalog.h>
#include <modelnet/swarm_tokgate/record.h>

#include <map>
#include <string>

namespace modelnet {

const SwarmTokenGateSession* SwarmTokenGateBook::find(const std::string& id) const
{
    if (id.empty()) return nullptr;
    const auto found = m_sessions.find(id);
    if (found == m_sessions.end()) return nullptr;
    return &found->second;
}

bool SwarmTokenGateBook::open(const std::string& id) const
{
    return find(id) != nullptr;
}

std::string SwarmTokenGateBook::model_id(const std::string& id) const
{
    const SwarmTokenGateSession* session = find(id);
    if (session == nullptr) return std::string{};
    return session->model_id;
}

bool SwarmTokenGateBook::engine_bound(const std::string& id) const
{
    const SwarmTokenGateSession* session = find(id);
    if (session == nullptr) return false;
    return session->engine_bound;
}

std::string SwarmTokenGateBook::engine_name(const std::string& id) const
{
    const SwarmTokenGateSession* session = find(id);
    if (session == nullptr) return std::string{};
    if (!session->engine_bound) return std::string{};
    return session->engine_name;
}

bool SwarmTokenGateBook::prompt_stored(const std::string& id) const
{
    const SwarmTokenGateSession* session = find(id);
    if (session == nullptr) return false;
    return session->prompt_stored;
}

std::string SwarmTokenGateBook::stored_prompt(const std::string& id) const
{
    const SwarmTokenGateSession* session = find(id);
    if (session == nullptr) return std::string{};
    if (!session->prompt_stored) return std::string{};
    return session->prompt;
}

bool SwarmTokenGateBook::store_open(const SwarmTokenGateSession& session)
{
    if (!SwarmTokenGateSessionUsable(session)) return false;
    if (open(session.id)) return false;
    if (session.engine_bound) return false;
    if (session.prompt_stored) return false;
    if (!session.engine_name.empty()) return false;
    if (!session.prompt.empty()) return false;
    m_sessions.emplace(session.id, session);
    return true;
}

bool SwarmTokenGateBook::store_engine(const std::string& id, const std::string& engine_name)
{
    if (!SwarmTokenGateEngineNameAllowed(engine_name)) return false;
    const auto found = m_sessions.find(id);
    if (found == m_sessions.end()) return false;
    if (found->second.engine_bound) return false;
    found->second.engine_name = engine_name;
    found->second.engine_bound = true;
    return true;
}

bool SwarmTokenGateBook::store_prompt(const std::string& id, const std::string& prompt)
{
    if (SwarmTokenGateBlank(prompt)) return false;
    const auto found = m_sessions.find(id);
    if (found == m_sessions.end()) return false;
    if (found->second.prompt_stored) return false;
    found->second.prompt = prompt;
    found->second.prompt_stored = true;
    return true;
}

} // namespace modelnet
