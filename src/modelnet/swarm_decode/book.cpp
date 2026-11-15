// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/book.h>

#include <modelnet/swarm_decode/record.h>

#include <map>
#include <string>

namespace modelnet {

const SwarmDecodeSession* SwarmDecodeBook::find(const std::string& id) const
{
    if (id.empty()) return nullptr;
    const auto found = m_sessions.find(id);
    if (found == m_sessions.end()) return nullptr;
    return &found->second;
}

bool SwarmDecodeBook::open(const std::string& id) const
{
    return find(id) != nullptr;
}

std::string SwarmDecodeBook::engine_of(const std::string& id) const
{
    const SwarmDecodeSession* session = find(id);
    if (session == nullptr) return std::string{};
    return session->engine;
}

bool SwarmDecodeBook::prompt_stored(const std::string& id) const
{
    const SwarmDecodeSession* session = find(id);
    if (session == nullptr) return false;
    return session->prompt_stored;
}

std::string SwarmDecodeBook::stored_prompt(const std::string& id) const
{
    const SwarmDecodeSession* session = find(id);
    if (session == nullptr) return std::string{};
    if (!session->prompt_stored) return std::string{};
    return session->prompt;
}

bool SwarmDecodeBook::store_open(const SwarmDecodeSession& session)
{
    if (!SwarmDecodeSessionUsable(session)) return false;
    if (open(session.id)) return false;
    m_sessions.emplace(session.id, session);
    return true;
}

bool SwarmDecodeBook::store_prompt(const std::string& id, const std::string& prompt)
{
    if (prompt.empty()) return false;
    const auto found = m_sessions.find(id);
    if (found == m_sessions.end()) return false;
    if (found->second.prompt_stored) return false;
    found->second.prompt = prompt;
    found->second.prompt_stored = true;
    return true;
}

} // namespace modelnet
