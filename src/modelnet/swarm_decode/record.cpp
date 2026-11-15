// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/record.h>

#include <modelnet/swarm_decode/names.h>

#include <string>

namespace modelnet {

SwarmDecodeSession SwarmDecodeMakeSession(const std::string& id, const std::string& engine)
{
    SwarmDecodeSession session;
    session.id = id;
    session.engine = engine;
    session.prompt.clear();
    session.prompt_stored = false;
    return session;
}

bool SwarmDecodeSessionUsable(const SwarmDecodeSession& session)
{
    if (session.id.empty()) return false;
    if (!SwarmDecodeEngineIsKnown(session.engine)) return false;
    if (session.prompt_stored) return false;
    if (!session.prompt.empty()) return false;
    return true;
}

} // namespace modelnet
