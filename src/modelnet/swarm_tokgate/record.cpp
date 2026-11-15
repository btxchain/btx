// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/record.h>

#include <modelnet/swarm_tokgate/blank.h>

#include <string>

namespace modelnet {

SwarmTokenGateSession SwarmTokenGateMakeSession(const std::string& id, const std::string& model_id)
{
    SwarmTokenGateSession session;
    session.id = id;
    session.model_id = model_id;
    session.engine_name.clear();
    session.engine_bound = false;
    session.prompt.clear();
    session.prompt_stored = false;
    return session;
}

bool SwarmTokenGateSessionUsable(const SwarmTokenGateSession& session)
{
    if (SwarmTokenGateBlank(session.id)) return false;
    if (SwarmTokenGateBlank(session.model_id)) return false;
    return true;
}

} // namespace modelnet
