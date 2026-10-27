// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/inspect.h>

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

bool SwarmTokenGateSessionOpen(const SwarmTokenGateBook& book, const std::string& session)
{
    return book.open(session);
}

std::string SwarmTokenGateSessionModel(const SwarmTokenGateBook& book, const std::string& session)
{
    return book.model_id(session);
}

std::string SwarmTokenGateSessionEngine(const SwarmTokenGateBook& book, const std::string& session)
{
    return book.engine_name(session);
}

bool SwarmTokenGateSessionPromptStored(const SwarmTokenGateBook& book, const std::string& session)
{
    return book.prompt_stored(session);
}

} // namespace modelnet
