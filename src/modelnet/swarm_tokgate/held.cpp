// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/held.h>

#include <modelnet/swarm_tokgate/blank.h>
#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/catalog.h>
#include <modelnet/swarm_tokgate/privacy.h>
#include <modelnet/swarm_tokgate/same.h>

#include <string>

namespace modelnet {

bool SwarmTokenGateEngineHeld(const SwarmTokenGateBook& book,
                              const std::string& session,
                              const std::string& engine_name)
{
    if (!book.open(session)) return false;
    if (!SwarmTokenGateEngineNameAllowed(engine_name)) return false;
    if (!book.engine_bound(session)) return false;
    return !SwarmTokenGateSame(book.engine_name(session), engine_name);
}

bool SwarmTokenGatePromptHeld(const SwarmTokenGateBook& book,
                              const std::string& session,
                              const std::string& text,
                              bool is_private)
{
    if (!book.open(session)) return false;
    if (SwarmTokenGatePrivatePrompt(is_private)) return false;
    if (SwarmTokenGateBlank(text)) return false;
    if (!book.prompt_stored(session)) return false;
    return !SwarmTokenGateSame(book.stored_prompt(session), text);
}

} // namespace modelnet
