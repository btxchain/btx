// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/bind_kind.h>

#include <modelnet/swarm_tokgate/blank.h>
#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/catalog.h>
#include <modelnet/swarm_tokgate/codes.h>
#include <modelnet/swarm_tokgate/held.h>
#include <modelnet/swarm_tokgate/replay.h>

#include <string>

namespace modelnet {

SwarmTokenGateBindKind SwarmTokenGateClassifyBind(const SwarmTokenGateBook& book,
                                                  const std::string& session,
                                                  const std::string& engine_name)
{
    if (!book.open(session)) return SwarmTokenGateBindKind::Session;
    if (SwarmTokenGateBlank(engine_name) || !SwarmTokenGateEngineNameAllowed(engine_name)) {
        return SwarmTokenGateBindKind::Engine;
    }
    if (SwarmTokenGateEngineReplay(book, session, engine_name)) return SwarmTokenGateBindKind::Replay;
    if (SwarmTokenGateEngineHeld(book, session, engine_name)) return SwarmTokenGateBindKind::Held;
    return SwarmTokenGateBindKind::Store;
}

const char* SwarmTokenGateBindKindCode(SwarmTokenGateBindKind kind)
{
    switch (kind) {
    case SwarmTokenGateBindKind::Store:
        return nullptr;
    case SwarmTokenGateBindKind::Session:
        return kSwarmTokenGateSession;
    case SwarmTokenGateBindKind::Engine:
        return kSwarmTokenGateEngine;
    case SwarmTokenGateBindKind::Replay:
        return kSwarmTokenGateReplay;
    case SwarmTokenGateBindKind::Held:
        return kSwarmTokenGateHeld;
    }
    return kSwarmTokenGateEngine;
}

} // namespace modelnet
