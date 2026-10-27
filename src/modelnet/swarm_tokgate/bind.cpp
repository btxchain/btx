// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/bind.h>

#include <modelnet/swarm_tokgate/bind_kind.h>
#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/catalog.h>
#include <modelnet/swarm_tokgate/codes.h>
#include <modelnet/swarm_tokgate/same.h>

#include <string>

namespace modelnet {

bool SwarmTokenGateBindApply(SwarmTokenGateBook& book,
                             const std::string& session,
                             const std::string& engine_name,
                             std::string& err)
{
    const SwarmTokenGateBindKind kind = SwarmTokenGateClassifyBind(book, session, engine_name);
    const char* code = SwarmTokenGateBindKindCode(kind);
    if (code != nullptr) {
        err = code;
        return false;
    }
    if (!book.store_engine(session, engine_name)) {
        if (!book.open(session)) {
            err = kSwarmTokenGateSession;
            return false;
        }
        if (!SwarmTokenGateEngineNameAllowed(engine_name)) {
            err = kSwarmTokenGateEngine;
            return false;
        }
        if (book.engine_bound(session) && SwarmTokenGateSame(book.engine_name(session), engine_name)) {
            err = kSwarmTokenGateReplay;
            return false;
        }
        if (book.engine_bound(session)) {
            err = kSwarmTokenGateHeld;
            return false;
        }
        err = kSwarmTokenGateEngine;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
