// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/decode.h>

#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/catalog.h>
#include <modelnet/swarm_tokgate/codes.h>

#include <string>

namespace modelnet {

bool SwarmTokenGateDecodeRefuse(const SwarmTokenGateBook& book,
                                const std::string& session,
                                std::string& err)
{
    if (!book.open(session)) {
        err = kSwarmTokenGateSession;
        return false;
    }
    if (book.engine_bound(session)) {
        const std::string bound = book.engine_name(session);
        if (SwarmTokenGateEngineNameRuns(bound)) {
            err = kSwarmTokenGateEngineAbsent;
            return false;
        }
    }
    err = kSwarmTokenGateEngineAbsent;
    return false;
}

} // namespace modelnet
