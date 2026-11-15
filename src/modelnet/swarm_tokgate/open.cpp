// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/open.h>

#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/codes.h>
#include <modelnet/swarm_tokgate/open_kind.h>
#include <modelnet/swarm_tokgate/record.h>

#include <string>

namespace modelnet {

bool SwarmTokenGateOpenApply(SwarmTokenGateBook& book,
                             const std::string& session,
                             const std::string& model_id,
                             std::string& err)
{
    const SwarmTokenGateOpenKind kind = SwarmTokenGateClassifyOpen(book, session, model_id);
    const char* code = SwarmTokenGateOpenKindCode(kind);
    if (code != nullptr) {
        err = code;
        return false;
    }
    const SwarmTokenGateSession record = SwarmTokenGateMakeSession(session, model_id);
    if (!book.store_open(record)) {
        err = book.open(session) ? std::string{kSwarmTokenGateReplay} : std::string{kSwarmTokenGateModel};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
