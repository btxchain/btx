// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/open_kind.h>

#include <modelnet/swarm_tokgate/blank.h>
#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/codes.h>
#include <modelnet/swarm_tokgate/replay.h>

#include <string>

namespace modelnet {

SwarmTokenGateOpenKind SwarmTokenGateClassifyOpen(const SwarmTokenGateBook& book,
                                                  const std::string& session,
                                                  const std::string& model_id)
{
    if (SwarmTokenGateBlank(session) || SwarmTokenGateBlank(model_id)) {
        return SwarmTokenGateOpenKind::Model;
    }
    if (SwarmTokenGateOpenReplay(book, session, model_id)) return SwarmTokenGateOpenKind::Replay;
    return SwarmTokenGateOpenKind::Store;
}

const char* SwarmTokenGateOpenKindCode(SwarmTokenGateOpenKind kind)
{
    switch (kind) {
    case SwarmTokenGateOpenKind::Store:
        return nullptr;
    case SwarmTokenGateOpenKind::Model:
        return kSwarmTokenGateModel;
    case SwarmTokenGateOpenKind::Replay:
        return kSwarmTokenGateReplay;
    }
    return kSwarmTokenGateModel;
}

} // namespace modelnet
