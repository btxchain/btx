// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/open_kind.h>

#include <modelnet/swarm_decode/book.h>
#include <modelnet/swarm_decode/codes.h>
#include <modelnet/swarm_decode/names.h>

#include <string>

namespace modelnet {

SwarmDecodeOpenKind SwarmDecodeClassifyOpen(const SwarmDecodeBook& book,
                                            const std::string& session,
                                            const std::string& engine)
{
    if (session.empty()) return SwarmDecodeOpenKind::Session;
    if (!SwarmDecodeEngineIsKnown(engine)) return SwarmDecodeOpenKind::Engine;
    if (book.open(session)) return SwarmDecodeOpenKind::Replay;
    return SwarmDecodeOpenKind::Store;
}

const char* SwarmDecodeOpenKindCode(SwarmDecodeOpenKind kind)
{
    if (kind == SwarmDecodeOpenKind::Session) return kSwarmDecodeSession;
    if (kind == SwarmDecodeOpenKind::Engine) return kSwarmDecodeEngine;
    if (kind == SwarmDecodeOpenKind::Replay) return kSwarmDecodeReplay;
    return nullptr;
}

} // namespace modelnet
