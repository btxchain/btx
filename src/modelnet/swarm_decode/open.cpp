// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/open.h>

#include <modelnet/swarm_decode/book.h>
#include <modelnet/swarm_decode/codes.h>
#include <modelnet/swarm_decode/open_kind.h>
#include <modelnet/swarm_decode/record.h>

#include <string>

namespace modelnet {

bool SwarmDecodeOpenApply(SwarmDecodeBook& book,
                          const std::string& session,
                          const std::string& engine,
                          std::string& err)
{
    const SwarmDecodeOpenKind kind = SwarmDecodeClassifyOpen(book, session, engine);
    const char* code = SwarmDecodeOpenKindCode(kind);
    if (code != nullptr) {
        err = code;
        return false;
    }
    const SwarmDecodeSession record = SwarmDecodeMakeSession(session, engine);
    if (!book.store_open(record)) {
        err = book.open(session) ? std::string{kSwarmDecodeReplay} : std::string{kSwarmDecodeEngine};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
