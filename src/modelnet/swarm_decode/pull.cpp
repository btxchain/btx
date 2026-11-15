// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/pull.h>

#include <modelnet/swarm_decode/absent.h>
#include <modelnet/swarm_decode/book.h>
#include <modelnet/swarm_decode/codes.h>
#include <modelnet/swarm_decode/memory.h>
#include <modelnet/swarm_decode/names.h>
#include <modelnet/swarm_decode/output.h>

#include <string>

namespace modelnet {

bool SwarmDecodePullApply(const SwarmDecodeBook& book,
                          SwarmDecodeOutput& output,
                          const std::string& session,
                          std::string& err)
{
    if (!book.open(session)) {
        err = kSwarmDecodeSession;
        return false;
    }
    if (!book.prompt_stored(session)) {
        err = kSwarmDecodePrompt;
        return false;
    }
    const std::string engine = book.engine_of(session);
    if (SwarmDecodeEngineIsProduction(engine)) {
        return SwarmDecodeProductionPull(err);
    }
    if (!SwarmDecodeEngineIsMemory(engine)) {
        err = kSwarmDecodeEngineAbsent;
        return false;
    }
    return SwarmDecodeMemoryPull(book.stored_prompt(session), output, err);
}

} // namespace modelnet
