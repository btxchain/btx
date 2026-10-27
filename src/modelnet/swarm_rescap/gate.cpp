// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/gate.h>

#include <modelnet/swarm_rescap/codes.h>
#include <modelnet/swarm_rescap/over.h>
#include <modelnet/swarm_rescap/replay.h>
#include <modelnet/swarm_rescap/under.h>

#include <string>

namespace modelnet {

SwarmResCapDecision SwarmResCapDecide(const SwarmResCapBook& book, int64_t threads)
{
    std::string err;
    if (!SwarmResCapUnder{}.accept(threads, err)) {
        return SwarmResCapDecision{err, false};
    }
    if (!SwarmResCapOver{}.accept(threads, err)) {
        return SwarmResCapDecision{err, false};
    }
    if (SwarmResCapIsReplay(book, threads)) {
        return SwarmResCapDecision{std::string{kSwarmResCapReplay}, false};
    }
    return SwarmResCapDecision{{}, true};
}

} // namespace modelnet
