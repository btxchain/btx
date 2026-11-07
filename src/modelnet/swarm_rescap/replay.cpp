// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/replay.h>

#include <modelnet/swarm_rescap/limits.h>

namespace modelnet {

bool SwarmResCapIsReplay(const SwarmResCapBook& book, int64_t threads)
{
    if (threads < kSwarmResCapMinThreads) return false;
    if (threads > kSwarmResCapThreadCap) return false;
    return book.contains(threads);
}

} // namespace modelnet
