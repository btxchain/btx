// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTHREADS64_H
#define BTX_MODELNET_SWARM_NOTNOTHREADS64_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about the CPU thread cap on one node. want_raise asks
 * this note to raise that cap.
 *
 * A unit note does not raise the CPU thread cap above 64. raised stays
 * false and threads stays 0 on every path.
 */
struct SwarmNotNoThreads64 {
    std::string node_id;
    bool want_raise{false};
};

/**
 * Outcome of noting a CPU thread cap. raised stays false and threads
 * stays 0 on every path. A unit note does not raise the CPU thread cap
 * above 64.
 */
struct SwarmNotNoThreads64Result {
    std::string code;
    bool raised{false};
    int64_t threads{0};
};

/**
 * Note a CPU thread cap without raising it. Order, first match wins:
 * an empty node_id is NODE. want_raise is CAPPED. Otherwise the note is
 * NOTED and err is cleared. raised stays false and threads stays 0 on
 * every path. A unit note does not raise the CPU thread cap above 64.
 */
SwarmNotNoThreads64Result SwarmNoteNotNoThreads64(const SwarmNotNoThreads64& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTHREADS64_H
