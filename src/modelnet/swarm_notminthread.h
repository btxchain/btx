// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMINTHREAD_H
#define BTX_MODELNET_SWARM_NOTMINTHREAD_H

#include <string>

namespace modelnet {

/**
 * A local note about the CPU thread floor on one node. thread_count is
 * the requested thread count. want_apply asks this note to apply it.
 *
 * CPU threads have a floor of 1. This note applies none. applied stays
 * false, and applied_threads stays 0, on every path.
 */
struct SwarmNotMinThread {
    std::string node_id;
    int thread_count{0};
    bool want_apply{false};
};

/**
 * Outcome of noting a CPU thread floor. applied stays false, and
 * applied_threads stays 0, on every path. CPU threads have a floor of 1.
 * This note applies none.
 */
struct SwarmNotMinThreadResult {
    std::string code;
    bool applied{false};
    int applied_threads{0};
};

/**
 * Note a CPU thread floor without applying it.
 * Order, first match wins:
 * 1. An empty node_id is NODE. applied stays false, applied_threads stays
 *    0, and err is NODE.
 * 2. If thread_count is less than 1, the note is FLOOR even when
 *    want_apply is false. applied stays false, applied_threads stays 0,
 *    and err is FLOOR.
 * 3. want_apply is HELD. applied stays false, applied_threads stays 0,
 *    and err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. applied stays false
 *    and applied_threads stays 0.
 * applied stays false and applied_threads stays 0 on every path. CPU
 * threads have a floor of 1. This note applies none.
 */
SwarmNotMinThreadResult SwarmNoteNotMinThread(const SwarmNotMinThread& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMINTHREAD_H
