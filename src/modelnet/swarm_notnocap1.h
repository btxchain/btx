// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCAP1_H
#define BTX_MODELNET_SWARM_NOTNOCAP1_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about the CPU thread floor on one node. thread_count is
 * the requested thread count. want_apply asks this note to apply it.
 *
 * CPU threads are at least 1. This note applies nothing. applied stays
 * false, and threads stays 0, on every path.
 */
struct SwarmNotNoCap1 {
    std::string node_id;
    int64_t thread_count{0};
    bool want_apply{false};
};

/**
 * Outcome of noting a CPU thread floor. applied stays false, and
 * threads stays 0, on every path. CPU threads are at least 1.
 * This note applies nothing.
 */
struct SwarmNotNoCap1Result {
    std::string code;
    bool applied{false};
    int64_t threads{0};
};

/**
 * Note a CPU thread floor without applying it. Order, first match wins:
 * an empty node_id is NODE. If thread_count is less than 1, the note is
 * CAPPED even when want_apply is false. want_apply is CAPPED. Otherwise
 * the note is NOTED and err is cleared. applied stays false and threads
 * stays 0 on every path. CPU threads are at least 1, and this note
 * applies nothing.
 */
SwarmNotNoCap1Result SwarmNoteNotNoCap1(const SwarmNotNoCap1& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCAP1_H
