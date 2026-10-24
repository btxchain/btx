// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCPUTHREAD2_H
#define BTX_MODELNET_SWARM_NOTNOCPUTHREAD2_H

#include <string>

namespace modelnet {

/**
 * A local note about the CPU thread cap on one node. requested is the
 * thread count this note asks for. want_raise asks this note to raise
 * that cap.
 *
 * CPU threads stay capped at 64. raised stays false and threads stays 0
 * on every path.
 */
struct SwarmNotNoCpuThread2 {
    std::string node_id;
    int requested{0};
    bool want_raise{false};
};

/**
 * Outcome of noting a CPU thread cap. raised stays false and threads
 * stays 0 on every path. CPU threads stay capped at 64.
 */
struct SwarmNotNoCpuThread2Result {
    std::string code;
    bool raised{false};
    int threads{0};
};

/**
 * Note a CPU thread cap without raising it. Order, first match wins:
 * an empty node_id is NODE. requested greater than 64 is CAPPED even
 * when want_raise is false. want_raise is CAPPED. Otherwise the note is
 * NOTED and err is cleared. raised stays false and threads stays 0 on
 * every path. CPU threads stay capped at 64.
 */
SwarmNotNoCpuThread2Result SwarmNoteNotNoCpuThread2(const SwarmNotNoCpuThread2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCPUTHREAD2_H
