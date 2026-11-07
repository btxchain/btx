// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTASKLAT_H
#define BTX_MODELNET_SWARM_NOTTASKLAT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a task might publish a latency.
 * want_publish asks this note to publish a latency figure.
 *
 * No task latency has been measured, so this note does not publish one.
 * published stays false and latency_us stays 0 on every path.
 */
struct SwarmNotTaskLat {
    std::string task_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unmeasured task latency. published stays false and
 * latency_us stays 0 on every path: no task latency has been measured, so
 * this note does not publish one.
 */
struct SwarmNotTaskLatResult {
    std::string code;
    bool published{false};
    int64_t latency_us{0};
};

/**
 * Note that no task latency is published.
 * Order, first match wins: an empty task_id is TASK and err is TASK.
 * want_publish is UNMEASURED and err is UNMEASURED. Otherwise the note is
 * NOTED and err is cleared. published stays false and latency_us stays 0
 * on every path. No task latency has been measured, so this note does not
 * publish one.
 */
SwarmNotTaskLatResult SwarmNoteNotTaskLat(const SwarmNotTaskLat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTASKLAT_H
