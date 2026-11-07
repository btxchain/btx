// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottasklat.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotTaskLatResult SwarmNoteNotTaskLat(const SwarmNotTaskLat& note, std::string& err)
{
    SwarmNotTaskLatResult result;
    result.published = false;
    result.latency_us = 0;
    if (note.task_id.empty()) {
        result.code = "TASK";
        result.published = false;
        result.latency_us = 0;
        err = "TASK";
        return result;
    }
    // No task latency has been measured, so this note does not publish one.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.latency_us = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.latency_us = 0;
    err.clear();
    return result;
}

} // namespace modelnet
