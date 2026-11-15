// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoframe.h>

#include <string>

namespace modelnet {

SwarmNotNoFrameResult SwarmNoteNotNoFrame(const SwarmNotNoFrame& note, std::string& err)
{
    SwarmNotNoFrameResult result;
    result.ran = false;
    result.trained = false;
    // Naming a framework does not run it.
    if (note.framework_id.empty()) {
        result.code = "FRAMEWORK";
        result.ran = false;
        result.trained = false;
        err = "FRAMEWORK";
        return result;
    }
    if (note.want_run) {
        result.code = "NOT_RUN";
        result.ran = false;
        result.trained = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.ran = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
