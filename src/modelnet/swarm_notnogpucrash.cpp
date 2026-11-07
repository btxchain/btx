// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogpucrash.h>

#include <string>

namespace modelnet {

SwarmNotNoGpuCrashResult SwarmNoteNotNoGpuCrash(const SwarmNotNoGpuCrash& note, std::string& err)
{
    // A GPU-crash publication code does not mean a GPU ran and publishes nothing.
    SwarmNotNoGpuCrashResult result;
    result.published = false;
    result.gpu = false;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.gpu = false;
        err = "RUN";
        return result;
    }
    // gpu_crash is NOT_RUN even when want_publish is false.
    if (note.gpu_crash) {
        result.code = "NOT_RUN";
        result.published = false;
        result.gpu = false;
        err = "NOT_RUN";
        return result;
    }
    if (note.want_publish) {
        result.code = "NOT_RUN";
        result.published = false;
        result.gpu = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
